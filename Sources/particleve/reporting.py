"""Bounded host observations and one-way delivery to an owner-selected receiver."""

import fcntl
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .common import Error, canonical, capture_bounded, digest, hash_file, read_json, require, run
from .config import https_url, integer, version_key
from .coordinator import Coordinator
from .landlock import confine_filesystem

MAX_REPORT = 65536
SETTINGS = Path("/etc/particleve/reporting.json")
CA_FILE = Path("/etc/particleve/reporting-ca.pem")
SENDER = "/usr/libexec/particleve-health-sender"
REPORT_USER = "particleve-report"
MAX_HANDOFF = 2 * MAX_REPORT + 4096
HANDOFF_SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
# Linux UAPI; Python does not export this modern memfd flag. Require it outright.
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/memfd.h
MFD_NOEXEC_SEAL = 0x0008


def private_file(path, *, secret=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) in ((0o400, 0o600) if secret else (0o400, 0o600, 0o644))
            and 0 < info.st_size <= (2048 if secret else MAX_REPORT),
            "reporting input must be a bounded, root-owned regular file with reviewed permissions",
        )
        data = stream.read(MAX_REPORT + 1)
        require(len(data) <= MAX_REPORT, "reporting input exceeds its size limit")
        return data


def settings():
    private_file(SETTINGS, secret=True)
    config = read_json(SETTINGS)
    require(
        set(config) == {"schema", "endpoint", "maximum_update_check_age_seconds", "private_ca"}
        and type(config["schema"]) is int
        and config["schema"] == 1,
        "unknown reporting configuration",
    )
    https_url(config["endpoint"])
    integer(config["maximum_update_check_age_seconds"], 3600, "maximum update-check age")
    require(
        config["maximum_update_check_age_seconds"] <= 7 * 86400, "update-check age cannot exceed seven days"
    )
    require(type(config["private_ca"]) is bool, "declare reporting private-CA policy")
    if config["private_ca"]:
        require(
            b"PRIVATE KEY" not in private_file(CA_FILE),
            "reporting CA input must contain only public certificates",
        )
    return config


def policy_binding():
    config = settings()
    return digest(
        {"settings": config, "private_ca_sha256": hash_file(CA_FILE) if config["private_ca"] else None}
    )


def journal():
    command = [
        "journalctl",
        "--quiet",
        "--since=-10min",
        "--lines=65",
        "--output=json",
        "--output-fields=__CURSOR,MESSAGE",
        "--grep=avc:.*denied",
        "_TRANSPORT=audit",
        "+",
        "_TRANSPORT=kernel",
    ]
    observed = capture_bounded(command, timeout=10, maximum_bytes=256 * 1024)
    require(
        observed.returncode == 0 or (observed.returncode == 1 and not observed.stdout),
        "SELinux journal observation failed",
    )
    require(not observed.stderr, "SELinux journal observation produced diagnostics")
    rows = [json.loads(line) for line in observed.stdout.splitlines()]
    events = []
    for row in rows[:64]:
        message = row["MESSAGE"]
        event = {"id": hashlib.sha256(row["__CURSOR"].encode()).hexdigest()}
        for key in ("scontext", "tcontext", "tclass"):
            match = re.search(r"\b" + key + r"=([A-Za-z0-9_:,.-]{1,128})(?:\s|$)", message)
            if match:
                event[key] = match[1]
        permissions = re.search(r"avc:\s+denied\s+\{\s*([a-z_ ]{1,128})\s*\}", message)
        if permissions:
            event["permissions"] = permissions[1].split()
        events.append(event)
    return {"window_seconds": 600, "limited": len(rows) > 64, "events": events}


def snapshot(backend, *, maximum_update_check_age_seconds=172800, now=None):
    now = now or datetime.now(UTC)
    checks = []
    details = {}
    probes = {
        "host_security": backend.health,
        "authenticated_time": backend.check_time,
        "storage": lambda: backend.check_storage(healthy=True),
        "resources": lambda: backend.check_resources(healthy=False),
        "selinux_denials": journal,
    }
    from .vms import LinuxVMs

    probes["vm_confinement"] = lambda: {"running_vm_count": len(LinuxVMs().inventory(inhibited=False))}
    for name, probe in probes.items():
        try:
            observed = probe()
            checks.append({"name": name, "result": "pass"})
            if name == "storage":
                details[name] = {
                    key: observed[key]
                    for key in ("free_bytes", "reserve_bytes", "swap_degraded", "swap_sync_action")
                }
            elif name == "resources":
                details[name] = {
                    "memory": observed["memory"],
                    "disk_status": [
                        {"role": d["role"], "status": d["status"]} for d in observed["physical_disks"]
                    ],
                    "pressure": observed["pressure"],
                    "oom_events": observed["oom_events"]
                    | {
                        "events": observed["oom_events"]["events"][:8],
                        "limited": observed["oom_events"]["limited"]
                        or len(observed["oom_events"]["events"]) > 8,
                    },
                    "alerts": observed["alerts"][:8],
                    "alerts_limited": observed["alerts_limited"] or len(observed["alerts"]) > 8,
                    "vm_count": len(observed["virtual_machines"]),
                    "vm_details_limited": len(observed["virtual_machines"]) > 8,
                    "virtual_machines": [
                        {
                            key: vm[key]
                            for key in (
                                "unit",
                                "state",
                                "result",
                                "oom_policy",
                                "oom_group",
                                "limits",
                                "memory_current_bytes",
                                "memory_peak_bytes",
                                "memory_events",
                                "tasks_current",
                                "task_events",
                                "pressure",
                            )
                            if key in vm
                        }
                        for vm in observed["virtual_machines"][:8]
                    ],
                }
                if (
                    observed["alerts"]
                    or observed["alerts_limited"]
                    or any(d["status"] != "passed" for d in observed["physical_disks"])
                ):
                    checks[-1]["result"] = "attention"
            elif name == "selinux_denials":
                details[name] = observed | {
                    "events": observed["events"][:32],
                    "limited": observed["limited"] or len(observed["events"]) > 32,
                }
                if observed["events"] or observed["limited"]:
                    checks[-1]["result"] = "attention"
            elif name in ("vm_confinement", "authenticated_time"):
                details[name] = observed
        except (Error, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
            checks.append({"name": name, "result": "attention", "detail": str(exc)[:256]})
    state = Coordinator(backend.directory, backend).load()
    rejected = state["rejected"]
    checks.append({"name": "quarantined_releases", "result": "attention" if rejected else "pass"})
    details["quarantined_releases"] = sorted(rejected, key=version_key)[-8:]
    from .bootloaders import Loaders

    loaders = Loaders(backend).load()["rejected"]
    details["quarantined_loaders"] = loaders[-8:]
    checks.append({"name": "quarantined_loaders", "result": "attention" if loaders else "pass"})
    commissioned = (backend.directory / "commissioned.json").exists()
    update_file = backend.directory / "release-check.json"
    update = read_json(update_file) if update_file.exists() else None
    update_ok = not commissioned
    if update:
        require(type(update) is dict and update.get("schema") == 1, "unknown release-check observation")
        require(update["result"] in ("pass", "fail"), "unknown release-check result")
        update_ok = False
        completed = update.get("last_success_at")
        if completed:
            age = (now - datetime.fromisoformat(completed)).total_seconds()
            update_ok = update["result"] == "pass" and 0 <= age <= maximum_update_check_age_seconds
        details["update_check"] = {
            key: update.get(key) for key in ("result", "attempted_at", "last_success_at", "version")
        }
    checks.append(
        {"name": "update_check", "result": "pass" if update_ok else "attention", "required": commissioned}
    )
    result = {
        "schema": 1,
        "installation_uuid": backend.manifest["installation_uuid"],
        "image_version": backend.current_version(),
        "boot_id": backend.boot_id(),
        "observed_at": now.isoformat(),
        "commissioned": commissioned,
        "result": "attention" if any(c["result"] != "pass" for c in checks) else "pass",
        "checks": checks,
        "details": details,
    }
    require(len(canonical(result)) <= MAX_REPORT, "health report exceeds its size limit")
    return result


def deliver(report, endpoint, token, *, ca_file=None, ca_data=None):
    endpoint = urlsplit(https_url(endpoint))
    require(re.fullmatch(rb"[A-Za-z0-9._~+/-]{32,2048}={0,2}", token), "invalid reporting service credential")
    body = canonical(report)
    require(len(body) <= MAX_REPORT, "health report exceeds its size limit")
    context = ssl.create_default_context(cafile=ca_file, cadata=ca_data)
    connection = http.client.HTTPSConnection(
        endpoint.hostname, endpoint.port or 443, timeout=20, context=context
    )
    try:
        connection.request(
            "POST",
            endpoint.path or "/",
            body=body,
            headers={
                "Authorization": "Bearer " + token.decode("ascii"),
                "Content-Type": "application/json",
                "User-Agent": "ParticleVE-health-report",
            },
        )
        response = connection.getresponse()
        require(
            response.status in (200, 202, 204),
            "health receiver refused delivery: HTTP " + str(response.status),
        )
        require(len(response.read(1025)) <= 1024, "health receiver acknowledgement exceeds its size limit")
        return {"delivered": True, "http_status": response.status, "report_result": report["result"]}
    except (OSError, http.client.HTTPException) as exc:
        raise Error("health receiver connection failed: " + type(exc).__name__) from exc
    finally:
        # http.client deliberately has no redirect/proxy handler: credentials
        # go only to the selected TLS-authenticated origin, never a Location URL.
        connection.close()


def send(backend):
    config = settings()
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    require(directory and Path(directory).is_absolute(), "send reports through the credential-loaded service")
    require(os.geteuid() == 0, "host inspection requires the trusted service bootstrap")
    lookup = run(
        [
            "busctl",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "LookupDynamicUserByName",
            "s",
            REPORT_USER,
        ]
    )
    match = re.fullmatch(r"u ([0-9]+)\n?", lookup.stdout)
    require(not lookup.stderr and match, "PID1 did not identify the private dynamic reporting user")
    uid = int(match[1])
    require(61184 <= uid <= 65519, "report delivery requires a private dynamic UID")
    payload = canonical(
        {
            "schema": 1,
            "uid": uid,
            "endpoint": config["endpoint"],
            "report": snapshot(
                backend, maximum_update_check_age_seconds=config["maximum_update_check_age_seconds"]
            ),
            "ca": private_file(CA_FILE).decode() if config["private_ca"] else None,
        }
    )
    require(len(payload) <= MAX_HANDOFF, "health handoff exceeds its size limit")
    fd = os.memfd_create("particleve-health-handoff", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)
    try:
        require(not os.fstat(fd).st_mode & 0o111, "health handoff must not be executable")
        require(os.write(fd, payload) == len(payload), "short health handoff write")
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, HANDOFF_SEALS)
        os.lseek(fd, 0, os.SEEK_SET)
        os.dup2(fd, 0, inheritable=True)
        os.set_inheritable(0, True)
    finally:
        if fd != 0:
            os.close(fd)
    # Replace the privileged inspector. There is no privileged parent parsing
    # network responses, and no retained user/VM ownership is changed.
    os.execv(
        "/usr/bin/setpriv",
        [
            "setpriv",
            f"--reuid={uid}",
            f"--regid={uid}",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "/usr/bin/python3",
            "-I",
            SENDER,
        ],
    )
    raise Error("native unprivileged reporting handoff unexpectedly returned")


def sender_main():
    uid = os.geteuid()
    require(
        61184 <= uid <= 65519 and os.getresuid() == (uid, uid, uid),
        "TLS sender is not a private dynamic user",
    )
    require(
        os.getresgid() == (uid, uid, uid) and not os.getgroups(), "TLS sender retained another group identity"
    )
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    require(
        all(int(status[name].strip(), 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1"
        and status["Seccomp"].strip() == "2",
        "TLS sender retained privilege or lost its syscall filter",
    )
    filesystem_abi = confine_filesystem()
    info = os.fstat(0)
    require(
        stat.S_ISREG(info.st_mode) and info.st_uid == 0 and 0 < info.st_size <= MAX_HANDOFF,
        "untrusted health handoff",
    )
    require(
        fcntl.fcntl(0, fcntl.F_GET_SEALS) & HANDOFF_SEALS == HANDOFF_SEALS, "health handoff is not sealed"
    )
    with os.fdopen(os.dup(0), "rb") as stream:
        data = stream.read(MAX_HANDOFF + 1)
    require(len(data) <= MAX_HANDOFF, "health handoff exceeds its size limit")
    payload = json.loads(data)
    require(payload["schema"] == 1 and payload["uid"] == uid, "health handoff identity differs")
    directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    groups = [
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")
    ]
    require(
        len(groups) == 1 and directory == Path("/run/credentials") / Path(groups[0]).name,
        "TLS sender has no credential directory for its owning unit",
    )
    info = directory.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == info.st_gid == 0
        and stat.S_IMODE(info.st_mode) == 0o550
        and os.statvfs(directory).f_flag & os.ST_RDONLY,
        "service credentials are not in PID1's read-only private mount",
    )
    # With the ! bootstrap, PID1 keeps root ownership and gives the allocated
    # dynamic UID read access through an ACL. No user/group/world write is allowed.
    fd = os.open(directory / "report-token", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o440
            and info.st_nlink == 1
            and 0 < info.st_size <= 2048,
            "service credential does not match PID1's private file contract",
        )
        token = stream.read(2049).removesuffix(b"\n")
    result = deliver(payload["report"], payload["endpoint"], token, ca_data=payload["ca"])
    result["sender_uid"] = uid
    result["sender_capabilities"] = "empty"
    result["sender_landlock_abi"] = filesystem_abi
    return result
