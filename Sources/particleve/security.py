"""Image-bound assertions and read-only evidence for the host security baseline."""

import errno
import json
import os
import re
import stat
import struct
from pathlib import Path

from .common import Error, capture_bounded, hash_file, read_json, require, run

KERNEL_REQUIRED = (
    "MEMFD_CREATE",
    "SECURITY_SELINUX",
    "SECURITY_LANDLOCK",
    "SECCOMP",
    "SECCOMP_FILTER",
    "BPF",
    "BPF_SYSCALL",
    "CGROUP_BPF",
    "BPF_JIT",
    "MODULES",
    "MODULE_SIG",
    "SECURITY_LOCKDOWN_LSM",
    "LOCK_DOWN_IN_EFI_SECURE_BOOT",
    "IOMMU_SUPPORT",
    "STRICT_KERNEL_RWX",
    "STRICT_MODULE_RWX",
    "CGROUPS",
    "MEMCG",
    "CGROUP_PIDS",
    "CGROUP_SCHED",
    "FAIR_GROUP_SCHED",
    "CFS_BANDWIDTH",
    "BLK_CGROUP",
    "BLK_DEV_THROTTLING",
    "PSI",
    "VT",
    "VT_CONSOLE",
    "SERIAL_8250",
    "SERIAL_8250_CONSOLE",
)
POLICY = Path("usr/lib/particleve/security-policy.json")
TPM_PROFILE = {"Name": "custom:particleve", "Attributes": "no-sha1-signing,no-sha1-verification"}
SELINUX_BOOLEANS = {"virt_use_nfs": False, "virt_use_samba": False, "virt_use_execmem": False}


def selinux_baseline():
    """Local VM storage and precompiled host code need none of these opt-ins."""
    response = run(["getsebool", *SELINUX_BOOLEANS])
    require(not response.stderr.strip(), "SELinux boolean inspection produced diagnostics")
    observed = {}
    for line in response.stdout.splitlines():
        match = re.fullmatch(r"([a-z0-9_]+) --> (on|off)", line)
        require(match is not None and match[1] not in observed, "invalid SELinux boolean observation")
        observed[match[1]] = match[2] == "on"
    require(observed == SELINUX_BOOLEANS, "SELinux virtualization boolean policy drift")
    return observed


def selinux_access():
    """Query effective permissions, including conditional and permissive state.

    libselinux's flags API queries selinuxfs/access. The older API deliberately
    does not return the per-domain permissive flag.
    """
    import selinux

    require(selinux.security_getenforce() == 1, "SELinux is not enforcing")
    classes = ("user_namespace", "alg_socket", "key_socket", "netlink_xfrm_socket")
    domains = {
        name: {kind: False for kind in classes}
        for name in (
            "svirt_t",
            "swtpm_t",
            "particleve_vmspawn_t",
            "systemd_homed_t",
            "systemd_nsresourced_t",
            "systemd_networkd_t",
            "systemd_resolved_t",
            "chronyd_t",
            "chronyd_restricted_t",
            "chronyc_t",
            "sshd_t",
            "unconfined_service_t",
            "unconfined_t",
        )
    }
    domains["particleve_vmspawn_t"]["user_namespace"] = True
    # Native cryptsetup benchmark demonstrated this interface in both contexts.
    for name in ("unconfined_service_t", "unconfined_t"):
        domains[name]["alg_socket"] = True
    sequences = set()

    def query(source, target, kind, action, allowed):
        cls = selinux.string_to_security_class(kind)
        permission = selinux.string_to_av_perm(cls, action) if cls else 0
        require(cls and permission, f"SELinux interface is unavailable: {kind}:{action}")
        decision = selinux.av_decision()
        result = selinux.security_compute_av_flags_raw(source, target, cls, permission, decision)
        require(result == 0, f"SELinux effective policy query failed: {source} {kind}:{action}")
        require(
            decision.flags == 0 and decision.decided & permission == permission,
            f"SELinux domain is permissive or policy decision is incomplete: {source}",
        )
        require(
            bool(decision.allowed & permission) == allowed,
            f"SELinux effective interface policy drift: {source} -> {target} {kind}:{action}",
        )
        sequences.add(decision.seqno)

    for domain, expected in domains.items():
        context = (
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
            if domain == "unconfined_t"
            else f"system_u:system_r:{domain}:s0"
        )
        for kind, allowed in expected.items():
            query(context, context, kind, "create", allowed)
    transitions = {}
    for domain in ("unconfined_t", "unconfined_service_t"):
        context = (
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"
            if domain == "unconfined_t"
            else f"system_u:system_r:{domain}:s0"
        )
        query(context, context.replace(":" + domain + ":", ":chronyc_t:"), "process2", "nnp_transition", True)
        transitions[domain] = "chronyc_t"
    require(len(sequences) == 1, "SELinux policy changed during inspection")
    return {
        "create": domains,
        "chrony_query_transitions": transitions,
        "policy_sequence": sequences.pop(),
        "permissive_domains": False,
    }


def write_tpm_profile(root):
    """Publish creation policy for explicit native provisioning, without opening any TPM state."""
    path = Path(root) / "usr/lib/particleve/tpm-profile.json"
    path.write_text(json.dumps(TPM_PROFILE) + "\n")


def ssh_baseline():
    """Inspect native effective policy after the host-key generation target."""
    common = {
        "usepam": "yes",
        "pubkeyauthentication": "yes",
        "pubkeyauthoptions": "touch-required verify-required",
        "authorizedkeyscommand": "/usr/bin/userdbctl ssh-authorized-keys %u",
        "authorizedkeyscommanduser": "root",
        "permitrootlogin": "prohibit-password",
        "permitemptypasswords": "no",
        "kbdinteractiveauthentication": "no",
        "disableforwarding": "yes",
        "permittunnel": "no",
        "x11forwarding": "no",
        "allowagentforwarding": "no",
    }
    result = {}
    for user in ("root", "particleve-policy-probe"):
        native = run(["/usr/sbin/sshd", "-T", "-C", f"user={user},host=localhost,addr=127.0.0.1"])
        require(not native.stderr.strip(), "SSH policy inspection diagnostics: " + native.stderr.strip())
        values = {
            key.lower(): value
            for line in native.stdout.splitlines()
            if " " in line
            for key, value in [line.split(" ", 1)]
        }
        expected = common | {
            "passwordauthentication": "no" if user == "root" else "yes",
            "authenticationmethods": "publickey" if user == "root" else "publickey,password",
        }
        require(all(values.get(k) == v for k, v in expected.items()), "SSH authentication/forwarding drift")
        algorithms = values.get("pubkeyacceptedalgorithms", "").split(",")
        require(
            {"sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"} <= set(algorithms),
            "FIDO2 SSH key support is missing",
        )
        result["root" if user == "root" else "homed"] = expected | {"fido2_key_types": True}
    return result


def kernel_baseline(root):
    from .kernelruntime import kernel_support

    trees = [p for p in (Path(root) / "usr/lib/modules").iterdir() if p.is_dir()]
    require(len(trees) == 1, "security baseline requires exactly one kernel")
    config = trees[0] / "config"
    values = dict(re.findall(r"^CONFIG_(\w+)=(.+)$", config.read_text(), re.M))
    missing = [name for name in KERNEL_REQUIRED if values.get(name) != "y"]
    require(not missing, "kernel security support missing: " + ", ".join(missing))
    require(values.get("RFKILL") in ("y", "m"), "kernel RFKill support is missing")
    console_uarts = {}
    for name in ("SERIAL_8250_NR_UARTS", "SERIAL_8250_RUNTIME_UARTS"):
        value = values.get(name, "")
        require(
            value.isdecimal() and int(value) >= 4, "kernel lacks the four signed serial consoles: " + name
        )
        console_uarts[name] = int(value)
    return {
        "schema": 1,
        "kernel": trees[0].name,
        "config_sha256": hash_file(config),
        "required": {name: values[name] for name in KERNEL_REQUIRED},
        "module_sig_force": values.get("MODULE_SIG_FORCE") == "y",
        "rfkill": {"core": values["RFKILL"], "deprecated_input": values.get("RFKILL_INPUT") == "y"},
        "module_signing_key": values.get("MODULE_SIG_KEY"),
        "iommu_default_strict": values.get("IOMMU_DEFAULT_DMA_STRICT") == "y",
        "runtime_support": kernel_support(values),
        "console_uarts": console_uarts,
    }


def verified_usr_mount():
    """An existing verity mapper is insufficient if an extension hides its mounted tree."""
    device = Path("/dev/mapper/usr").stat()
    require(stat.S_ISBLK(device.st_mode), "verified usr mapper is not a block device")
    observed = run(
        [
            "findmnt",
            "--json",
            "--target",
            "/usr",
            "--output",
            "TARGET,SOURCE,FSTYPE,MAJ:MIN,FSROOT,VFS-OPTIONS",
        ]
    )
    require(not observed.stderr, "verified usr mount inspection produced diagnostics")
    mounts = json.loads(observed.stdout)["filesystems"]
    require(len(mounts) == 1, "verified usr mount is ambiguous")
    mount = mounts[0]
    options = mount["vfs-options"].split(",")
    require(
        mount["target"] == "/usr"
        and mount["fstype"] == "erofs"
        and mount["fsroot"] == "/"
        and mount["maj:min"] == f"{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}"
        and "ro" in options
        and "rw" not in options,
        "usr is not the unchanged read-only verified EROFS mount",
    )
    return {"filesystem": mount["fstype"], "device": mount["maj:min"], "readonly": True}


def usr_backing_disks(mapper, *, sysfs=Path("/sys")):
    """Identify both physical verity members, without following ambiguous UUID links."""
    device = sysfs / "class/block" / mapper
    require((device / "dm/uuid").read_text().strip().startswith("CRYPT-VERITY-"), "usr is not dm-verity")
    members = list((device / "slaves").iterdir())
    require(len(members) == 2, "unexpected usr verity backing")
    disks = set()
    for member in members:
        physical = member.resolve(strict=True)
        require((physical / "partition").is_file(), "usr backing is not a physical disk partition")
        disks.add(physical.parent.name)
    return disks


def capabilities(data):
    """Decode Linux vfs_cap_data; namespace-rooted capabilities are explicit."""
    require(len(data) in (20, 24), "unsupported file capability record")
    magic, low_p, low_i, high_p, high_i = struct.unpack("<IIIII", data[:20])
    revision = magic >> 24
    require(
        revision in (2, 3) and len(data) == (24 if revision == 3 else 20) and magic & 0xFFFFFE == 0,
        "unsupported file capability flags",
    )
    return {
        "effective": bool(magic & 1),
        "permitted": low_p | high_p << 32,
        "inheritable": low_i | high_i << 32,
        "rootid": struct.unpack("<I", data[20:])[0] if revision == 3 else 0,
    }


def privilege_inventory(root, *, image=None):
    root = Path(root)
    result = {}

    def failed(exc):
        raise exc

    for directory, dirs, files in os.walk(root / "usr", followlinks=False, onerror=failed):
        dirs.sort()
        for name in sorted(files):
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            try:
                caps = capabilities(os.getxattr(path, "security.capability", follow_symlinks=False))
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    raise
                caps = None
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o6000 or caps:
                owner = info.st_uid, info.st_gid
                if image is not None:
                    # fsck.erofs applies chown after xattrs, clearing capabilities.
                    # Extraction therefore omits chown; read the original owner
                    # from EROFS metadata rather than trusting the extractor UID.
                    name = "/" + path.relative_to(root / "usr").as_posix()
                    metadata = run(["dump.erofs", "--path=" + name, image]).stdout
                    matches = re.findall(r"^Uid:\s*(\d+)\s+Gid:\s*(\d+)\s+Access:", metadata, re.M)
                    require(len(matches) == 1, "ambiguous original privileged-file ownership")
                    owner = tuple(int(value) for value in matches[0])
                result["/" + path.relative_to(root).as_posix()] = {
                    "mode": format(mode, "04o"),
                    "uid": owner[0],
                    "gid": owner[1],
                    "capabilities": caps,
                }
    return result


def check_privileges(root, *, image=None):
    policy = read_json(Path(root) / POLICY)
    require(policy.get("schema") == 1, "unknown image privilege policy")
    allowed = policy["privileged_files"]
    for path, record in allowed.items():
        require(path.startswith("/usr/") and record.get("purpose"), "privilege needs a reviewed purpose")
        require(
            record["uid"] == 0 and not int(record["mode"], 8) & 0o022, "unsafe privileged-file owner/mode"
        )
    actual = privilege_inventory(root, image=image)
    expected = {path: {k: v for k, v in record.items() if k != "purpose"} for path, record in allowed.items()}
    require(actual == expected, "image privileged-file inventory differs from the reviewed policy")
    return actual


def apply_image_privileges(root):
    """Revoke only individually reviewed privileges, rejecting dependency drift first."""
    root = Path(root)
    policy = read_json(root / POLICY)
    require(policy.get("schema") == 1, "unknown image privilege policy")
    allowed, revoked = policy["privileged_files"], policy["revoked_privileges"]
    require(not (set(allowed) & set(revoked)), "conflicting image privilege decisions")
    expected = {
        path: {k: v for k, v in item.items() if k != "purpose"} for path, item in (allowed | revoked).items()
    }
    actual = privilege_inventory(root)
    require(
        all(name in expected and item == expected[name] for name, item in actual.items())
        and all(actual.get(name) == expected[name] for name in allowed),
        "package privilege inventory expanded or a required helper changed",
    )
    for name, item in revoked.items():
        require(
            name.startswith("/usr/") and item.get("purpose"), "privilege revocation needs a reviewed purpose"
        )
        if name not in actual:
            continue  # A vendor already removing an unused privilege is acceptable.
        path = root / name.lstrip("/")
        if item["capabilities"]:
            os.removexattr(path, "security.capability", follow_symlinks=False)
        path.chmod(int(item["mode"], 8) & ~0o6000, follow_symlinks=False)
    return check_privileges(root)


def process_evidence(pid, *, proc=Path("/proc")):
    directory = proc / str(pid)
    status = dict(
        line.split(":", 1) for line in (directory / "status").read_text().splitlines() if ":" in line
    )
    fields = (
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    )
    args = (directory / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    # Native credentials and fw_cfg arguments can contain secrets. Record only
    # security-relevant options, never the complete command/environment or FDs.
    options = {}
    for option in ("-sandbox", "-accel", "-machine", "-cpu", "-run-with"):
        options[option] = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg == option]
    devices = set()
    for fd in (directory / "fd").iterdir():
        try:
            info = fd.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISCHR(info.st_mode):
            devices.add(f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}")
    return {
        "pid": pid,
        "status": {field: status[field].strip() for field in fields},
        "selinux": (directory / "attr/current").read_text().rstrip("\0\n"),
        "namespaces": {p.name: p.readlink().as_posix() for p in (directory / "ns").iterdir()},
        "character_devices": sorted(devices),
        "security_options": options,
    }


def firmware_evidence():
    firmware = capture_bounded(["fwupdmgr", "security", "--json"], timeout=60, maximum_bytes=256 * 1024)
    require(not firmware.stderr.strip(), "fwupd security inspection produced diagnostics")
    try:
        data = json.loads(firmware.stdout)
    except (ValueError, RecursionError) as exc:
        raise Error("invalid fwupd security observation") from exc
    require(type(data) is dict, "invalid fwupd security response")
    if firmware.returncode:
        require(type(data.get("Error")) is dict, "unknown fwupd security failure")
        return {"available": False, "reason": data["Error"], "attributes": []}
    attributes = data.get("SecurityAttributes")
    require(
        type(attributes) is list and attributes and all(type(attribute) is dict for attribute in attributes),
        "unknown/empty fwupd security attributes",
    )
    return {"available": True, "attributes": attributes}


def live_baseline(root=Path("/"), *, evidence=True):
    from .kernelruntime import baseline as runtime_baseline
    from .landlock import abi_version
    from .memoryprivacy import baseline as memory_baseline
    from .resourceusage import controllers

    baseline = kernel_baseline(root)
    baseline["kernel_runtime"] = runtime_baseline()
    baseline["memory_privacy"] = memory_baseline()
    baseline["resource_controllers"] = controllers()
    baseline["landlock_abi"] = abi_version()
    require(os.uname().release == baseline["kernel"], "running kernel differs from verified /usr")
    require(
        "systemd.ssh_auto=no" in Path("/proc/cmdline").read_text().split(),
        "automatic SSH socket generation is enabled",
    )
    lockdown = Path("/sys/kernel/security/lockdown").read_text().strip()
    selected = re.findall(r"\[(\w+)\]", lockdown)
    require(selected in (["integrity"], ["confidentiality"]), "kernel lockdown is not enforced")
    enforcement = Path("/sys/module/module/parameters/sig_enforce").read_text().strip()
    require(enforcement in ("Y", "N", "1", "0"), "unknown module-signature enforcement state")
    nested = {
        p.parent.parent.name: p.read_text().strip()
        for p in Path("/sys/module").glob("kvm_*/parameters/nested")
    }
    require(
        nested and all(value in ("N", "0") for value in nested.values()), "nested virtualization is enabled"
    )
    baseline.update(lockdown=selected[0], module_sig_enforce=enforcement, nested=nested)
    if not evidence:
        return baseline
    from .physical import collect as physical_interfaces

    baseline["physical_interfaces"] = physical_interfaces()
    keys = {}
    for name in (".builtin_trusted_keys", ".secondary_trusted_keys", ".machine", ".platform"):
        keys[name] = run(["keyctl", "list", "%:" + name]).stdout
    baseline.update(
        accepted_keyrings=keys,
        cpu_vulnerabilities={
            p.name: p.read_text().strip() for p in Path("/sys/devices/system/cpu/vulnerabilities").iterdir()
        },
        microcode=sorted(set(re.findall(r"^microcode\s*:\s*(.+)$", Path("/proc/cpuinfo").read_text(), re.M))),
        iommu_groups=len(list(Path("/sys/kernel/iommu_groups").iterdir())),
    )
    baseline["firmware_security"] = firmware_evidence()
    return baseline
