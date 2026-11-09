#!/usr/bin/python3
"""Exercise the RFKill policy with Fedora's signed virtual Wi-Fi driver.

Run only in a UUID-selected disposable QEMU installation with no exposed radios.
Stage the reviewed source in /run; the component unit changes only its launcher
and credential paths. No hardware transmitter is attached, and this does not
replace early-boot or physical reconnect/recovery acceptance of the final image.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

from particleve.common import canonical, digest, read_json, require, run
from particleve.radio import EVENT, POLICY_PATH, UNIT

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--expect-installation", required=True)
parser.add_argument("--source-dir", type=Path, required=True)
parser.add_argument("--preserve-unit", action="append", default=[])
args = parser.parse_args()
require(os.geteuid() == 0, "run inside the disposable test installation as root")
manifest = read_json("/var/lib/particleve/installation.json")
require(manifest["installation_uuid"] == args.expect_installation, "unexpected test installation")
require(
    run(["systemd-detect-virt", "--vm"]).stdout.strip() in ("qemu", "kvm"), "use the disposable QEMU fixture"
)
source = args.source_dir.resolve(strict=True)
require(re.fullmatch(r"/run/[a-zA-Z0-9_./-]+", str(source)), "stage reviewed component source under /run")
radios = Path("/sys/class/rfkill")
require(not list(radios.iterdir()), "do not test an installation with exposed radios")
require(not Path("/sys/module/virt_wifi").exists(), "virtual Wi-Fi must not already be loaded")
holders = sorted(p.name for p in Path("/sys/module/rfkill/holders").iterdir())
require(holders == ["cfg80211"], "unexpected RFKill module dependencies")
require(not list(Path("/sys/module/cfg80211/holders").iterdir()), "cfg80211 must have no active consumers")
initial_default = Path("/sys/module/rfkill/parameters/default_state").read_text().strip()
require(initial_default in ("0", "1"), "unknown initial RFKill default")
node = Path("/dev/rfkill")
initial_node = node.stat()
original_pids = {
    name: run(["systemctl", "show", "--property=MainPID", "--value", name]).stdout.strip()
    for name in args.preserve_unit
}
require(all(int(pid) > 0 for pid in original_pids.values()), "preserved units must be running")
native_units = ("systemd-rfkill.service", "systemd-rfkill.socket")
native_active = {
    unit: run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0
    for unit in native_units
}
require(not native_active[native_units[0]], "native state restoration must be idle before this test")
for unit in native_units:
    require(
        run(["systemctl", "show", "--property=LoadState", "--value", unit]).stdout.strip() == "loaded",
        "this component fixture must initially use the unmodified native RFKill units",
    )
runtime_unit = Path("/run/systemd/system") / UNIT
runtime_rule = Path("/run/udev/rules.d/71-particleve-radio.rules")
require(
    all(not path.exists() and not path.is_symlink() for path in (runtime_unit, runtime_rule)),
    "refusing to replace existing test files",
)
require(
    run(["systemctl", "show", "--property=LoadState", "--value", UNIT]).stdout.strip() == "not-found",
    "do not override an installed policy; use the isolated component fixture",
)
cases = {}


def property_value(name):
    return run(["systemctl", "show", "--property=" + name, "--value", UNIT]).stdout.strip()


def wait_for(operation, label):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if operation():
            cases[label] = True
            return
        time.sleep(0.05)
    raise RuntimeError("acceptance timeout: " + label)


def radio():
    nodes = list(radios.iterdir())
    require(len(nodes) == 1, "expected exactly the virtual test radio")
    result = nodes[0]
    require((result / "type").read_text().strip() == "wlan", "unexpected test radio type")
    return result


def block(value):
    index = int(radio().name.removeprefix("rfkill"))
    fd = os.open(node, os.O_RDWR | os.O_CLOEXEC)
    try:
        require(os.write(fd, EVENT.pack(index, 1, 2, value, 0)) == EVENT.size, "test state write failed")
    finally:
        os.close(fd)


def soft():
    return (radio() / "soft").read_text().strip()


def cycle_core():
    # No hardware is present and both known consumers have been stopped. Reset
    # the disposable kernel's unobservable per-type defaults by recreating the
    # core with its original module default, rather than guessing CHANGE_ALLs.
    for module in ("cfg80211", "rfkill"):
        run(["modprobe", "--remove", module])
    run(["modprobe", "rfkill", "default_state=" + initial_default])
    run(["modprobe", "cfg80211"])
    run(["udevadm", "settle"])


with tempfile.TemporaryDirectory(prefix="particleve-radio-component-", dir="/run") as temporary:
    directory = Path(temporary)
    directory.chmod(0o755)
    policy_path = directory / "policy.json"
    launcher = directory / "launcher.py"
    launcher.write_text(
        (source / "Sources/bin/particleve-radio-policy")
        .read_text()
        .replace('"/usr/lib/particleve"', repr(str(source)))
    )
    unit_source = source / "mkosi.extra/usr/lib/systemd/system" / UNIT
    unit = (
        unit_source.read_text()
        .replace(
            "ExecStart=/usr/libexec/particleve-radio-policy", f"ExecStart=/usr/bin/python3 -I {launcher}"
        )
        .replace("radio-policy:" + str(POLICY_PATH), "radio-policy:" + str(policy_path))
    )
    policy = {"allowed_types": []}
    policy_path.write_bytes(canonical(policy))
    policy_path.chmod(0o600)
    try:
        run(["systemctl", "stop", *native_units])
        run(["systemctl", "mask", "--runtime", *native_units])
        runtime_rule.parent.mkdir(exist_ok=True)
        runtime_rule.write_bytes(
            (source / "mkosi.extra/usr/lib/udev/rules.d/71-particleve-radio.rules").read_bytes()
        )
        runtime_unit.write_text(unit)
        run(["udevadm", "control", "--reload"])
        cycle_core()
        run(["systemctl", "daemon-reload"])
        validation = run(["systemd-analyze", "verify", "--man=no", runtime_unit])
        require(not validation.stderr.strip(), "radio unit verification diagnostics: " + validation.stderr)
        run(["modprobe", "virt_wifi"])
        wait_for(lambda: len(list(radios.iterdir())) == 1, "virtual-radio-registered")
        run(["systemctl", "start", UNIT])
        wait_for(lambda: soft() == "1", "existing-radio-blocked")
        require(
            property_value("StatusText") == "RFKill policy " + digest(policy), "wrong active policy identity"
        )
        permissions = node.stat()
        require(
            (permissions.st_uid, permissions.st_gid, stat.S_IMODE(permissions.st_mode)) == (0, 0, 0o600),
            "udev did not restrict RFKill access",
        )
        info = run(["udevadm", "info", "--query=property", "--path=/sys/devices/virtual/misc/rfkill"])
        # TAGS includes historical tags. Both rule matching at 73-seat-late and
        # logind's seat-device enumeration check CURRENT_TAGS instead.
        require(not re.search(r"^CURRENT_TAGS=.*:uaccess:", info.stdout, re.M), "current uaccess tag remains")
        cases["udev-root-only-no-session-access"] = True
        pid = property_value("MainPID")
        status = dict(
            line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line
        )
        require(
            all(int(value) > 0 for key in ("Uid", "Gid") for value in status[key].split())
            and "0" not in status["Groups"].split()
            and all(
                int(status[k].strip(), 16) == 0 for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
            )
            and status["NoNewPrivs"].strip() == "1"
            and status["Seccomp"].strip() == "2",
            "radio service has unexpected privileges",
        )
        require(not Path(f"/proc/{pid}/root/dev/rfkill").exists(), "raw device visible in service namespace")
        require(stat.S_ISCHR(Path(f"/proc/{pid}/fd/3").stat().st_mode), "inherited device descriptor missing")
        kernel_config = Path("/usr/lib/modules") / os.uname().release / "config"
        require(
            (Path(f"/proc/{pid}/root/run/credentials") / UNIT / "kernel-config").read_bytes()
            == kernel_config.read_bytes(),
            "verified kernel capabilities were not passed through the credential mount",
        )
        cases["zero-capability-private-device-handoff"] = True
        rss_kib = int(status["VmRSS"].split()[0])
        block(0)
        wait_for(lambda: soft() == "1", "denied-state-change-reblocked")
        run(["modprobe", "--remove", "virt_wifi"])
        wait_for(lambda: not list(radios.iterdir()), "virtual-radio-removed")
        run(["modprobe", "virt_wifi"])
        wait_for(lambda: len(list(radios.iterdir())) == 1 and soft() == "1", "denied-reconnect-blocked")
        policy = {"allowed_types": ["wlan"]}
        policy_path.write_bytes(canonical(policy))
        run(["systemctl", "restart", UNIT])
        wait_for(lambda: soft() == "0", "selected-radio-permitted")
        with node.open("r+b", buffering=0) as observer:
            os.set_blocking(observer.fileno(), False)
            while True:
                try:
                    os.read(observer.fileno(), EVENT.size)
                except BlockingIOError:
                    break
            run(["systemctl", "restart", UNIT])
            while True:
                try:
                    event = EVENT.unpack(os.read(observer.fileno(), EVENT.size))
                except BlockingIOError:
                    break
                require(
                    not (event[1] == 1 and event[2] in (0, 2) and event[3]),
                    "restart blocked an allowed radio",
                )
        cases["allowed-radio-uninterrupted-on-restart"] = True
        block(1)
        time.sleep(1)
        require(soft() == "1", "service cleared an allowed radio's manual software block")
        cases["allowed-manual-block-preserved"] = True
        policy = {"allowed_types": []}
        policy_path.write_bytes(canonical(policy))
        run(["systemctl", "restart", UNIT])
        previous_pid = property_value("MainPID")
        run(["systemctl", "kill", "--kill-whom=main", "--signal=KILL", UNIT])
        wait_for(
            lambda: (
                property_value("ActiveState") == "active"
                and property_value("MainPID") != previous_pid
                and property_value("StatusText") == "RFKill policy " + digest(policy)
                and soft() == "1"
            ),
            "supervised-restart-restores-policy",
        )
        last_ping = property_value("WatchdogTimestampMonotonic")
        wait_for(lambda: property_value("WatchdogTimestampMonotonic") != last_ping, "native-watchdog-ping")
        probe = "import os; os.open('/dev/rfkill', os.O_RDWR)"
        denied = run(
            [
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "python3",
                "-I",
                "-c",
                probe,
            ],
            check=False,
        )
        require(denied.returncode != 0 and "PermissionError" in denied.stderr, "ordinary user opened RFKill")
        cases["ordinary-user-control-denied"] = True
    finally:
        run(["systemctl", "stop", UNIT], check=False)
        run(["systemctl", "reset-failed", UNIT], check=False)
        runtime_unit.unlink(missing_ok=True)
        runtime_rule.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])
        if Path("/sys/module/virt_wifi").exists():
            run(["modprobe", "--remove", "virt_wifi"])
        run(["udevadm", "control", "--reload"])
        cycle_core()
        run(["systemctl", "unmask", "--runtime", *native_units])
        for name, active in native_active.items():
            if active:
                run(["systemctl", "start", name])

require(not list(radios.iterdir()) and not Path("/sys/module/virt_wifi").exists(), "test radio remains")
require(
    Path("/sys/module/rfkill/parameters/default_state").read_text().strip() == initial_default,
    "RFKill default changed",
)
after_node = node.stat()
require(
    (after_node.st_uid, after_node.st_gid, stat.S_IMODE(after_node.st_mode))
    == (initial_node.st_uid, initial_node.st_gid, stat.S_IMODE(initial_node.st_mode)),
    "original device permissions were not restored",
)
for name, pid in original_pids.items():
    require(
        run(["systemctl", "show", "--property=MainPID", "--value", name]).stdout.strip() == pid,
        "preserved VM changed",
    )
for name, active in native_active.items():
    require(
        (run(["systemctl", "is-active", "--quiet", name], check=False).returncode == 0) == active,
        "native RFKill unit changed",
    )
cases["cleanup-and-existing-vms-preserved"] = True
print(
    json.dumps(
        {
            "kernel": os.uname().release,
            "cases": cases,
            "service_rss_kib": rss_kib,
            "policy_source_sha256": hashlib.sha256(
                (source / "Sources/particleve/radio.py").read_bytes()
            ).hexdigest(),
            "fixture": "signed Fedora virt_wifi; no physical transmitter",
            "early_boot_tested": False,
        },
        sort_keys=True,
    )
)
