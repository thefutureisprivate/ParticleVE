#!/usr/bin/python3
"""Evaluate USBGuard, including temporary-rule semantics, in a pinned VM.

Uses a hash-verified Fedora runtime bundle and signed dummy_hcd/configfs gadgets.
No firmware is flashed and no physical USB device may be present. This records
integration findings; successful execution is not approval to deploy USBGuard.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import select
import struct
import time
from pathlib import Path

from usb_gadget_fixture import VirtualUSB, wait_for

from particleve.common import require, run

UNIT = "particleve-usbguard-evaluation.service"
KEY_EVENT = struct.Struct("=qqHHI")
EVIOCGRAB = 0x40044590


def keyboard(gadget):
    device = gadget.host_device().resolve()
    nodes = [p for p in Path("/sys/class/input").glob("event*") if p.resolve().is_relative_to(device)]
    require(len(nodes) == 1, "expected only the synthetic recovery keyboard input")
    event = os.open("/dev/input/" + nodes[0].name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    report = None
    grabbed = False
    observed_release = False
    disconnected = False
    try:
        # Grab only this dummy controller's device, so test reports never reach
        # a console/session. No existing input device is opened or grabbed.
        fcntl.ioctl(event, EVIOCGRAB, 1)
        grabbed = True
        major, minor = map(int, (gadget.path / "functions/hid.test/dev").read_text().split(":"))
        devices = [p for p in Path("/dev").glob("hidg*") if p.stat().st_rdev == os.makedev(major, minor)]
        require(len(devices) == 1, "expected the synthetic HID report endpoint")
        report = os.open(devices[0], os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        # F24 has no printable console character. Still keep the device grabbed
        # until its release is observed, and disconnect it on any failed send.
        require(os.write(report, b"\0\0\x73\0\0\0\0\0") == 8, "keyboard press failed")
        require(select.select([], [report], [], 1)[1], "keyboard report did not complete")
        require(os.write(report, b"\0" * 8) == 8, "keyboard release failed")
        deadline = time.monotonic() + 3
        seen = set()
        while time.monotonic() < deadline and seen != {0, 1}:
            if select.select([event], [], [], 0.1)[0]:
                data = os.read(event, KEY_EVENT.size * 64)
                require(len(data) % KEY_EVENT.size == 0, "partial input event")
                for _, _, kind, code, value in KEY_EVENT.iter_unpack(data):
                    if kind == 1 and code == 194 and value in (0, 1):
                        seen.add(value)
        require(seen == {0, 1}, "recovery keyboard press/release did not reach the grabbed test reader")
        observed_release = True
    finally:
        try:
            try:
                if report is not None and not observed_release:
                    (gadget.path / "UDC").write_text("\n")
                    disconnected = True
            finally:
                if report is not None:
                    os.close(report)
            if grabbed and not disconnected:
                fcntl.ioctl(event, EVIOCGRAB, 0)
        finally:
            os.close(event)


class Guard:
    def __init__(self, directory):
        self.directory = directory
        self.bundle = directory / "bundle"
        identity = json.loads((self.bundle / "identity.json").read_text())
        for name, item in identity["files"].items():
            require(
                hashlib.sha256((self.bundle / name).read_bytes()).hexdigest() == item["sha256"],
                "bundle changed",
            )
        self.identity = identity
        self.loader = [
            str(self.bundle / "lib64/ld-linux-x86-64.so.2"),
            "--library-path",
            str(self.bundle / "lib64"),
        ]
        require(
            self.cli("list-rules", check=False).returncode != 0, "an existing USBGuard IPC server is running"
        )
        self.policy_directory = directory / "policy"
        self.policy_directory.mkdir(mode=0o700)
        self.rules = self.policy_directory / "rules.conf"
        self.baseline = (
            b"# Reviewed synthetic recovery and normal-mode fixtures only.\n"
            b'allow id 1209:0001 serial "PV_RECOVERY" via-port "1-1" with-interface equals { 03:01:01 }\n'
            b'allow id 1209:0002 serial "PV_NORMAL" via-port "2-1" '
            b"with-interface equals { 02:02:01 0a:00:00 }\n"
        )
        self.rules.write_bytes(self.baseline)
        self.rules.chmod(0o600)
        self.config = self.policy_directory / "daemon.conf"
        self.config.write_text(
            f"RuleFile={self.rules}\nImplicitPolicyTarget=block\nPresentDevicePolicy=apply-policy\n"
            "PresentControllerPolicy=keep\nInsertedDevicePolicy=apply-policy\nAuthorizedDefault=none\n"
            "RestoreControllerDeviceState=false\nDeviceManagerBackend=uevent\nIPCAllowedUsers=root\n"
            f"DeviceRulesWithPort=true\nAuditBackend=FileAudit\nAuditFilePath={self.policy_directory}/audit.log\n"
            "HidePII=true\n"
        )
        self.config.chmod(0o600)
        self.unit = Path("/run/systemd/system") / UNIT
        require(not self.unit.exists() and not self.unit.is_symlink(), "test unit already exists")
        self.vendor_unit = (self.bundle / "usr/lib/systemd/system/usbguard.service").read_text()

    def cli(self, *arguments, check=True, unprivileged=False):
        prefix = []
        if unprivileged:
            prefix = [
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
            ]
        return run(
            [*prefix, *self.loader, self.bundle / "usr/bin/usbguard", *arguments], check=check, timeout=10
        )

    def stop(self):
        run(["systemctl", "stop", UNIT], check=False)

    def start(self, *, readonly):
        self.stop()
        command = " ".join(
            [
                *self.loader,
                str(self.bundle / "usr/sbin/usbguard-daemon"),
                "-f",
                "-s",
                "-p",
                str(self.policy_directory / "daemon.pid"),
                "-c",
                str(self.config),
            ]
        )
        unit = re.sub(r"^ExecStart=.*$", "ExecStart=" + command, self.vendor_unit, flags=re.M)
        unit = re.sub(r"^PIDFile=.*$", f"PIDFile={self.policy_directory}/daemon.pid", unit, flags=re.M)
        unit = re.sub(
            r"^ReadWritePaths=.*$", f"ReadWritePaths=/dev/shm /sys {self.policy_directory}", unit, flags=re.M
        )
        unit = re.sub(r"^OOMScoreAdjust=.*$", "OOMScoreAdjust=0", unit, flags=re.M)
        if readonly:
            unit = unit.replace("ReadOnlyPaths=-/", "ReadOnlyPaths=-/ " + str(self.rules))
        unit = unit.replace(
            "[Service]\n",
            "[Service]\nLimitCORE=0\nCoredumpFilter=0\nTimeoutStartSec=20s\nTimeoutStopSec=10s\n",
        )
        self.unit.write_text(unit)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "start", UNIT], timeout=25)
        self.cli("list-rules")

    def close(self):
        self.stop()
        run(["systemctl", "reset-failed", UNIT], check=False)
        self.unit.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-installation", required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--preserve-unit", action="append", default=[])
    args = parser.parse_args()
    require(os.geteuid() == 0, "run in the disposable installation as root")
    directory = args.runtime_dir.resolve(strict=True)
    require(
        re.fullmatch(r"/run/particleve-usbguard-[a-zA-Z0-9_.-]+", str(directory)),
        "use the private test staging path",
    )
    directory.chmod(0o755)  # Only public RPM code is shared; policy stays 0700/0600.
    pids = {
        name: run(["systemctl", "show", "-p", "MainPID", "--value", name]).stdout.strip()
        for name in args.preserve_unit
    }
    require(all(int(pid) > 0 for pid in pids.values()), "preserved guests must be running")
    cases, findings = {}, {}
    guard = None
    with VirtualUSB(args.expect_installation) as fixture:
        try:
            recovery = fixture.create("particleve-recovery", 0, 1, "PV_RECOVERY", ["hid"])
            normal = fixture.create("particleve-normal", 1, 2, "PV_NORMAL", ["acm"])
            recovery.connect()
            normal.connect()
            run(["udevadm", "settle"])
            keyboard(recovery)
            cases["independent-recovery-keyboard-baseline"] = True
            guard = Guard(directory)
            guard.start(readonly=True)
            pid = run(["systemctl", "show", "-p", "MainPID", "--value", UNIT]).stdout.strip()
            status = dict(
                line.split(":", 1)
                for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                if ":" in line
            )
            maximum_caps = (1 << 0) | (1 << 2) | (1 << 3) | (1 << 29)
            require(
                not (int(status["CapBnd"].strip(), 16) & ~maximum_caps)
                and not (int(status["CapEff"].strip(), 16) & ~maximum_caps)
                and status["NoNewPrivs"].strip() == "1"
                and status["Seccomp"].strip() == "2",
                "test service gained unexpected capabilities or lost its native confinement",
            )
            profile = {
                "uid": status["Uid"].split(),
                "cap_effective": status["CapEff"].strip(),
                "cap_bounding": status["CapBnd"].strip(),
                "no_new_privileges": True,
                "seccomp": 2,
                "rss_kib": int(status["VmRSS"].split()[0]),
                "selinux_context": Path(f"/proc/{pid}/attr/current").read_text().strip(),
            }
            cases["native-service-capability-and-seccomp-observation"] = True
            require(guard.rules.read_bytes() == guard.baseline, "baseline policy changed")
            keyboard(recovery)
            cases["reviewed-present-devices-remain-usable"] = True
            guard.cli("--version", unprivileged=True)
            require(
                guard.cli("list-rules", unprivileged=True, check=False).returncode != 0,
                "unprivileged IPC allowed",
            )
            cases["root-only-ipc"] = True
            normal.close()
            normal = fixture.create("particleve-normal", 1, 2, "PV_NORMAL", ["acm", "hid"])
            node = normal.connect()
            wait_for(
                lambda: (node / "authorized").read_text().strip() == "0",
                "unexpected composite interface rejected",
            )
            keyboard(recovery)
            cases["unexpected-composite-function-denied"] = True
            normal.close()
            normal = fixture.create("particleve-boot", 1, 0xF0, "PV_BOOT", ["acm"])
            node = normal.connect()
            wait_for(
                lambda: (node / "authorized").read_text().strip() == "0",
                "unreviewed firmware identity denied",
            )
            cases["unreviewed-firmware-mode-denied"] = True
            normal.close()
            temporary = (
                'allow id 1209:00f0 serial "PV_BOOT" via-port "2-1" '
                'with-interface equals { 02:02:01 0a:00:00 } label "PV_TEMP_A"'
            )
            rule_id = guard.cli("append-rule", "--temporary", temporary).stdout.strip()
            require(rule_id.isdecimal(), "temporary append did not return its rule ID")
            require(guard.rules.read_bytes() == guard.baseline, "temporary append changed the baseline")
            normal = fixture.create("particleve-boot", 1, 0xF0, "PV_BOOT", ["acm"])
            node = normal.connect()
            wait_for(lambda: (node / "authorized").read_text().strip() == "1", "reviewed flashing transition")
            cases["narrow-volatile-firmware-transition"] = True
            removed = guard.cli("remove-rule", rule_id, check=False)
            findings["readonly_remove_returncode"] = removed.returncode
            findings["readonly_remove_diagnostic"] = removed.stderr.strip()[:512]
            findings["removed_rule_still_active_in_memory"] = "PV_TEMP_A" in guard.cli("list-rules").stdout
            require(guard.rules.read_bytes() == guard.baseline, "read-only baseline changed")
            findings["connected_device_authorized_after_rule_removal"] = (
                node / "authorized"
            ).read_text().strip() == "1"
            guard.start(readonly=True)
            wait_for(
                lambda: (node / "authorized").read_text().strip() == "0",
                "restart revokes the connected exception",
            )
            require(
                "PV_TEMP_A" not in guard.cli("list-rules").stdout, "temporary rule survived baseline reload"
            )
            keyboard(recovery)
            cases["baseline-restart-revokes-exception-preserves-input"] = True
            normal.close()
            normal = fixture.create("particleve-normal", 1, 2, "PV_NORMAL", ["acm"])
            node = normal.connect()
            wait_for(
                lambda: (node / "authorized").read_text().strip() == "1", "normal firmware mode restored"
            )
            cases["normal-mode-reconnect"] = True
            guard.start(readonly=False)
            a = guard.cli("append-rule", "--temporary", temporary).stdout.strip()
            other = (
                temporary.replace("00f0", "00f1")
                .replace("PV_BOOT", "PV_OTHER")
                .replace("PV_TEMP_A", "PV_TEMP_B")
            )
            guard.cli("append-rule", "--temporary", other)
            require(guard.rules.read_bytes() == guard.baseline, "temporary appends persisted immediately")
            guard.cli("remove-rule", a)
            findings["removal_persisted_other_temporary_rule"] = b"PV_TEMP_B" in guard.rules.read_bytes()
            guard.start(readonly=True)
            findings["other_temporary_rule_survived_restart"] = "PV_TEMP_B" in guard.cli("list-rules").stdout
            guard.stop()
            guard.rules.write_bytes(guard.baseline)
            guard.start(readonly=True)
            require("PV_TEMP_" not in guard.cli("list-rules").stdout, "reviewed baseline not restored")
            keyboard(recovery)
            cases["reviewed-policy-restored-after-characterization"] = True
            guard.stop()
            for root_hub in Path("/sys/bus/usb/devices").glob("usb*"):
                require(
                    (root_hub / "authorized_default").read_text().strip() == "0",
                    "daemon exit restored permissive defaults",
                )
            normal.close()
            normal = fixture.create("particleve-unknown", 1, 3, "PV_UNKNOWN", ["acm"])
            node = normal.connect()
            require(
                (node / "authorized").read_text().strip() == "0", "new device enabled with daemon stopped"
            )
            keyboard(recovery)
            cases["daemon-stop-keeps-new-devices-blocked-and-input-working"] = True
        finally:
            if guard is not None:
                guard.close()
    for name, pid in pids.items():
        require(
            run(["systemctl", "show", "-p", "MainPID", "--value", name]).stdout.strip() == pid,
            "preserved guest changed",
        )
    cases["virtual-devices-and-unit-removed-guests-preserved"] = True
    print(
        json.dumps(
            {
                "kernel": os.uname().release,
                "cases": cases,
                "findings": findings,
                "service_observation": profile,
                "package": next(row for row in guard.identity["packages"] if row.startswith("usbguard-")),
                "no_firmware_flashing": True,
                "physical_hardware_tested": False,
                "adoption_approved": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
