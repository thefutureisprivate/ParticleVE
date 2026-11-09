"""Bounded, reversible maintenance of existing vmspawn units. No VM definitions are created."""

import json
import os
import re
import time
from pathlib import Path

from .common import Deferred, Error, atomic_write, read_json, require, run, sync_dir, write_json
from .confinement import verify_processes
from .processes import observe

UNIT = re.compile(r"systemd-vmspawn@[A-Za-z0-9_.:\\-]+\.service\Z")
GATE = Path("/run/particleve/vm-start-inhibited")
DROPIN = Path("/run/systemd/system/systemd-vmspawn@.service.d/zz-particleve-maintenance.conf")


def properties(command, name, fields):
    text = run([command, "show", name, *(f"--property={field}" for field in fields)], timeout=15).stdout
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def process_identity(pid, *, proc=Path("/proc")):
    try:
        with observe(pid, proc=proc) as process:
            return process.identity()
    except FileNotFoundError, ProcessLookupError:
        return None


def unit_state(unit):
    require(UNIT.fullmatch(unit), "VM is not owned by the packaged vmspawn template")
    return properties(
        "systemctl",
        unit,
        (
            "ActiveState",
            "SubState",
            "MainPID",
            "ControlGroup",
            "InvocationID",
            "Restart",
            "RefuseManualStart",
            "ExecStart",
            "ExecStartPre",
        ),
    )


def cgroup_processes(cgroup):
    require(cgroup.startswith("/") and ".." not in cgroup.split("/"), "invalid VM cgroup")
    root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
    try:
        root.stat()
    except FileNotFoundError:
        return []
    result = set()

    def failed(exc):
        raise exc

    for directory, _, _ in os.walk(root, onerror=failed):
        path = Path(directory) / "cgroup.procs"
        try:
            result.update(int(pid) for pid in path.read_text().splitlines())
        except FileNotFoundError:
            continue
    return [identity for pid in sorted(result) if (identity := process_identity(pid))]


def qemu_processes():
    result = []
    for path in Path("/proc").glob("[0-9]*/exe"):
        try:
            binary = path.readlink().name
        except FileNotFoundError, ProcessLookupError:
            continue
        if binary.startswith("qemu-system-") or binary == "qemu-kvm":
            require(
                (identity := process_identity(int(path.parent.name))) is not None, "QEMU inventory changed"
            )
            result.append(identity)
    return result


def stop_instance(name):
    """ExecStop: wait for native ACPI shutdown before vmspawn receives any signal."""
    unit = f"systemd-vmspawn@{name}.service"
    require(UNIT.fullmatch(unit), "invalid vmspawn instance")
    groups = [
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")
    ]
    require(len(groups) == 1 and Path(groups[0]).name == unit, "VM stop helper must run in its owning unit")

    def remaining():
        return [entry for entry in cgroup_processes(groups[0]) if entry["pid"] != os.getpid()]

    if not remaining():
        return  # A guest which exited on its own needs no further poweroff request.
    try:
        result = run(["machinectl", "poweroff", "--", name], check=False, timeout=15)
        if result.returncode:
            print("Graceful VM poweroff request failed; waiting for owner-assisted guest exit", flush=True)
    except Error as exc:
        print(
            f"Graceful VM poweroff request failed: {exc}; waiting for owner-assisted guest exit", flush=True
        )
    # An ordinary host shutdown must not fall through to vmspawn's SIGKILL fallback.
    # Automatic maintenance uses its separate bounded Shutdown transaction before reboot.
    while remaining():
        time.sleep(1)


class LinuxVMs:
    clock = staticmethod(time.monotonic)
    pause = staticmethod(time.sleep)

    def inhibit(self):
        atomic_write(GATE, b"OS maintenance in progress\n")
        atomic_write(
            DROPIN,
            b"[Unit]\nRefuseManualStart=yes\n"
            b"ConditionPathExists=!/run/particleve/vm-start-inhibited\n[Service]\nRestart=no\n",
            0o644,
        )
        run(["systemctl", "daemon-reload"])

    def release(self):
        # Restore external restart policy while the start condition still blocks new invocations.
        DROPIN.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])
        GATE.unlink(missing_ok=True)
        if GATE.parent.exists():
            sync_dir(GATE.parent)

    def jobs(self):
        output = run(["systemctl", "list-jobs", "--no-legend", "--no-pager", "--full"], timeout=15).stdout
        return [line for line in output.splitlines() if "systemd-vmspawn@" in line]

    def inventory(self, *, inhibited=True):
        output = run(
            [
                "systemctl",
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--no-pager",
                "--full",
                "systemd-vmspawn@*.service",
            ],
            timeout=15,
        ).stdout
        units = {line.split()[0]: unit_state(line.split()[0]) for line in output.splitlines() if line.strip()}
        require(not self.jobs(), "VM start/restart jobs have not settled")
        machines = json.loads(run(["machinectl", "--all", "--output=json", "list"], timeout=15).stdout)
        result = []
        for machine in machines:
            if machine["machine"] == ".host" and machine["class"] == "host":
                continue  # Upstream --all includes the manager's intrinsic host entry.
            if machine["class"] != "vm":
                raise Deferred("unexpected host container; VM maintenance inventory is incomplete")
            require(machine["service"] == "systemd-vmspawn", "unmanaged VM runner present")
            info = properties("machinectl", machine["machine"], ("Unit", "Leader", "Class", "Service"))
            unit = info["Unit"]
            require(
                unit in units and UNIT.fullmatch(unit),
                "VM registration does not match an owning template unit",
            )
            state = units[unit]
            require(
                state["ActiveState"] == "active" and state["SubState"] == "running",
                "VM unit is transitioning",
            )
            require(
                "systemd-vmspawn" in state["ExecStart"]
                and "--register=yes" in state["ExecStart"]
                and "--keep-unit" in state["ExecStart"],
                "external unit must preserve vmspawn registration and ownership",
            )
            require(
                "vm-start-guard" in state["ExecStartPre"],
                "VM start guard was removed by external configuration",
            )
            require(
                "path=/usr/libexec/particleve-vm-run " in state["ExecStart"],
                "native VM lifecycle supervisor was removed by external configuration",
            )
            if inhibited:
                require(
                    state["RefuseManualStart"] == "yes" and state["Restart"] == "no",
                    "temporary VM inhibition was overridden",
                )
            processes = cgroup_processes(state["ControlGroup"])
            verify_processes(processes)
            require(
                int(info["Leader"]) in {p["pid"] for p in processes}, "QEMU leader is not in its owning unit"
            )
            result.append(
                {
                    "machine": machine["machine"],
                    "unit": unit,
                    "invocation": state["InvocationID"],
                    "cgroup": state["ControlGroup"],
                    "processes": processes,
                }
            )
        active = {
            name
            for name, state in units.items()
            if state["ActiveState"] in ("active", "activating", "deactivating") or int(state["MainPID"])
        }
        require(active == {m["unit"] for m in result}, "unit/process state and machined registrations differ")
        owned = {p["pid"] for m in result for p in m["processes"]}
        require(
            all(p["pid"] in owned for p in qemu_processes()),
            "QEMU process exists outside registered vmspawn units",
        )
        return result

    def alive(self, entry):
        original = any(process_identity(p["pid"]) == p for p in entry["processes"])
        state = unit_state(entry["unit"])
        active = bool(cgroup_processes(entry["cgroup"])) or state["ActiveState"] in (
            "active",
            "activating",
            "deactivating",
        )
        same = state["InvocationID"] == entry["invocation"]
        # ExecStop and auxiliary processes must finish too, even after MainPID exits.
        original = original or (same and active)
        # A new invocation must be left alone during restoration and must abort activation.
        replacement = active and not same
        return original, replacement

    def poweroff(self, entry):
        run(["machinectl", "poweroff", "--", entry["machine"]], timeout=15)

    def start(self, entry):
        original, replacement = self.alive(entry)
        if original or replacement:
            return
        run(["systemctl", "start", entry["unit"]], timeout=120)
        state = unit_state(entry["unit"])
        require(
            state["ActiveState"] == "active" and int(state["MainPID"]) > 0,
            f"VM restoration did not reach running state: {entry['unit']}",
        )

    def empty(self):
        require(not self.jobs(), "a VM start/restart is pending")
        require(not self.inventory() and not qemu_processes(), "VM processes have not all exited")

    def normal_operation(self):
        result = run(["systemctl", "is-system-running"], check=False, timeout=10)
        return result.stdout.strip() in ("running", "degraded")


class Shutdown:
    def __init__(self, directory, platform, boot_id, *, graceful_seconds, restore_seconds):
        self.path = Path(directory) / "vm-shutdown.json"
        self.platform, self.boot_id = platform, boot_id
        self.graceful_seconds, self.restore_seconds = graceful_seconds, restore_seconds

    def save(self, record):
        write_json(self.path, record)

    def freeze(self):
        if self.path.exists():
            previous = read_json(self.path)
            require(
                previous["phase"] in ("restored", "reboot-completed"),
                "previous VM shutdown attempt needs reconciliation",
            )
        record = {
            "schema": 1,
            "boot_id": self.boot_id,
            "phase": "inhibiting",
            "running": [],
            "requested": [],
            "restored": [],
            "failures": [],
        }
        self.save(record)  # durable intent precedes temporary restrictions
        self.platform.inhibit()
        deadline = self.platform.clock() + min(self.graceful_seconds, 60)
        while self.platform.jobs():
            require(self.platform.clock() < deadline, "concurrent VM starts/restarts did not settle")
            self.platform.pause(1)
        record["running"] = self.platform.inventory()
        record["phase"] = "frozen"
        self.save(record)

    def stop(self):
        record = read_json(self.path)
        require(record["phase"] == "frozen", "VM inventory has not been frozen")
        record["phase"] = "stopping"
        record["deadline"] = self.platform.clock() + self.graceful_seconds
        self.save(record)
        for entry in record["running"]:
            record["requested"].append(entry["unit"])
            self.save(record)  # recover a crash after ACPI submission but before its return
            self.platform.poweroff(entry)
        while True:
            observations = [self.platform.alive(entry) for entry in record["running"]]
            require(
                not any(replacement for _, replacement in observations), "a VM restarted despite inhibition"
            )
            if not any(original for original, _ in observations):
                self.platform.empty()
                record["phase"] = "stopped"
                self.save(record)
                return
            if self.platform.clock() >= record["deadline"]:
                raise Deferred("VM refused graceful poweroff; host reboot cancelled")
            self.platform.pause(1)

    def assert_empty(self):
        require(read_json(self.path)["phase"] == "stopped", "VM shutdown is incomplete")
        self.platform.empty()

    def mark_reboot(self):
        record = read_json(self.path)
        record["phase"] = "reboot-requested"
        self.save(record)

    def recover(self):
        if not self.path.exists():
            return {"action": "nothing-to-recover"}
        record = read_json(self.path)
        require(record["schema"] == 1, "unknown VM shutdown transaction schema")
        if record["boot_id"] != self.boot_id:
            previous_phase = record["phase"]
            self.platform.release()
            record["phase"] = "reboot-completed"
            self.save(record)
            return {"action": "external-startup-policy", "previous_phase": previous_phase}
        if record["phase"] in ("restored", "reboot-completed"):
            return {"action": record["phase"]}
        # Starting a VM during a shutdown already underway would put its state at risk.
        if not self.platform.normal_operation():
            record["failures"] = ["host is shutting down or normal operation cannot be confirmed"]
            self.save(record)
            return {"action": "restoration-deferred", "failures": record["failures"]}
        record["phase"] = "restoring"
        record.setdefault("restore_deadline", self.platform.clock() + self.restore_seconds)
        self.save(record)
        self.platform.release()
        pending = [
            e
            for e in record["running"]
            if e["unit"] in record["requested"] and e["unit"] not in record["restored"]
        ]
        failures = {}
        while pending:
            for entry in pending[:]:
                original, replacement = self.platform.alive(entry)
                if original:
                    continue  # leave the still-running original alone; observe late exits
                try:
                    if not replacement:
                        self.platform.start(entry)
                    record["restored"].append(entry["unit"])
                    pending.remove(entry)
                    self.save(record)
                except Error as exc:
                    failures[entry["unit"]] = str(exc)
            if not pending or self.platform.clock() >= record["restore_deadline"]:
                break
            self.platform.pause(1)
        record["failures"] = [
            failures.get(e["unit"], e["unit"] + ": still running after ACPI; late exit needs review")
            for e in pending
        ]
        record["phase"] = "restoration-failed" if pending else "restored"
        self.save(record)
        return {"action": record["phase"], "restored": record["restored"], "failures": record["failures"]}
