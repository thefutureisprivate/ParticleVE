"""Bounded, read-only pressure and VM cgroup observations."""

import hashlib
import json
import re
from pathlib import Path

from .common import capture_bounded, require
from .vms import UNIT

MAX_VMS = 128
CONTROLLERS = {"cpu", "io", "memory", "pids"}
OOM_PATTERN = (
    "oom-kill:|Memory cgroup out of memory:|Out of memory: Killed process|"
    "A process of this unit has been killed by the OOM killer|Failed with result 'oom-kill'"
)


def text(path):
    with path.open("rb") as stream:
        data = stream.read(65537)
    require(len(data) <= 65536 and data.isascii(), "resource observation exceeds its bound or is not ASCII")
    return data.decode()


def numbers(value):
    result = {}
    for line in value.splitlines():
        match = re.fullmatch(r"([a-z][a-z0-9_.]{0,63}) ([0-9]{1,20})", line)
        require(match and match[1] not in result, "invalid/duplicate cgroup counter")
        result[match[1]] = int(match[2])
    require(result, "empty cgroup counters")
    return result


def unsigned(path):
    observed = text(path).strip()
    require(re.fullmatch(r"[0-9]{1,20}", observed), "invalid unsigned cgroup value")
    return int(observed)


def pressure(path):
    observed = {}
    for line in text(path).splitlines():
        match = re.fullmatch(
            r"(some|full) avg10=([0-9]+\.[0-9]{2}) avg60=([0-9]+\.[0-9]{2}) "
            r"avg300=([0-9]+\.[0-9]{2}) total=([0-9]{1,20})",
            line,
        )
        require(match and match[1] not in observed, "invalid/duplicate pressure observation")
        values = {
            name: float(value)
            for name, value in zip(("avg10", "avg60", "avg300"), match.groups()[1:4], strict=True)
        }
        require(all(0 <= value <= 100 for value in values.values()), "invalid pressure percentage")
        observed[match[1]] = values | {"total_usec": int(match[5])}
    require(set(observed) == {"some", "full"}, "incomplete pressure observation")
    return observed


def devices(value):
    observed = {}
    for line in value.splitlines():
        device, *fields = line.split()
        require(
            re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", device) and device not in observed,
            "invalid I/O device observation",
        )
        values = {}
        for field in fields:
            match = re.fullmatch(r"([a-z_]{1,32})=(max|[0-9]{1,20})", field)
            require(match and match[1] not in values, "invalid I/O resource counter/limit")
            values[match[1]] = None if match[2] == "max" else int(match[2])
        require(values, "empty I/O device observation")
        observed[device] = values
    return observed


def controllers(root=Path("/sys/fs/cgroup")):
    available = set(text(root / "cgroup.controllers").split())
    require(available >= CONTROLLERS, "required cgroup v2 resource controllers are unavailable")
    return sorted(available)


def command(arguments):
    result = capture_bounded(arguments, timeout=10, maximum_bytes=512 * 1024)
    require(result.returncode == 0 and not result.stderr, "native resource inspection failed")
    return result.stdout


def virtual_machines(root=Path("/sys/fs/cgroup")):
    rows = json.loads(
        command(
            [
                "systemctl",
                "list-units",
                "--all",
                "--type=service",
                "--output=json",
                "systemd-vmspawn@*.service",
            ]
        )
    )
    require(type(rows) is list and len(rows) <= MAX_VMS, "VM resource inventory exceeds its bound")
    units = [row["unit"] for row in rows]
    require(
        len(units) == len(set(units)) and all(len(unit) <= 256 and UNIT.fullmatch(unit) for unit in units),
        "invalid VM resource inventory",
    )
    if not units:
        return []
    fields = (
        "Id",
        "ActiveState",
        "Result",
        "ControlGroup",
        "MemoryHigh",
        "MemoryMax",
        "MemorySwapMax",
        "TasksMax",
        "IOAccounting",
        "MemoryAccounting",
        "TasksAccounting",
        "OOMPolicy",
    )
    native = command(["systemctl", "show", *units, *("--property=" + name for name in fields)])
    observed = {}
    for block in native.strip().split("\n\n"):
        props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        name = props.get("Id")
        require(
            name in units and name not in observed and set(fields) <= props.keys(),
            "incomplete VM resource properties",
        )
        limits = {}
        for field in ("MemoryHigh", "MemoryMax", "MemorySwapMax", "TasksMax"):
            value = props[field]
            require(
                value == "infinity" or re.fullmatch(r"[0-9]{1,20}", value), "invalid native resource limit"
            )
            limits[field] = None if value == "infinity" else int(value)
        item = {
            "unit": name,
            "state": props["ActiveState"],
            "result": props["Result"],
            "oom_policy": props["OOMPolicy"],
            "limits": limits,
            "accounting": {
                field: props[field] == "yes"
                for field in ("IOAccounting", "MemoryAccounting", "TasksAccounting")
            },
        }
        require(
            all(props[field] in ("yes", "no") for field in item["accounting"]),
            "invalid accounting observation",
        )
        if props["ControlGroup"] and props["ActiveState"] in ("active", "activating", "deactivating"):
            cgroup = props["ControlGroup"]
            require(
                cgroup.startswith("/")
                and ".." not in cgroup.split("/")
                and str(Path(cgroup)) == cgroup
                and Path(cgroup).name == name,
                "invalid VM resource cgroup",
            )
            directory = root / cgroup.lstrip("/")
            item.update(
                memory_current_bytes=unsigned(directory / "memory.current"),
                memory_peak_bytes=unsigned(directory / "memory.peak"),
                memory_stat=numbers(text(directory / "memory.stat")),
                memory_events=numbers(text(directory / "memory.events")),
                tasks_current=unsigned(directory / "pids.current"),
                task_events=numbers(text(directory / "pids.events")),
                oom_group=unsigned(directory / "memory.oom.group"),
                cpu_stat=numbers(text(directory / "cpu.stat")),
                pressure={
                    kind: pressure(directory / (kind + ".pressure")) for kind in ("cpu", "memory", "io")
                },
            )
            for field in ("io.stat", "io.max"):
                item[field.replace(".", "_")] = (
                    devices(text(directory / field)) if (directory / field).exists() else None
                )
            if (directory / "cpu.max").exists():
                limit = text(directory / "cpu.max").strip().split()
                require(
                    len(limit) == 2
                    and re.fullmatch(r"max|[0-9]{1,20}", limit[0])
                    and re.fullmatch(r"[0-9]{1,20}", limit[1])
                    and int(limit[1]) > 0,
                    "invalid CPU bandwidth limit",
                )
                item["cpu_max"] = {
                    "quota_usec": None if limit[0] == "max" else int(limit[0]),
                    "period_usec": int(limit[1]),
                }
        observed[name] = item
    require(set(observed) == set(units), "VM resource observation is incomplete")
    return [observed[name] for name in sorted(observed)]


def oom_events():
    result = capture_bounded(
        [
            "journalctl",
            "--quiet",
            "--since=-10min",
            "--lines=65",
            "--output=json",
            "--output-fields=__CURSOR,MESSAGE,_TRANSPORT",
            "--grep=" + OOM_PATTERN,
            "_TRANSPORT=kernel",
            "+",
            "_PID=1",
        ],
        timeout=10,
        maximum_bytes=256 * 1024,
    )
    require(
        result.returncode == 0 or (result.returncode == 1 and not result.stdout),
        "OOM journal inspection failed",
    )
    require(not result.stderr, "OOM journal inspection produced diagnostics")
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    events = []
    for row in rows[:64]:
        # Export an event identity and bounded unit name, never raw kernel text,
        # killed-process arguments or memory contents.
        match = re.search(r"systemd-vmspawn@[A-Za-z0-9_.:\\-]+\.service", row["MESSAGE"])
        events.append(
            {
                "id": hashlib.sha256(row["__CURSOR"].encode()).hexdigest(),
                "source": "kernel" if row.get("_TRANSPORT") == "kernel" else "service-manager",
                "unit": match[0] if match and len(match[0]) <= 256 else None,
            }
        )
    return {"window_seconds": 600, "limited": len(rows) > 64, "events": events}
