"""Physical memory headroom and read-only health of the selected boot disks."""

import json
from pathlib import Path

from .common import Deferred, Error, require, run
from .inventory import observe_disk
from .resourceusage import controllers, oom_events, pressure, virtual_machines


def memory():
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemAvailable"):
            number, unit = value.split()
            require(unit == "kB", "unexpected kernel memory units")
            fields[key] = int(number) * 1024
    require(
        set(fields) == {"MemTotal", "MemAvailable"} and 0 <= fields["MemAvailable"] <= fields["MemTotal"],
        "physical memory availability cannot be established",
    )
    return {"total_bytes": fields["MemTotal"], "available_bytes": fields["MemAvailable"]}


def disk_health(selected):
    observe_disk(selected)  # Recheck the configured whole-disk identity before querying it.
    result = run(
        ["smartctl", "--json", "--health", "--attributes", selected["path"]],
        check=False,
        timeout=20,
    )
    report = json.loads(result.stdout)
    require(isinstance(report, dict), "invalid smartctl report")
    passed = report.get("smart_status", {}).get("passed")
    # smartctl's exit status is a bitmask: bits 3..7 report device health/history.
    # Missing/unsupported transport data must never be presented as a healthy disk.
    if passed is False or result.returncode & 0xF8:
        status = "attention"
    elif result.returncode == 0 and passed is True:
        status = "passed"
    else:
        status = "unavailable"
    return {
        "role": selected["role"],
        "path": selected["path"],
        "status": status,
        "exit_status": result.returncode,
        "report": report,
    }


def status(config, selected, *, healthy):
    ram = memory()
    reserve = config["maintenance"]["minimum_available_ram_mib"] * 1024**2
    normal = config["resources"]["minimum_available_ram_mib"] * 1024**2
    ram.update(reserve_bytes=reserve, normal_reserve_bytes=normal)
    alerts = []
    if ram["available_bytes"] < normal:
        alerts.append("physical memory headroom is below the normal-operation reserve")
    elif ram["available_bytes"] < reserve:
        alerts.append("physical memory headroom is below the maintenance reserve")
    available = controllers()
    pressures = {kind: pressure(Path("/proc/pressure") / kind) for kind in ("cpu", "memory", "io")}
    machines = virtual_machines()
    events = oom_events()
    observations = {"host": pressures} | {vm["unit"]: vm["pressure"] for vm in machines if "pressure" in vm}
    for owner, observed in observations.items():
        for kind, threshold in config["resources"]["pressure_avg60_percent"].items():
            if observed[kind]["some"]["avg60"] >= threshold:
                alerts.append(f"sustained {kind} pressure exceeds policy: {owner}")
    for vm in machines:
        if vm["state"] == "failed" or vm["result"] == "oom-kill":
            alerts.append("VM unit failed: " + vm["unit"])
        if vm.get("memory_events", {}).get("oom_kill", 0):
            alerts.append("VM cgroup has OOM kills: " + vm["unit"])
        if vm["state"] in ("active", "activating") and not all(vm["accounting"].values()):
            alerts.append("VM resource accounting is disabled: " + vm["unit"])
        if vm["state"] in ("active", "activating"):
            if vm["oom_policy"] != "kill" or vm.get("oom_group") != 1:
                alerts.append("VM kernel group OOM policy changed: " + vm["unit"])
            limits = vm["limits"]
            if (
                any(
                    limits[key] is None or limits[key] <= 0 for key in ("MemoryHigh", "MemoryMax", "TasksMax")
                )
                or limits["MemoryHigh"] >= limits["MemoryMax"]
            ):
                alerts.append("VM resource limits violate the launch contract: " + vm["unit"])
    maxima = [vm["limits"]["MemoryMax"] for vm in machines if vm["state"] in ("active", "activating")]
    ram["running_vm_memory_max_bytes"] = sum(value for value in maxima if value is not None)
    if ram["running_vm_memory_max_bytes"] + normal >= ram["total_bytes"]:
        alerts.append("configured running VM memory maxima leave no normal host reserve before host overhead")
    if events["events"] or events["limited"]:
        alerts.append("recent out-of-memory events require inspection")
    if healthy and alerts:
        raise Deferred(alerts[0])
    disks = []
    for disk in selected:
        try:
            disks.append(disk_health(disk))
        except (Error, OSError, ValueError) as exc:
            disks.append(
                {"role": disk["role"], "path": disk["path"], "status": "unavailable", "reason": str(exc)}
            )
    if healthy and any(disk["status"] == "attention" for disk in disks):
        raise Deferred("a selected disk reports a SMART health fault; inspect physical disk health")
    return {
        "memory": ram,
        "physical_disks": disks,
        "controllers": available,
        "pressure": pressures,
        "virtual_machines": machines,
        "oom_events": events,
        "alerts": alerts[:32],
        "alerts_limited": len(alerts) > 32,
    }
