"""Native encrypted Btrfs mirror and separate encrypted md swap health."""

import os
import re
from pathlib import Path

from .common import Deferred, array_uuid, require, run


def profiles(text):
    rows = []
    for line in text.splitlines():
        match = re.fullmatch(r"(Data|Metadata|System), ([A-Za-z0-9]+): total=(\d+), used=(\d+)", line.strip())
        if match:
            rows.append(
                {
                    "kind": match[1].lower(),
                    "profile": match[2].lower(),
                    "total": int(match[3]),
                    "used": int(match[4]),
                }
            )
    require({r["kind"] for r in rows} >= {"data", "metadata"}, "Btrfs allocation profiles unavailable")
    return rows


def members(text):
    return [
        {"devid": int(m[1]), "size": int(m[2]), "used": int(m[3]), "path": m[4]}
        for line in text.splitlines()
        if (m := re.fullmatch(r"\s*devid\s+(\d+)\s+size\s+(\d+)\s+used\s+(\d+)\s+path\s+(.+)", line))
    ]


def present_members(manifest, devices, *, admitted=None):
    require(1 <= len(devices) <= 2, "Btrfs device inventory is ambiguous")
    require(len({d["devid"] for d in devices}) == len(devices), "duplicate Btrfs device identity")
    present = []
    for member in devices:
        matches = [d for d in manifest["devices"] if d["btrfs_devid"] == member["devid"]]
        require(len(matches) == 1, "unrecorded Btrfs device")
        disk = matches[0]
        mapper = f"particleve-state-{disk['role']}"
        part = next(p for p in disk["partitions"] if p["role"] == "state")
        underlying = Path("/dev/disk/by-partuuid", part["uuid"])
        if member["path"] == "MISSING":
            require(
                member["size"] == 0
                and member["used"] == 0
                and (
                    (admitted is not None and disk["role"] not in admitted)
                    or (not Path(disk["path"]).exists() and not underlying.exists())
                )
                and not Path("/dev/mapper", mapper).exists(),
                "Btrfs missing member conflicts with an available recorded device",
            )
            continue
        require(admitted is None or disk["role"] in admitted, "quarantined Btrfs member was assembled")
        require(
            Path(member["path"]).resolve() == Path("/dev/mapper", mapper).resolve(),
            "Btrfs device mapping changed",
        )
        require(
            run(["cryptsetup", "luksUUID", underlying]).stdout.strip() == disk["state_luks_uuid"],
            "state LUKS identity changed",
        )
        detail = run(["cryptsetup", "status", mapper]).stdout
        match = re.search(r"^\s*device:\s*(.+)$", detail, re.M)
        require(
            match and Path(match[1]).resolve() == underlying.resolve(),
            "state mapper uses an unexpected partition",
        )
        present.append(member)
    require(present, "no recorded Btrfs member is available")
    return present


def status(manifest, config, *, healthy):
    from .admission import verify_manifest
    from .common import read_json

    journal = Path("/var/lib/particleve/replacement.json")
    replacing = read_json(journal)["role"] if journal.exists() else None
    witness = verify_manifest(manifest, replacing=replacing)
    admitted = witness["allowed"] + ([replacing] if replacing else [])
    fsid = manifest["btrfs"]["uuid"]
    require(Path("/sys/fs/btrfs", fsid).exists(), "recorded Btrfs root is not mounted")
    allocation = profiles(run(["btrfs", "filesystem", "df", "--raw", "/"]).stdout)
    devices = present_members(
        manifest, members(run(["btrfs", "filesystem", "show", "--raw", "/"]).stdout), admitted=admitted
    )
    md = Path("/dev/md/particleve-swap")
    require(
        md.exists() and array_uuid("particleve-swap") == manifest["swap"]["md_uuid"],
        "swap array identity changed",
    )
    require(
        run(["cryptsetup", "luksUUID", md]).stdout.strip() == manifest["swap"]["luks_uuid"],
        "swap LUKS identity changed",
    )
    detail = run(["cryptsetup", "status", "particleve-swap"]).stdout
    swap_device = re.search(r"^\s*device:\s*(.+)$", detail, re.M)
    require(
        swap_device and Path(swap_device[1]).resolve() == md.resolve(),
        "swap mapper uses an unexpected device",
    )
    sys_md = Path("/sys/class/block", md.resolve().name, "md")
    degraded_swap = int((sys_md / "degraded").read_text().strip())
    sync_action = (sys_md / "sync_action").read_text().strip()
    stat = os.statvfs("/")
    free, total = stat.f_bavail * stat.f_frsize, stat.f_blocks * stat.f_frsize
    reserve = max(
        config["storage"]["reserve_mib"] * 1024**2, total * config["storage"]["reserve_percent"] // 100
    )
    device_stats = run(["btrfs", "device", "stats", "--check", "/"], check=False)
    require(device_stats.returncode in (0, 64), "cannot read Btrfs device error counters")
    scrub = run(["btrfs", "scrub", "status", "/"], check=False)
    if healthy:
        if len(devices) != 2 or degraded_swap or sync_action != "idle":
            raise Deferred("Btrfs or swap redundancy is degraded or rebuilding")
        if any(r["profile"] != "raid1" for r in allocation):
            raise Deferred("allocated Btrfs data/metadata/system profiles have not returned to RAID1")
        require(device_stats.returncode == 0, "Btrfs reports device errors; inspect scrub and device health")
        uncorrectable = re.search(r"Uncorrectable:\s*(\d+)", scrub.stdout, re.I)
        require(not uncorrectable or int(uncorrectable[1]) == 0, "Btrfs scrub reports uncorrectable errors")
        require(free >= reserve, "shared Btrfs free-space reserve exhausted")
        for row in allocation:
            if row["kind"] == "metadata":
                require(
                    row["used"] * 100 <= row["total"] * config["storage"]["metadata_max_percent"],
                    "Btrfs metadata allocation exceeds the maintenance threshold",
                )
        balance = run(["btrfs", "balance", "status", "/"], check=False).stdout.lower()
        require("no balance found" in balance, "Btrfs balance is active or cannot be excluded")
        replace = run(["btrfs", "replace", "status", "-1", "/"], check=False).stdout.lower()
        require(
            "never started" in replace or "finished" in replace,
            "Btrfs replacement is active or cannot be excluded",
        )
        if (Path("/var/lib/particleve") / "replacement.json").exists():
            raise Deferred("disk replacement has not been finalized and commissioned")
    return {
        "uuid": fsid,
        "devices": devices,
        "allocation": allocation,
        "free_bytes": free,
        "reserve_bytes": reserve,
        "swap_degraded": degraded_swap,
        "swap_sync_action": sync_action,
        "device_errors": device_stats.stdout,
        "scrub": scrub.stdout,
        "nocow_payload_checksums": False,
        "admitted_roles": witness["allowed"],
        "quarantined_roles": [r for r in ("a", "b") if r not in witness["allowed"]],
    }
