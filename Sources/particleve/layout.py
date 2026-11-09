"""Geometry in bytes, aligned for both 512e and 4Kn, based on the smaller disk."""

import uuid

from .common import digest, require
from .config import VERITY_SIGNATURE_SIZE, version_key

MIB = 1024**2
GIB = 1024**3
TYPES = {
    "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "usr": "8484680c-9521-48c6-9c11-b0720656f69e",
    "verity": "77ff5f63-e7b6-4633-acf4-1565b864c0e6",
    "verity_sig": "e7bb33fb-06cf-4e81-8273-e543b413e2e2",
    "raid": "a19d880f-05fc-4d3b-a006-743f0f84911e",
    "root": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
}


def os_label(version):
    version_key(version)
    return "PVE_" + version


def align(value):
    return ((value + MIB - 1) // MIB) * MIB


def calculate(config, devices, release):
    require(len(devices) == 2, "layout requires exactly two observed disks")
    require(len({d["identity"] for d in devices}) == 2, "selected paths alias the same physical disk")
    for device in devices:
        require(device["logical_sector"] in (512, 4096), "only 512-byte and 4Kn logical sectors supported")
        require(device["physical_sector"] in (512, 4096), "unsupported physical sector size")
        require(device["size"] > 0, "disk capacity is unavailable")
    storage = config["storage"]
    artifacts = release["artifacts"]
    working_space = 3 * sum(artifacts[k]["size"] for k in ("usr", "verity", "verity_sig", "uki"))
    esp = storage["esp_mib"] * MIB
    boot_bytes = artifacts["uki"]["size"] + artifacts["bootloader"]["size"]
    require(
        esp >= align(3 * boot_bytes + storage["firmware_staging_mib"] * MIB),
        "ESP cannot retain boot artifacts, staging space, and growth margin",
    )
    sizes = {
        kind: align(artifacts[kind]["size"] * (100 + storage["usr_growth_percent"]) // 100)
        for kind in ("usr", "verity", "verity_sig")
    }
    require(
        artifacts["verity_sig"]["size"] == VERITY_SIGNATURE_SIZE,
        "signature payload must completely cover its fixed partition",
    )
    sizes["verity_sig"] = VERITY_SIGNATURE_SIZE
    # Only swap uses mdraid. Writable state is native Btrfs over individually encrypted devices.
    swap = (storage["swap_mib"] + 160) * MIB
    fixed = MIB + esp + 2 * sum(sizes.values()) + swap
    end = (min(d["size"] for d in devices) // MIB - 1) * MIB
    state = end - fixed
    usable_state = state - 32 * MIB
    reserve = max(storage["reserve_mib"] * MIB, usable_state * storage["reserve_percent"] // 100)
    require(
        usable_state >= storage["minimum_state_mib"] * MIB
        and usable_state - reserve >= working_space + 2048 * MIB,
        "selected disks cannot fit state, update working space and shared filesystem headroom",
    )
    result = {
        "schema": 1,
        "storage_admission": "uefi-witness-v1",
        "installation_uuid": str(uuid.uuid4()),
        "config_sha256": digest(config),
        "release": release["version"],
        "release_sha256": digest(release),
        "devices": [],
        "state_usable_bytes": usable_state,
        "state_reserve_bytes": reserve,
        "storage_policy": {
            "filesystem": "btrfs",
            "data": "raid1",
            "metadata": "raid1",
            "factory_reset": False,
            "subvolumes": ["/var"],
        },
    }
    for selected, observed in zip(config["disks"], devices, strict=True):
        offset = MIB
        partitions = []

        def add(role, size, kind, label, part_uuid=None, partitions=partitions):
            nonlocal offset
            partitions.append(
                {
                    "number": len(partitions) + 1,
                    "role": role,
                    "offset": offset,
                    "size": size,
                    "type": TYPES[kind],
                    "label": label,
                    "uuid": part_uuid or str(uuid.uuid4()),
                }
            )
            offset += size

        add("esp", esp, "esp", f"ParticleVE-esp-{selected['role']}")
        for slot in ("a", "b"):
            for kind in ("verity_sig", "verity", "usr"):
                # The partition type GUID distinguishes the three OS payloads.
                label = os_label(release["version"]) if slot == "a" else "_empty"
                part_uuid = artifacts[kind]["partition_uuid"] if slot == "a" else None
                add(f"{slot}_{kind}", sizes[kind], kind, label, part_uuid)
        add("state", state, "root", f"ParticleVE-state-{selected['role']}")
        add("swap", swap, "raid", "ParticleVE-swap")
        require(offset == end, "internal layout accounting error")
        result["devices"].append(
            {**selected, "observed": observed, "disk_uuid": str(uuid.uuid4()), "partitions": partitions}
        )
    result["confirmation"] = digest(result)
    return result


def sfdisk_script(device):
    sector = device["observed"]["logical_sector"]
    lines = ["label: gpt", f"label-id: {device['disk_uuid']}", "unit: sectors"]
    for part in device["partitions"]:
        require(len(part["label"].encode("utf-16-le")) <= 72, "GPT label exceeds 36 UTF-16 code units")
        lines.append(
            f"start={part['offset'] // sector}, size={part['size'] // sector}, "
            f'type={part["type"]}, uuid={part["uuid"]}, name="{part["label"]}"'
        )
    return "\n".join(lines) + "\n"
