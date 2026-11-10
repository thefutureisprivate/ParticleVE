import uuid
from pathlib import Path

from particleve.common import read_json
from particleve.layout import GIB, MIB

ROOT = Path(__file__).resolve().parent.parent


def host():
    result = read_json(ROOT / "Tools/Examples/host.json")
    result["admin_ssh_keys"] = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER owner"
    ]
    result["feed"] = "https://updates.example.org/particleve"
    return result


def release(version="45.0.1.2-1.1"):
    root_hash = "ab" * 32
    result = {
        "schema": 1,
        "version": version,
        "architecture": "x86-64",
        "cpu_baseline": "x86-64-v2",
        "fedora": "45",
        "usr_root_hash": root_hash,
        "persistent_state": {"btrfs_features": "initial", "vmspawn": "262", "qemu": "11"},
        "sources": {name: "a" * 40 for name in ("particleos", "mkosi")},
        "artifacts": {},
    }
    for kind, size in {
        "usr": 4 * GIB,
        "verity": 64 * MIB,
        "verity_sig": MIB,
        "uki": 120 * MIB,
        "bootloader": MIB,
        "fwupd_efi": MIB,
    }.items():
        item = {"size": size, "sha256": "a" * 64}
        if kind in ("usr", "verity", "verity_sig"):
            item["partition_uuid"] = (
                str(uuid.UUID(hex=root_hash[:32]))
                if kind == "usr"
                else (
                    str(uuid.UUID(hex=root_hash[32:]))
                    if kind == "verity"
                    else "11111111-2222-3333-4444-555555555555"
                )
            )
            suffix = {
                "usr": "usr-x86-64",
                "verity": "usr-x86-64-verity",
                "verity_sig": "usr-x86-64-verity-sig",
            }[kind]
            item["file"] = f"ParticleVE_{version}_x86-64.{suffix}.{item['partition_uuid']}.raw"
        else:
            item["file"] = f"ParticleVE_{version}_x86-64.efi" if kind == "uki" else f"{kind}.efi"
        result["artifacts"][kind] = item
    return result


def devices():
    return [
        {
            "identity": f"8:{n}",
            "size": size * GIB,
            "logical_sector": 512,
            "physical_sector": 4096,
            "serial": f"REPLACE_SERIAL_{role}",
            "wwn": f"wwn-{role}",
        }
        for n, size, role in ((0, 256, "A"), (16, 512, "B"))
    ]
