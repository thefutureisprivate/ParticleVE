import copy
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


class Backend:
    def __init__(self):
        self.config = host()
        self.current = "45.0.1.1-1.1"
        self.boot = "first-boot"
        self.latest = "45.0.1.2-1.1"
        self.releases = {
            "45.0.1.1-1.1": release("45.0.1.1-1.1"),
            "45.0.1.2-1.1": release("45.0.1.2-1.1"),
            "45.0.1.3-1.1": release("45.0.1.3-1.1"),
        }
        self.disks = {}
        self.entries = {}
        self.calls = []
        self.blocked = None
        self.fail_at = None
        self.commissioned = True

    def event(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise OSError(f"simulated interruption at {name}")

    def current_version(self):
        return self.current

    def boot_id(self):
        return self.boot

    def check_commissioned(self):
        from particleve.common import Deferred

        if not self.commissioned:
            raise Deferred("not commissioned")

    def check_firmware_clear(self):
        from particleve.common import Deferred

        if self.blocked == "firmware":
            raise Deferred("staged firmware")

    def check_storage(self, *, healthy):
        from particleve.common import Deferred

        if self.blocked == "disk":
            raise Deferred("missing disk or rebuilding mirror")

    def check_resources(self, *, healthy):
        from particleve.common import Deferred

        if self.blocked == "memory":
            raise Deferred("insufficient physical memory headroom")

    def check_time(self, *, anchor=None):
        from particleve.common import Deferred

        self.event("time-recheck" if anchor else "time-check")
        if self.blocked == "time":
            raise Deferred("authenticated time unavailable")
        return {"wall": 1793935800.0, "boottime": 100.0}

    def release(self, version=None):
        return copy.deepcopy(self.releases[version or self.latest])

    def check_compatibility(self, current, manifest):
        from particleve.common import Deferred

        if self.blocked == "schema":
            raise Deferred("persistent state incompatible")

    def protect_current(self, current, candidate):
        self.event("protect")

    def verify_disk(self, role, manifest, *, boot):
        return self.disks.get(role) == manifest["version"] and (
            not boot or self.entries.get(role) == manifest["version"]
        )

    def transfer(self, role, manifest, current):
        self.event("transfer-" + role)
        self.disks[role] = manifest["version"]
        self.event("transferred-" + role)

    def expose_boot(self, role, manifest):
        assert self.disks == {"a": manifest["version"], "b": manifest["version"]}
        self.event("expose-" + role)
        self.entries[role] = manifest["version"]
        self.event("exposed-" + role)

    def prove_fallback(self, current):
        self.event("fallback")

    def select(self, version):
        self.event("select")

    def conditional_reboot(self, version):
        self.event("reboot")
        return True

    def reject(self, version, current):
        self.event("reject-" + version)
        self.entries = {k: v for k, v in self.entries.items() if v != version}

    def health(self):
        self.event("health")

    def check_runtime_state(self):
        self.event("daemon-state")

    def accept(self, version):
        self.event("accept-" + version)

    def bless_current(self):
        self.event("bless")
        return {"boot_blessed": self.current}

    def cleanup_cache(self):
        self.event("cleanup")

    def freeze_vms(self):
        self.event("freeze-vms")

    def stop_vms(self):
        self.event("stop-vms")

    def assert_no_vms(self):
        self.event("no-vms")

    def restore_vms(self):
        self.event("restore-vms")
        return {"action": "restored"}

    def recover_vms(self):
        self.event("recover-vms")

    def mark_vm_reboot(self):
        self.event("mark-vm-reboot")
