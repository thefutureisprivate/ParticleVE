"""Check boot-critical drivers in final artifacts, after mkosi module filtering."""

from pathlib import Path

from .common import require

REQUIRED_MODULES = {
    "ahci",
    "btrfs",
    "dm_crypt",
    "dm_mod",
    "dm_verity",
    "erofs",
    "kvm_amd",
    "kvm_intel",
    "nvme",
    "rfkill",
    "sd_mod",
    "virtio_blk",
    "virtio_pci",
}


def verify_modules(directory):
    versions = [p for p in Path(directory).iterdir() if p.is_dir()]
    require(len(versions) == 1, "final image must contain exactly one kernel module tree")
    tree = versions[0]
    builtin = tree / "modules.builtin"
    require(builtin.is_file(), "kernel built-in module metadata is missing")
    files = [
        p.name
        for p in tree.rglob("*.ko*")
        if p.is_file() and p.name.endswith((".ko", ".ko.xz", ".ko.zst", ".ko.gz"))
    ]
    names = {
        Path(name).name.split(".ko", 1)[0].replace("-", "_")
        for name in files + builtin.read_text().splitlines()
    }
    require(
        not (missing := REQUIRED_MODULES - names),
        "final image is missing required drivers: " + ", ".join(sorted(missing)),
    )
    return {"kernel": tree.name, "module_files": len(files), "required_drivers": sorted(REQUIRED_MODULES)}
