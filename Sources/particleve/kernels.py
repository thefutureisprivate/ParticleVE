"""Check boot-critical drivers in final artifacts, after mkosi module filtering."""

import re
from pathlib import Path

from .common import Error, digest, hash_file, require
from .kernelpayload import RECORD, kernel_tree, verify

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

KERNEL_PACKAGES = {"kernel-core", "kernel-modules-core", "kernel-modules", "kernel-modules-extra"}


def verify_kernel(root, source, certificate):
    """Bind the image's selected subset to the signed, complete kernel build."""
    modules = Path(root) / "usr/lib/modules"
    try:
        value = verify(modules, source, certificate, filtered=True)
        tree = kernel_tree(modules)
        require(
            tree.name.startswith(source["fedora_version"]["specrpmversion"] + "-")
            and tree.name.endswith(".x86_64"),
            "selected kernel release differs from the reviewed Fedora source",
        )
        drivers = verify_modules(modules)
        return {
            **drivers,
            "source_sha256": digest(source),
            "record_sha256": hash_file(tree / RECORD),
            "config_sha256": value["metadata"]["config"],
            "kernel_pe_sha256": hash_file(tree / "vmlinuz"),
            "signing_certificate_sha256": value["signing_certificate_sha256"],
            "built_module_files": len(value["modules"]),
        }
    except (OSError, ValueError, KeyError) as exc:
        raise Error(f"selected kernel payload verification failed: {exc}") from exc


def verify_kernel_packages(rows, kernel):
    """Require one matching set; retain actual origins, including local fixtures."""
    selected = [row for row in rows if row[0].startswith("kernel")]
    require(
        {row[0] for row in selected} == KERNEL_PACKAGES
        and len(selected) == len(KERNEL_PACKAGES)
        and re.fullmatch(r"[A-Za-z0-9_+.-]+\.x86_64", kernel)
        and {row[1] for row in selected} == {kernel.removesuffix(".x86_64")},
        "selected kernel RPMs differ from the verified kernel and module build",
    )
    return [
        {"name": name, "evr": evr, "vendor": vendor, "origin": origin}
        for name, evr, vendor, origin in sorted(selected)
    ]


def verify_modules(directory, *, required=None):
    required = REQUIRED_MODULES if required is None else required
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
        not (missing := required - names),
        "final image is missing required drivers: " + ", ".join(sorted(missing)),
    )
    return {"kernel": tree.name, "module_files": len(files), "required_drivers": sorted(required)}
