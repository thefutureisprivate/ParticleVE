"""Reviewed first-party files required in the final early-boot archive."""

import stat
from pathlib import Path

from .common import hash_file, require

OVERLAY = "mkosi.initrd.conf/mkosi.extra"
SHARED = (
    "usr/lib/particleve/ld.so.preload",
    "usr/lib/udev/rules.d/61-particleve-boot-disk.rules",
    "usr/lib/systemd/coredump.conf.d/60-particleve.conf",
    "usr/lib/systemd/system.conf.d/60-particleve-memory.conf",
    "usr/lib/systemd/user.conf.d/60-particleve-memory.conf",
    "usr/lib/sysctl.d/60-particleve-memory.conf",
    "usr/lib/sysctl.d/60-particleve-kernel.conf",
    "usr/lib/udev/rules.d/71-particleve-kernel.rules",
    "usr/lib/modules-load.d/60-particleve-radio.conf",
    "usr/lib/udev/rules.d/71-particleve-radio.rules",
)


def inputs(source):
    source = Path(source)
    return sorted(
        [p for p in (source / OVERLAY).rglob("*") if p.is_symlink() or p.is_file()]
        + [source / "mkosi.extra" / name for name in SHARED]
    )


def policy(source):
    source = Path(source)
    files = {}
    for path in inputs(source):
        relative = (
            path.relative_to(source / OVERLAY)
            if path.is_relative_to(source / OVERLAY)
            else path.relative_to(source / "mkosi.extra")
        )
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            item = {"kind": "symlink", "target": str(path.readlink())}
        else:
            require(stat.S_ISREG(metadata.st_mode), "initrd policy requires regular source files or links")
            item = {
                "kind": "file",
                "mode": 0o755 if metadata.st_mode & 0o111 else 0o644,
                "size": metadata.st_size,
                "sha256": hash_file(path),
            }
        files[relative.as_posix()] = item
    files["etc/systemd/system/initrd.target.wants/particleve-initrd-watchdog.timer"] = {
        "kind": "symlink",
        "target": "/usr/lib/systemd/system/particleve-initrd-watchdog.timer",
    }
    files["lib"] = {"kind": "symlink", "target": "usr/lib"}
    return {"schema": 1, "files": files}
