#!/usr/bin/python3
"""Prepare native OBS sources from an exact reviewed Git tree, without signing or publishing it."""

import argparse
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from particleve.common import atomic_write, require, run
from particleve.versioning import OBS_RECIPE, source_key

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--tree", required=True, help="exact Git commit or tree object")
p.add_argument("--output", type=Path, default=Path("build/obs-packages"))
p.add_argument("--cargo", default="cargo", help="Cargo from the pinned Rust toolchain")
args = p.parse_args()
tree = run(["git", "rev-parse", f"{args.tree}^{{tree}}"]).stdout.strip()
archive = subprocess.run(
    ["git", "archive", "--format=tar", "--mtime=1970-01-01T00:00:00Z", tree],
    capture_output=True,
    check=True,
).stdout
package = args.output / "particleve"
require(not package.exists(), f"output must be fresh: {package}")
package.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(archive)) as source:
    raw_version = source.extractfile("particleve.version").read(65)
    require(len(raw_version) <= 64, "source version file is too large")
    version = raw_version.decode().strip()
    source_key(version)
    for name, destination in (
        (".obs/fedora/x86-64/mkosi.conf", package / "mkosi.conf"),
        (str(OBS_RECIPE), package / OBS_RECIPE.name),
        (".obs/particleve/_multibuild", package / "_multibuild"),
    ):
        atomic_write(destination, source.extractfile(name).read(), 0o644)
    with tarfile.open(package / f"particleve-{version}.tar.xz", "w:xz") as output:
        for member in source.getmembers():
            content = source.extractfile(member) if member.isfile() else None
            member.name = f"particleve-{version}/" + member.name
            if member.isdir() or member.isfile():
                member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            output.addfile(member, content)
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    root = directory / f"particleve-{version}"
    root.mkdir()
    # Git does not track directory modes. A private caller umask must not turn
    # public /usr overlay directories into root-only daemon configuration.
    root.chmod(0o755)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source.getmembers():
            relative = Path(member.name)
            require(not relative.is_absolute() and ".." not in relative.parts, "unsafe source archive")
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
                target.chmod(0o755)
            elif member.issym():
                target.symlink_to(member.linkname)
            else:
                require(member.isfile(), "unexpected Git archive entry")
                with source.extractfile(member) as content, target.open("wb") as output:
                    shutil.copyfileobj(content, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    paths = sorted((f"particleve-{version}", *(str(path.relative_to(directory)) for path in root.rglob("*"))))
    with (package / "particleve.obscpio").open("wb") as output:
        subprocess.run(
            ["cpio", "--create", "--format=newc", "--null", "--quiet", "--reproducible"],
            input=b"\0".join(os.fsencode(path) for path in paths) + b"\0",
            cwd=directory,
            stdout=output,
            check=True,
        )
    original_lock = (root / "Cargo.lock").read_bytes()
    vendor = subprocess.run(
        [args.cargo, "vendor", "--locked", "--versioned-dirs", "vendor"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    require((root / "Cargo.lock").read_bytes() == original_lock, "Cargo changed the source lock")
    (root / ".cargo").mkdir(exist_ok=True)
    atomic_write(root / ".cargo/config", vendor.stdout, 0o644)
    with tarfile.open(package / "vendor.tar.zst", "w:zst") as output:
        paths = [root / ".cargo/config", root / "Cargo.lock", *sorted((root / "vendor").rglob("*"))]
        for path in paths:
            member = output.gettarinfo(path, arcname=path.relative_to(root).as_posix())
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            if member.isfile():
                with path.open("rb") as content:
                    output.addfile(member, content)
            else:
                output.addfile(member)
atomic_write(
    package / "particleve.obsinfo",
    f"name: particleve\nversion: {version}\nmtime: 0\ntree: {tree}\n".encode(),
    0o644,
)
print(f"Prepared exact Git tree {tree}; automatic obs_scm follows the checked build ref.")
