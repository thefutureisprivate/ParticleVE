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
args = p.parse_args()
tree = run(["git", "rev-parse", f"{args.tree}^{{tree}}"]).stdout.strip()
archive = subprocess.run(["git", "archive", "--format=tar", tree], capture_output=True, check=True).stdout
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
            output.addfile(member, content)
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    root = directory / f"particleve-{version}"
    root.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source.getmembers():
            relative = Path(member.name)
            require(not relative.is_absolute() and ".." not in relative.parts, "unsafe source archive")
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
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
atomic_write(
    package / "particleve.obsinfo",
    f"name: particleve\nversion: {version}\ntree: {tree}\n".encode(),
    0o644,
)
print(f"Prepared exact Git tree {tree}; automatic obs_scm follows the checked build ref.")
