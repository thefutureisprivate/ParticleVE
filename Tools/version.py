#!/usr/bin/python3
"""Advance PVE versions and verify all generated version declarations."""

import argparse
import json
import re
import tomllib
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import atomic_write, read_json, require
from particleve.versioning import OBS_RECIPE, bump, read_version, source_key

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("command", choices=("check", "sync", "patch", "minor", "major", "fedora"))
parser.add_argument("--fedora", type=int)
parser.add_argument(
    "--owner-approved", action="store_true", help="PVE major increase explicitly approved by the owner"
)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
version = read_version(root)
if args.command not in ("check", "sync"):
    version = bump(version, args.command, owner_approved=args.owner_approved, fedora=args.fedora)
files = {}
cargo_version = ".".join(map(str, source_key(version)[1:]))
for name, pattern, replacement in (
    ("mkosi.conf", r"^ImageVersion=.*$", f"ImageVersion={version}-0.0"),
    (str(OBS_RECIPE), r"^Version:.*$", f"Version:        {version}"),
    ("pyproject.toml", r'^version = ".*"$', f'version = "{version}"'),
    ("Cargo.toml", r'^version = ".*"$', f'version = "{cargo_version}"'),
    (
        "Cargo.lock",
        r'^(\[\[package\]\]\nname = "particleve"\nversion = ")[^"]+("$)',
        rf"\g<1>{cargo_version}\g<2>",
    ),
):
    path = root / name
    content, count = re.subn(pattern, replacement, path.read_text(), flags=re.M)
    require(count == 1, f"expected exactly one version declaration in {name}")
    files[path] = content.encode()
service = ET.parse(root / ".obs/particleve/_service")
for name, value in {
    "versionformat": "@PARENT_TAG@",
    "match-tag": "v[0-9]*.[0-9]*.[0-9]*.[0-9]*",
    "versionrewrite-pattern": "v(.*)",
    "versionrewrite-replacement": r"\1",
}.items():
    fields = service.findall(f"./service[@name='obs_scm']/param[@name='{name}']")
    require(len(fields) == 1 and fields[0].text == value, "OBS must derive versions from source tags")
if args.command == "check":
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain), "pin a stable Rust toolchain release")
    cargo = tomllib.loads((root / "Cargo.toml").read_text())
    require(
        cargo["package"]["rust-version"] == toolchain.rsplit(".", 1)[0],
        "Rust language baseline differs from the pinned toolchain",
    )
    recipe = (root / OBS_RECIPE).read_text()
    for package in ("cargo", "rust", "rustfmt", "clippy"):
        require(
            re.findall(rf"^BuildRequires:\s+{package}\s+=\s+(\S+)\s*$", recipe, re.M) == [toolchain],
            f"pin the native {package} build requirement to the Rust toolchain",
        )
    require(
        str(source_key(version)[0]) == read_json(root / "sources.lock.json")["fedora"],
        "version and Fedora lock differ",
    )
    for path, content in files.items():
        require(
            path.read_bytes() == content,
            f"stale version declaration: {path.relative_to(root)}; run Tools/version.py sync",
        )
else:
    for path, content in files.items():
        atomic_write(path, content, 0o644)
    atomic_write(root / "particleve.version", (version + "\n").encode(), 0o644)
print(json.dumps({"source_version": version}))
