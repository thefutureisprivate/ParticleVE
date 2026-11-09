#!/usr/bin/python3
"""Advance PVE versions and verify all generated version declarations."""

import argparse
import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import atomic_write, read_json, require
from particleve.versioning import bump, read_version, source_key

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
for name, pattern, replacement in (
    ("mkosi.conf", r"^ImageVersion=.*$", f"ImageVersion={version}-0.0"),
    (".obs/particleve/particleve.spec", r"^Version:.*$", f"Version:        {version}"),
    ("pyproject.toml", r'^version = ".*"$', f'version = "{version}"'),
):
    path = root / name
    content, count = re.subn(pattern, replacement, path.read_text(), flags=re.M)
    require(count == 1, f"expected exactly one version declaration in {name}")
    files[path] = content.encode()
path = root / ".obs/particleve/_service"
service = ET.fromstring(path.read_bytes())
fields = service.findall("./service[@name='obs_scm']/param[@name='versionformat']")
require(len(fields) == 1, "the unified source service needs one version format")
fields[0].text = version
ET.indent(service)
files[path] = ET.tostring(service) + b"\n"
if args.command == "check":
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
