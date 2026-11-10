#!/usr/bin/python3
"""Fetch only the immutable public inputs in sources.lock.json."""

import argparse
from pathlib import Path

from particleve.common import read_json, require
from Tools.sourcegit import fetch, git

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--output", type=Path, default=Path("build/sources"))
args = p.parse_args()
pins = read_json("sources.lock.json")["sources"]
args.output.mkdir(parents=True, exist_ok=True)
for name, pin in pins.items():
    if name == "particleos":
        continue  # This checkout is the fork; the base revision is provenance, not a second build tree.
    directory = args.output / name
    if not directory.exists():
        directory.mkdir()
        git(directory, "init", "--quiet", "--initial-branch=source")
        git(directory, "remote", "add", "origin", pin["url"])
        fetch(directory, pin["url"], pin["revision"])
        git(directory, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    actual = git(directory, "rev-parse", "HEAD").stdout.strip()
    require(actual == pin["revision"], f"{name}: source pin differs")
    require(
        not git(directory, "status", "--porcelain").stdout,
        f"{name}: checkout is dirty",
    )
    print(f"{name}: {actual}")
