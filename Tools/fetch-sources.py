#!/usr/bin/python3
"""Fetch only the immutable public inputs in sources.lock.json."""

import argparse
import subprocess
from pathlib import Path

from particleve.common import read_json, require

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
        subprocess.run(["git", "init", str(directory)], check=True)
        subprocess.run(["git", "-C", str(directory), "remote", "add", "origin", pin["url"]], check=True)
        subprocess.run(
            ["git", "-C", str(directory), "fetch", "--depth=1", "origin", pin["revision"]], check=True
        )
        subprocess.run(["git", "-C", str(directory), "checkout", "--detach", "FETCH_HEAD"], check=True)
    actual = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
    require(actual == pin["revision"], f"{name}: source pin differs")
    require(
        not subprocess.check_output(["git", "-C", str(directory), "status", "--porcelain"], text=True),
        f"{name}: checkout is dirty",
    )
    print(f"{name}: {actual}")
