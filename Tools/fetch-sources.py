#!/usr/bin/python3
"""Fetch only the immutable public inputs in sources.lock.json."""

import argparse
import re
import tempfile
from pathlib import Path

from particleve.common import read_json, require
from Tools.sourcegit import fetch, git

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--output", type=Path, default=Path("build/sources"))
args = p.parse_args()
pins = read_json("sources.lock.json")["sources"]
args.output.mkdir(parents=True, exist_ok=True)
for name, pin in pins.items():
    require(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name), "invalid source checkout name")
    if name == "particleos":
        continue  # This checkout is the fork; the base revision is provenance, not a second build tree.
    directory = args.output / name
    if not directory.exists():
        # A failed transfer must not expose a partially initialized checkout as
        # a reusable source. The final name appears only after pin validation.
        with tempfile.TemporaryDirectory(prefix=f".{name}-", dir=args.output) as temporary:
            staged = Path(temporary) / "source"
            staged.mkdir()
            git(staged, "init", "--quiet", "--initial-branch=source")
            git(staged, "remote", "add", "origin", pin["url"])
            fetch(staged, pin["url"], pin["revision"], branch=pin.get("branch"))
            git(staged, "checkout", "--quiet", "--detach", pin["revision"])
            require(git(staged, "rev-parse", "HEAD").stdout.strip() == pin["revision"], "source pin differs")
            staged.rename(directory)
    actual = git(directory, "rev-parse", "HEAD").stdout.strip()
    require(actual == pin["revision"], f"{name}: source pin differs")
    require(
        not git(directory, "status", "--porcelain").stdout,
        f"{name}: checkout is dirty",
    )
    print(f"{name}: {actual}")
