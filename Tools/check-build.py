#!/usr/bin/python3
"""Validate resolved mkosi configuration or actual image packages."""

import argparse
import json
from pathlib import Path

from particleve.buildcheck import root_check, source_revision, summary_check
from particleve.common import read_json, write_json

parser = argparse.ArgumentParser(description=__doc__)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--summary", type=Path)
group.add_argument("--root", type=Path)
parser.add_argument("--tree", choices=("usr", "initrd", "tools"), default="usr")
parser.add_argument("--output", type=Path)
parser.add_argument("--source-dir", type=Path)
args = parser.parse_args()
if args.summary:
    summary_check(read_json(args.summary))
else:
    if args.source_dir and args.tree == "usr":
        build_file = args.root / "usr/lib/particleve/build.json"
        build = read_json(build_file)
        source_name, revision = source_revision(args.source_dir)
        build["sources"][source_name] = revision
        write_json(build_file, build)
    root_check(args.root.resolve(), tree=args.tree, output=args.output, source_dir=args.source_dir)
print(json.dumps({"verification": "passed"}))
