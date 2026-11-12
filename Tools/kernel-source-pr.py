#!/usr/bin/python3
"""Prepare or publish only the generated files of a validated Renovate kernel PR."""

import argparse
import json
from pathlib import Path

from Tools.kernel_source import regular
from Tools.kernel_updates import prepare, publish

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--event", type=Path, required=True)
parser.add_argument("--repository", required=True)
parser.add_argument("--output", type=Path, default=Path("build/kernel-pr"))
parser.add_argument("--publish", action="store_true")
args = parser.parse_args()
event = json.loads(regular(args.event, 2 * 1024**2))
if args.publish:
    plan = json.loads(regular(args.output / "plan.json", 64 * 1024**2))
    head = publish(Path.cwd(), event, args.repository, plan)
    print(json.dumps({"published_commit": head}))
else:
    plan = prepare(Path.cwd(), event, args.repository, args.output)
    print(json.dumps({"prepared_files": sorted(plan["files"]), "head": plan["head"]}))
