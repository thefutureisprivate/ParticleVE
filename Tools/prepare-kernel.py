#!/usr/bin/python3
"""Generate and verify the native Fedora/secureblue OBS source recipe."""

import argparse
from pathlib import Path

from particleve.common import read_json
from particleve.kernelbuild import source_manifest, verify_sources
from Tools.kernel_source import generate, source_files, write_generated

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fedora", type=Path, default=Path("build/sources/fedora_kernel"))
parser.add_argument("--secureblue", type=Path, default=Path("build/sources/secureblue_kernel"))
parser.add_argument("--lock", type=Path, default=Path("sources.lock.json"))
parser.add_argument("--output", type=Path, default=Path(".obs/kernel"))
parser.add_argument("--verify-srpm-sources", type=Path)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
lock = read_json(args.lock)
if args.verify_srpm_sources:
    names = source_files(args.fedora, lock["sources"]["fedora_kernel"]["revision"])
    verify_sources(args.verify_srpm_sources, source_manifest(args.fedora, names))
files = generate(Path.cwd(), lock, args.fedora, args.secureblue)
write_generated(args.output, files, check=args.check)
print("Verified pinned Fedora/secureblue source inputs and generated OBS kernel recipe.")
