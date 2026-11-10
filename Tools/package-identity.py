#!/usr/bin/python3
"""Record source and installed-payload identity during the RPM build."""

import argparse
from pathlib import Path

from particleve.provenance import record_package
from particleve.versioning import verify_obs_sources

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--source", type=Path, default=Path.cwd())
parser.add_argument("--obs-sources", type=Path, help="OBS source directory containing the native recipe")
parser.add_argument("--component", choices=("integration", "initrd", "build-tools"), required=True)
args = parser.parse_args()
if args.obs_sources is not None:
    verify_obs_sources(args.obs_sources, args.source, rpm=True)
record_package(args.root, args.source, args.component)
