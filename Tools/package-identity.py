#!/usr/bin/python3
"""Record source and installed-payload identity during the RPM build."""

import argparse
from pathlib import Path

from particleve.provenance import record_package

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--source", type=Path, default=Path.cwd())
parser.add_argument("--component", choices=("integration", "build-tools"), required=True)
args = parser.parse_args()
record_package(args.root, args.source, args.component)
