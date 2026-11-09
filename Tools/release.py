#!/usr/bin/python3
"""Assemble a local release for review; native OBS builds invoke the final signing hook."""

import argparse
from pathlib import Path

from particleve.buildartifacts import assemble
from particleve.common import read_json, require, write_json

parser = argparse.ArgumentParser(description=__doc__)
for flag in ("artifacts", "bootloader", "fwupd-efi", "verification", "output"):
    parser.add_argument("--" + flag, type=Path, required=True)
parser.add_argument("--version", required=True)
parser.add_argument("--root-hash", required=True)
args = parser.parse_args()
require(not args.output.exists(), "release output must be fresh")
args.output.mkdir(parents=True)
manifest = assemble(
    args.artifacts,
    args.version,
    args.root_hash,
    args.bootloader,
    args.fwupd_efi,
    read_json(args.verification),
    {name: pin["revision"] for name, pin in read_json("sources.lock.json")["sources"].items()},
    args.output,
)
write_json(args.output / f"ParticleVE_{args.version}_x86-64.release.json", manifest)
print(args.output.resolve())
