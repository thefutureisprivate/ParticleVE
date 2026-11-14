"""Prepare the production allocator RPM's authenticated sources in a fresh directory."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from particleve.common import read_json, require
from Tools.allocator_source import check
from Tools.publication import request
from Tools.sourcegit import environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    pin = read_json(root / "sources.lock.json")["sources"]["hardened_malloc"]
    output = args.output.resolve()
    require(not output.exists(), "allocator source output must be fresh")
    with tempfile.TemporaryDirectory(prefix="particleve-allocator-fetch-") as temporary:
        source = Path(temporary)
        subprocess.run(
            ["/usr/bin/git", "init", "--quiet", str(source)], check=True, env=environment(), timeout=15
        )
        check(source, pin, root)
        archive = request(
            pin["url"].removesuffix(".git") + "/archive/" + pin["revision"] + ".tar.gz",
            size_limit=4 * 1024**2,
        )
        require(
            hashlib.sha256(archive).hexdigest() == pin["archive_sha256"],
            "allocator source archive checksum mismatch",
        )
    output.mkdir(mode=0o755, parents=True)
    (output / (pin["revision"] + ".tar.gz")).write_bytes(archive)
    for name, destination in (
        (".obs/particleve/allocator.spec", "allocator.spec"),
        (".obs/particleve/allocator.spec", "hardened_malloc.recipe"),
        ("sources.lock.json", "sources.lock.json"),
        ("Sources/particleve/package_sources.py", "package_sources.py"),
        (".obs/particleve/hardened_malloc.allowed_signers", "hardened_malloc.allowed_signers"),
        (
            ".obs/particleve/hardened_malloc-chacha-output-pointer.patch",
            "hardened_malloc-chacha-output-pointer.patch",
        ),
        ("Tests/acceptance/allocator/chacha-boundaries.c", "chacha-boundaries.c"),
    ):
        shutil.copy2(root / name, output / destination)
    print(json.dumps({"version": pin["version"], "revision": pin["revision"], "signed_tag": "verified"}))


if __name__ == "__main__":
    main()
