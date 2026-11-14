"""Authenticate and refresh the allocator's immutable source coordinates."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from particleve.common import read_json, require, write_json
from Tools.publication import request
from Tools.sourcegit import fetch, git


def verify(source, pin, root):
    require(
        pin["url"] == "https://github.com/GrapheneOS/hardened_malloc.git", "unexpected allocator upstream"
    )
    require(re.fullmatch(r"[0-9]{10}", pin["version"]), "invalid allocator release tag")
    fetch(source, pin["url"], "refs/tags/" + pin["version"])
    tag = git(source, "rev-parse", "FETCH_HEAD").stdout.strip()
    commit = git(source, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
    signature = git(
        source,
        "-c",
        "gpg.ssh.allowedSignersFile=" + str(root / ".obs/particleve/hardened_malloc.allowed_signers"),
        "verify-tag",
        tag,
    )
    require(
        pin["signer"] in signature.stderr and pin["signer_fingerprint"] in signature.stderr,
        "allocator release signer differs from its trusted identity",
    )
    return tag, commit, int(git(source, "show", "-s", "--format=%ct", commit).stdout)


def check(source, pin, root):
    tag, commit, epoch = verify(source, pin, root)
    require(
        (tag, commit, epoch) == (pin["tag_object"], pin["revision"], pin["source_epoch"]),
        "allocator release metadata differs from its source lock",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=Path("build/sources/hardened_malloc"))
    parser.add_argument("--refresh", action="store_true", help="refresh reviewed tag provenance and recipe")
    args = parser.parse_args()
    root = Path.cwd()
    lock = read_json(root / "sources.lock.json")
    pin = lock["sources"]["hardened_malloc"]
    if not args.refresh:
        check(args.sources, pin, root)
        print(json.dumps({"allocator": "verified", "revision": pin["revision"]}))
        return
    tag, commit, epoch = verify(args.sources, pin, root)
    archive = request(
        pin["url"].removesuffix(".git") + "/archive/" + commit + ".tar.gz", size_limit=4 * 1024**2
    )
    pin.update(
        tag_object=tag,
        revision=commit,
        source_epoch=epoch,
        archive_sha256=hashlib.sha256(archive).hexdigest(),
    )
    recipe = root / ".obs/particleve/allocator.spec"
    text = recipe.read_text()
    text, count = re.subn(
        r"(?m)^%global upstream_commit [a-f0-9]{40}$", "%global upstream_commit " + commit, text
    )
    require(count == 1, "allocator recipe commit is missing or ambiguous")
    text, count = re.subn(r"(?m)^Version:\s+\S+$", "Version:        " + pin["version"], text)
    require(count == 1, "allocator recipe version is missing or ambiguous")
    write_json(root / "sources.lock.json", lock)
    recipe.write_text(text)
    print(
        json.dumps({"allocator": "refreshed; review changes", "revision": commit, "version": pin["version"]})
    )


if __name__ == "__main__":
    main()
