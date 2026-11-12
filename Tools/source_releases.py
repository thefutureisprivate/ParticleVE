#!/usr/bin/python3
"""Prepare source-version changelogs; publish them only with --publish."""

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

from particleve.common import atomic_write, require, run
from particleve.versioning import source_key
from Tools.trust import system_tls_environment


def git(root, *arguments, check=True, text=True):
    return run(["git", "-C", root, *arguments], check=check, text=text)


def github(repository, endpoint, body=None, *, method=None):
    arguments = ["gh", "api", "--hostname", "github.com", f"repos/{repository}/{endpoint}"]
    if method is not None:
        arguments.extend(["--method", method])
    if body is not None:
        arguments.extend(["--input", "-"])
    response = run(
        arguments,
        input=json.dumps(body) if body is not None else None,
        timeout=60,
        env=system_tls_environment() | {"GH_HOST": "github.com"},
    )
    require(len(response.stdout) <= 1024**2, "oversized release-reference response")
    return json.loads(response.stdout)


def ensure_tag(repository, release):
    """Create only a missing ref; never move an existing source-version tag."""
    reference = "refs/tags/" + release["tag"]
    matches = github(repository, "git/matching-refs/tags/" + release["tag"])
    exact = [item for item in matches if item["ref"] == reference]
    require(len(exact) <= 1, "ambiguous source-version tag")
    if exact:
        value = exact[0]["object"]
    else:
        value = github(repository, "git/refs", {"ref": reference, "sha": release["commit"]})["object"]
    for _ in range(5):
        require(re.fullmatch(r"[0-9a-f]{40}", value["sha"]), "invalid source-version tag object")
        if value["type"] == "commit":
            require(value["sha"] == release["commit"], "release tag points to another commit")
            return
        require(value["type"] == "tag", "source-version tag does not identify a commit")
        value = github(repository, "git/tags/" + value["sha"])["object"]
    require(False, "too many nested source-version tag objects")


def vendor_digest(archive, lock):
    require(archive.name == "vendor.tar.zst", "unexpected release vendor archive filename")
    require(archive.is_file() and not archive.is_symlink(), "vendor archive must be a regular file")
    require(0 < archive.stat().st_size <= 64 * 1024**2, "vendor archive exceeds its size limit")
    found = False
    total = 0
    with tarfile.open(archive, "r|zst", stream=True) as contents:
        for index, entry in enumerate(contents):
            total += entry.size
            require(
                index < 20000 and 0 <= entry.size <= 64 * 1024**2 and total <= 512 * 1024**2,
                "vendor archive expands beyond its size limit",
            )
            if entry.name == "Cargo.lock":
                require(
                    not found and entry.isfile() and entry.size <= 1024**2,
                    "vendor archive must contain exactly one bounded lockfile",
                )
                with contents.extractfile(entry) as source:
                    require(source.read() == lock, "vendor archive has another lockfile")
                found = True
    require(found, "vendor archive must contain exactly one bounded lockfile")
    with archive.open("rb") as source:
        return "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()


def release_inventory(repository):
    # Retain existing IDs for interrupted drafts. Newly created releases use
    # the creation response, without depending on immediate list visibility.
    response = run(
        [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "--paginate",
            f"repos/{repository}/releases",
            "--jq",
            ".[] | [.tag_name, (.id | tostring)] | @tsv",
        ],
        timeout=300,
        env=system_tls_environment() | {"GH_HOST": "github.com"},
    ).stdout
    require(len(response) <= 2 * 1024**2, "oversized source release inventory")
    releases = {}
    for line in response.splitlines():
        values = line.split("\t")
        require(
            len(values) == 2
            and re.fullmatch(r"v[0-9]+(?:\.[0-9]+){3}", values[0])
            and re.fullmatch(r"[1-9][0-9]{0,19}", values[1])
            and values[0] not in releases,
            "source release inventory is invalid or ambiguous",
        )
        releases[values[0]] = values[1]
    return releases


def publish_vendor(repository, release, archive, digest, identifier):
    require(re.fullmatch(r"[1-9][0-9]{0,19}", identifier), "invalid source release ID")
    endpoint = "releases/" + identifier

    def existing():
        info = github(repository, endpoint)
        require(info["tag_name"] == release["tag"], "source release ID identifies another tag")
        assets = info["assets"]
        matches = [asset for asset in assets if asset["name"] == "vendor.tar.zst"]
        require(len(matches) <= 1, "ambiguous release vendor archive")
        if matches:
            require(
                matches[0]["state"] == "uploaded" and matches[0]["digest"] == digest,
                "release vendor archive does not match the checked archive",
            )
        return info, bool(matches)

    info, present = existing()
    if not present:
        require(info["draft"], "vendor assets must be attached before publishing an immutable release")
        run(
            [
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "POST",
                f"https://uploads.github.com/repos/{repository}/{endpoint}/assets?name=vendor.tar.zst",
                "--header",
                "Content-Type: application/zstd",
                "--input",
                archive,
                "--silent",
            ],
            timeout=300,
            env=system_tls_environment() | {"GH_HOST": "github.com"},
        )
        info, present = existing()
        require(present, "release vendor archive upload is incomplete")
    if info["draft"]:
        github(repository, endpoint, {"draft": False, "make_latest": "true"}, method="PATCH")
        info, present = existing()
        require(present and not info["draft"], "source release publication is incomplete")


def release_plan(root, repository):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid GitHub repository")
    commits = git(root, "log", "--first-parent", "--reverse", "--format=%H", "--", "particleve.version")
    plan = []
    previous = None
    for commit in commits.stdout.splitlines():
        version = git(root, "show", f"{commit}:particleve.version").stdout.strip()
        require(len(version) <= 64, "source version is too large")
        key = source_key(version)
        if plan and version == plan[-1]["version"]:
            continue
        require(not plan or key > source_key(plan[-1]["version"]), "source versions must increase")
        if previous is None:
            pins = json.loads(git(root, "show", f"{commit}:sources.lock.json").stdout)
            previous = pins["sources"]["particleos"]["revision"]
            require(re.fullmatch(r"[0-9a-f]{40}", previous), "invalid upstream base")
            git(root, "merge-base", "--is-ancestor", previous, commit)
        changes = git(root, "log", "--reverse", "--format=%H%x09%s", f"{previous}..{commit}")
        notes = ["Source release. Signed images append their OBS check-in and build counters.", ""]
        for line in changes.stdout.splitlines():
            revision, subject = line.split("\t", 1)
            subject = re.sub(r"([\\`*_{}\[\]<>])", r"\\\1", subject)
            notes.append(f"- [{revision[:12]}](https://github.com/{repository}/commit/{revision}) {subject}")
        start = "v" + plan[-1]["version"] if plan else previous
        notes.extend(
            ["", f"[Full changelog](https://github.com/{repository}/compare/{start}...v{version})", ""]
        )
        plan.append({"version": version, "tag": "v" + version, "commit": commit, "notes": "\n".join(notes)})
        previous = commit
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, default=Path("build/source-releases"))
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--vendor-archive", type=Path, help="locked archive for the latest source release")
    args = parser.parse_args()
    require(
        not args.publish or args.vendor_archive is not None, "source publication requires --vendor-archive"
    )
    root = Path.cwd()
    plan = release_plan(root, args.repository)
    digest = None
    if args.vendor_archive:
        require(bool(plan), "vendor publication needs a source release")
        lock = git(root, "show", f"{plan[-1]['commit']}:Cargo.lock", text=False).stdout
        digest = vendor_digest(args.vendor_archive, lock)
    args.output.mkdir(parents=True, exist_ok=True)
    existing = release_inventory(args.repository) if args.publish else {}
    for index, release in enumerate(plan):
        notes = args.output / (release["tag"] + ".md")
        atomic_write(notes, release["notes"].encode(), 0o644)
        if not args.publish or release["tag"] in existing:
            continue
        tag = git(
            root, "rev-parse", "--verify", "--quiet", f"refs/tags/{release['tag']}^{{commit}}", check=False
        )
        require(
            tag.returncode != 0 or tag.stdout.strip() == release["commit"],
            "release tag points to another commit",
        )
        # Authorize and verify the immutable Git ref separately. Resending a
        # historical target_commitish to the Releases API invokes its workflow
        # permission check even though an existing tag already selects the
        # release's contents. Keep release publication scoped to that ref.
        ensure_tag(args.repository, release)
        draft = bool(args.vendor_archive and index == len(plan) - 1)
        created = github(
            args.repository,
            "releases",
            {
                "tag_name": release["tag"],
                "name": "ParticleVE " + release["version"],
                "body": release["notes"],
                "draft": draft,
                "make_latest": "false",
            },
        )
        require(
            type(created.get("id")) is int
            and 0 < created["id"] < 10**20
            and created.get("tag_name") == release["tag"]
            and created.get("draft") is draft,
            "source release creation returned an invalid identity",
        )
        existing[release["tag"]] = str(created["id"])
    if args.publish and args.vendor_archive:
        ensure_tag(args.repository, plan[-1])
        publish_vendor(args.repository, plan[-1], args.vendor_archive, digest, existing[plan[-1]["tag"]])
    atomic_write(args.output / "releases.json", (json.dumps(plan, indent=2) + "\n").encode(), 0o644)
    print(json.dumps({"source_versions": [item["version"] for item in plan], "published": args.publish}))


if __name__ == "__main__":
    main()
