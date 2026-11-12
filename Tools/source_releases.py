#!/usr/bin/python3
"""Prepare source-version changelogs; publish them only with --publish."""

import argparse
import json
import re
from pathlib import Path

from particleve.common import atomic_write, require, run
from particleve.versioning import source_key
from Tools.trust import system_tls_environment


def git(root, *arguments, check=True):
    return run(["git", "-C", root, *arguments], check=check)


def github(repository, endpoint, body=None):
    arguments = ["gh", "api", "--hostname", "github.com", f"repos/{repository}/{endpoint}"]
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
    args = parser.parse_args()
    root = Path.cwd()
    plan = release_plan(root, args.repository)
    args.output.mkdir(parents=True, exist_ok=True)
    existing = set()
    if args.publish:
        existing = set(
            run(
                [
                    "gh",
                    "api",
                    "--hostname",
                    "github.com",
                    "--paginate",
                    f"repos/{args.repository}/releases",
                    "--jq",
                    ".[] | select(.draft == false) | .tag_name",
                ],
                timeout=300,
                env=system_tls_environment() | {"GH_HOST": "github.com"},
            ).stdout.splitlines()
        )
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
        run(
            [
                "gh",
                "release",
                "create",
                release["tag"],
                "--repo",
                "github.com/" + args.repository,
                "--verify-tag",
                "--title",
                "ParticleVE " + release["version"],
                "--notes-file",
                notes,
                "--latest=" + ("true" if index == len(plan) - 1 else "false"),
            ],
            timeout=120,
            env=system_tls_environment() | {"GH_HOST": "github.com"},
        )
    atomic_write(args.output / "releases.json", (json.dumps(plan, indent=2) + "\n").encode(), 0o644)
    print(json.dumps({"source_versions": [item["version"] for item in plan], "published": args.publish}))


if __name__ == "__main__":
    main()
