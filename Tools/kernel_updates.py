"""Prepare narrowly scoped Renovate kernel updates from trusted base code.

Never check out candidate code or execute an upstream recipe with repository
write authority. The PR contributes a published Fedora version and secureblue
revision; trusted base code resolves and verifies Fedora's immutable source pin
and supplies the generator, policy, certificate bundle and tools.
"""

import base64
import copy
import json
import re
import tempfile
from pathlib import Path

from particleve.common import atomic_write, canonical, require, run
from Tools import fedora_kernel
from Tools.kernel_source import GENERATED, generate, pins
from Tools.sourcegit import fetch, git
from Tools.trust import system_tls_environment

LOCK = "sources.lock.json"
BUILD_METADATA = "mkosi.extra/usr/lib/particleve/build.json"
KERNEL_INPUTS = ".obs/kernel/kernel.inputs.json"
OUTPUTS = (*(".obs/kernel/" + name for name in GENERATED), BUILD_METADATA)
ALLOWED = {LOCK, *OUTPUTS}
SOURCES = ("fedora_kernel", "secureblue_kernel")


def oid(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{40}", value), "invalid Git commit identity")
    return value


def context(event, repository):
    require(re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository), "invalid GitHub repository")
    pr = event["pull_request"]
    require(
        event["action"] in ("opened", "synchronize", "reopened")
        and event["sender"]["login"] == "renovate[bot]"
        and event["sender"]["type"] == "Bot"
        and pr["user"]["login"] == "renovate[bot]"
        and pr["user"]["type"] == "Bot"
        and pr["state"] == "open"
        and event["repository"]["full_name"] == repository
        and pr["head"]["repo"]["full_name"] == repository
        and pr["base"]["repo"]["full_name"] == repository
        and pr["base"]["ref"] == "main",
        "kernel preparation requires an open, same-repository Renovate PR targeting main",
    )
    branch = pr["head"]["ref"]
    require(
        isinstance(branch, str)
        and re.fullmatch(r"renovate/[A-Za-z0-9_./-]{1,160}", branch)
        and not any(part in ("", ".", "..") or part.endswith(".lock") for part in branch.split("/"))
        and ".." not in branch,
        "invalid Renovate branch",
    )
    require(type(pr["number"]) is int and pr["number"] > 0, "invalid pull request number")
    require(
        type(pr["changed_files"]) is int and 1 <= pr["changed_files"] <= len(ALLOWED),
        "kernel PR changes too many files",
    )
    return {
        "repository": repository,
        "pull_request": pr["number"],
        "branch": branch,
        "base": oid(pr["base"]["sha"]),
        "head": oid(pr["head"]["sha"]),
    }


def locked_update(base, candidate, *, allow_unchanged=False):
    pins(base)
    pins(candidate)
    expected = copy.deepcopy(base)
    for name in SOURCES:
        expected["sources"][name]["revision"] = candidate["sources"][name]["revision"]
    require(candidate == expected, "kernel update may change only the two reviewed source revisions")
    require(allow_unchanged or candidate != base, "kernel source revisions did not change")
    return candidate


def build_metadata(base, updated, metadata):
    require(
        metadata.get("schema") == 1
        and metadata.get("sources") == {name: pin["revision"] for name, pin in base["sources"].items()},
        "trusted image source metadata differs from the base source lock",
    )
    value = copy.deepcopy(metadata)
    value["sources"] = {name: pin["revision"] for name, pin in updated["sources"].items()}
    return canonical(value).decode()


def blob(root, commit, path, maximum=65536):
    entry = git(root, "ls-tree", commit, "--", path).stdout.strip().split()
    require(
        len(entry) == 4 and entry[:2] == ["100644", "blob"] and entry[3] == path,
        "kernel update requires regular non-executable files",
    )
    size = git(root, "cat-file", "-s", entry[2]).stdout.strip()
    require(size.isdecimal() and 0 < int(size) <= maximum, "oversized kernel update input")
    return git(root, "show", f"{commit}:{path}", text=False).stdout.decode("utf-8")


def candidate(root, selected):
    require(
        git(root, "rev-parse", "HEAD").stdout.strip() == selected["base"],
        "kernel generator must run from the exact trusted PR base",
    )
    url = f"https://github.com/{selected['repository']}.git"
    git(root, "fetch", "--no-tags", "--depth=64", url, selected["head"], remote=url)
    git(root, "merge-base", "--is-ancestor", selected["base"], selected["head"])
    changes = git(
        root, "diff", "--name-only", "--no-renames", "-z", selected["base"], selected["head"]
    ).stdout
    paths = {path for path in changes.split("\0") if path}
    require(paths & {LOCK, KERNEL_INPUTS} and paths <= ALLOWED, "kernel PR changed an unapproved path")
    for path in paths:
        blob(root, selected["head"], path, maximum=16 * 1024**2)
    base = json.loads(blob(root, selected["base"], LOCK))
    updated = json.loads(blob(root, selected["head"], LOCK))
    versions = [
        fedora_kernel.version(
            json.loads(blob(root, selected[side], KERNEL_INPUTS, maximum=1024**2))["fedora_version"],
            base["fedora"],
        )
        for side in ("base", "head")
    ]
    return locked_update(base, updated, allow_unchanged=versions[0] != versions[1])


def prepare(root, event, repository, output):
    root, output = Path(root), Path(output)
    selected = context(event, repository)
    lock = candidate(root, selected)
    base_lock = json.loads(blob(root, selected["base"], LOCK))
    requested = fedora_kernel.version(
        json.loads(blob(root, selected["head"], KERNEL_INPUTS, maximum=1024**2))["fedora_version"],
        lock["fedora"],
    )
    published = fedora_kernel.resolve(requested, lock["fedora"])
    require(
        lock["sources"]["fedora_kernel"]["revision"]
        in (base_lock["sources"]["fedora_kernel"]["revision"], published["revision"]),
        "candidate Fedora pin differs from both the trusted base and published source",
    )
    lock["sources"]["fedora_kernel"]["revision"] = published["revision"]
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="particleve-kernel-update-") as temporary:
        trees = {}
        for name in SOURCES:
            pin = lock["sources"][name]
            tree = Path(temporary) / name
            tree.mkdir()
            git(tree, "init", "--quiet", "--initial-branch=source")
            fetch(tree, pin["url"], pin["revision"], branch=pin["branch"])
            git(tree, "checkout", "--quiet", "--detach", pin["revision"])
            trees[name] = tree
        fedora_kernel.verify_published(
            published, lock["fedora"], trees["fedora_kernel"], Path(temporary) / "published"
        )
        files = {
            ".obs/kernel/" + name: content
            for name, content in generate(
                root, lock, trees["fedora_kernel"], trees["secureblue_kernel"]
            ).items()
        }
    files[LOCK] = json.dumps(lock, indent=2) + "\n"
    files[BUILD_METADATA] = build_metadata(
        base_lock,
        lock,
        json.loads(blob(root, selected["base"], BUILD_METADATA)),
    )
    additions = {}
    for path, content in files.items():
        if content != blob(root, selected["head"], path, maximum=16 * 1024**2):
            additions[path] = base64.b64encode(content.encode()).decode()
    plan = {**selected, "files": additions}
    atomic_write(output / "plan.json", (json.dumps(plan, sort_keys=True, indent=2) + "\n").encode(), 0o600)
    return plan


def api(endpoint, body=None):
    arguments = ["gh", "api", "--hostname", "github.com", endpoint]
    if body is not None:
        arguments.extend(["--input", "-"])
    result = run(
        arguments,
        input=json.dumps(body) if body is not None else None,
        timeout=60,
        env=system_tls_environment() | {"GH_HOST": "github.com"},
    )
    require(len(result.stdout) <= 2 * 1024**2, "oversized GitHub API response")
    return json.loads(result.stdout) if result.stdout.strip() else None


def validate_plan(plan, selected, base_lock=None):
    require(
        set(plan) == {*selected, "files"} and all(plan[key] == value for key, value in selected.items()),
        "prepared kernel update does not match the workflow event",
    )
    files = plan["files"]
    require(isinstance(files, dict) and files.keys() <= ALLOWED, "unapproved generated kernel path")
    for data in files.values():
        require(isinstance(data, str) and len(data) <= 24 * 1024**2, "oversized generated kernel file")
        decoded = base64.b64decode(data, validate=True)
        require(0 < len(decoded) <= 16 * 1024**2, "invalid generated kernel file size")
        decoded.decode()
    if LOCK in files:
        require(base_lock is not None, "generated source pin requires the trusted base lock")
        locked_update(
            base_lock, json.loads(base64.b64decode(files[LOCK], validate=True)), allow_unchanged=True
        )
    return files


def reconcile(root, plan, current):
    """Recover our completed append after a late response or dispatch failure."""
    url = f"https://github.com/{plan['repository']}.git"
    git(root, "fetch", "--no-tags", "--depth=2", url, current, remote=url)
    require(
        git(root, "show", "-s", "--format=%P", current).stdout.strip() == plan["head"],
        "Renovate branch advanced independently; prepare the new head",
    )
    changed = git(root, "diff", "--name-only", "--no-renames", "-z", plan["head"], current).stdout
    require(
        {path for path in changed.split("\0") if path} == plan["files"].keys(),
        "Renovate branch has different generated changes",
    )
    for path, encoded in plan["files"].items():
        require(
            blob(root, current, path, maximum=16 * 1024**2).encode()
            == base64.b64decode(encoded, validate=True),
            "Renovate branch has different generated contents",
        )
    verification = api(f"repos/{plan['repository']}/git/commits/{current}")["verification"]
    require(verification["verified"] is True, "prepared kernel commit is not verified by GitHub")
    return current


def report_check(repository, commit, result, url):
    require(re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository), "invalid GitHub repository")
    oid(commit)
    require(result in ("success", "failure", "cancelled", "skipped"), "invalid source-check outcome")
    require(
        re.fullmatch(r"https://github\.com/" + re.escape(repository) + r"/actions/runs/[0-9]+", url),
        "invalid source-check workflow URL",
    )
    return api(
        f"repos/{repository}/check-runs",
        {
            "name": "source-checks",
            "head_sha": commit,
            "status": "completed",
            "conclusion": result,
            "details_url": url,
            "output": {
                "title": "Source checks " + result,
                "summary": "Complete source checks for the exact generated kernel PR commit.",
            },
        },
    )


def publish(root, event, repository, plan):
    selected = context(event, repository)
    files = validate_plan(plan, selected, json.loads(blob(root, selected["base"], LOCK)))
    pr = api(f"repos/{repository}/pulls/{selected['pull_request']}")
    require(
        pr["state"] == "open"
        and pr["user"]["login"] == "renovate[bot]"
        and pr["base"]["repo"]["full_name"] == repository
        and pr["base"]["ref"] == "main"
        and pr["head"]["repo"]["full_name"] == repository
        and pr["head"]["ref"] == selected["branch"],
        "pull request ownership or target changed",
    )
    current = oid(pr["head"]["sha"])
    if current != selected["head"]:
        current = reconcile(root, plan, current)
    elif files:
        mutation = """mutation($input: CreateCommitOnBranchInput!) {
          createCommitOnBranch(input: $input) {
            commit { oid signature { isValid } }
          }
        }"""
        result = api(
            "graphql",
            {
                "query": mutation,
                "variables": {
                    "input": {
                        "branch": {"repositoryNameWithOwner": repository, "refName": selected["branch"]},
                        "expectedHeadOid": selected["head"],
                        "message": {"headline": "build: refresh generated kernel source inputs"},
                        "fileChanges": {
                            "additions": [
                                {"path": path, "contents": data} for path, data in sorted(files.items())
                            ]
                        },
                    }
                },
            },
        )
        require(not result.get("errors"), "GitHub refused the kernel preparation commit")
        commit = result["data"]["createCommitOnBranch"]["commit"]
        current = oid(commit["oid"])
        require(
            commit["signature"] and commit["signature"]["isValid"] is True,
            "GitHub did not verify the generated kernel commit",
        )
    # GITHUB_TOKEN updates need an explicit check run. The dispatched workflow
    # uses main's workflow with read-only candidate execution and reports the
    # outcome on this exact commit in a separate trusted job.
    api(
        f"repos/{repository}/actions/workflows/check.yml/dispatches",
        {
            "ref": "main",
            "inputs": {"source_commit": current},
        },
    )
    return current
