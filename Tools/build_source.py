#!/usr/bin/python3
"""Select checked system changes for the OBS build ref; leave ancillary commits on main."""

import argparse
import json
import tomllib
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import require
from Tools.source_releases import git

# These tools run in the image/RPM build, rather than on a maintainer's workstation.
BUILD_TOOLS = {"Tools/check-build.py", "Tools/obs-postoutput", "Tools/package-identity.py"}
SERVICE_SELECTION = {
    "revision",
    "versionformat",
    "match-tag",
    "versionrewrite-pattern",
    "versionrewrite-replacement",
}


def ancillary(path):
    return (
        ("/" not in path and path.endswith(".md"))
        or path.startswith(("Documentation/", "Tests/", ".github/"))
        or (path.startswith("Tools/") and path not in BUILD_TOOLS)
        or path in {"Makefile", "LICENSE", ".gitignore", ".obs/site.json", ".obs/project.xml"}
    )


def build_content(root, commit, path):
    entry = git(root, "ls-tree", commit, "--", path).stdout
    if not entry:
        return None
    mode = entry.split()[0]
    content = git(root, "show", f"{commit}:{path}").stdout
    if path == "pyproject.toml":
        project = tomllib.loads(content)
        # Ruff config affects source checks, not the installed Python package.
        project.get("tool", {}).pop("ruff", None)
        return mode, project
    if path.startswith(".obs/") and path.endswith("/_service"):
        service = ET.fromstring(content)
        # Ref/version selection is publication plumbing. Keep every actual service,
        # extraction rule and buildtime operation in the system-input comparison.
        for scm in service.findall("service[@name='obs_scm']"):
            for parameter in list(scm):
                if parameter.tag == "param" and parameter.get("name") in SERVICE_SELECTION:
                    scm.remove(parameter)
        for element in service.iter():
            element.text = (element.text or "").strip() or None
            element.tail = None
        return mode, ET.tostring(service)
    return mode, content


def system_changes(root, base, candidate):
    base = git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}").stdout.strip()
    candidate = git(
        root, "rev-parse", "--verify", "--end-of-options", f"{candidate}^{{commit}}"
    ).stdout.strip()
    require(
        git(root, "merge-base", "--is-ancestor", base, candidate, check=False).returncode == 0,
        "the build ref must be an ancestor of the checked candidate",
    )
    # Compare trees, not the last push: queued CI runs can combine several pushes.
    # Disabling rename detection ensures moving system code into docs still counts.
    paths = git(root, "diff", "--name-only", "--no-renames", "-z", base, candidate, "--")
    return [
        path
        for path in paths.stdout.split("\0")
        if path
        and not ancillary(path)
        and (
            not (path == "pyproject.toml" or (path.startswith(".obs/") and path.endswith("/_service")))
            or build_content(root, base, path) != build_content(root, candidate, path)
        )
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="current OBS build-ref commit")
    parser.add_argument("--candidate", default="HEAD", help="exact commit which passed source checks")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    paths = system_changes(Path.cwd(), args.base, args.candidate)
    if args.github_output:
        with args.github_output.open("a") as output:
            output.write("changed=" + str(bool(paths)).lower() + "\n")
    print(json.dumps({"system_changes": paths, "advance_build": bool(paths)}))


if __name__ == "__main__":
    main()
