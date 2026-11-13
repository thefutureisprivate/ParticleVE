"""Notify OBS only for the selected, checked source commit using package tokens."""

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import Error, read_json, require
from Tools.source_releases import git, github
from Tools.trust import system_tls_context

MARKERS = {
    "particleve": ("_scmsync.obsinfo", "_service:obs_scm:particleve.obsinfo"),
    "kernel": ("_scmsync.obsinfo", "_service:obs_scm:particleve-kernel-inputs.obsinfo"),
    "mkosi": ("_service:obs_scm:particleve-build-inputs.obsinfo",),
    "fwupd-efi": ("_service:obs_scm:particleve-build-inputs.obsinfo",),
}
API = "https://api.opensuse.org"
OID = re.compile(r"[0-9a-f]{40}")


def component_changed(root, package, previous, candidate, *, git_command=None):
    invoke = git_command or git
    if previous == candidate:
        return False
    if package == "particleve":
        return True
    if invoke(root, "cat-file", "-e", previous + "^{commit}", check=False).returncode:
        return True
    # Kernel generation binds every extracted input in .obs/kernel; the source
    # checks require that generated directory to match the helpers and pins.
    paths = [".obs/" + package]
    if package in {"mkosi", "fwupd-efi"}:
        paths.extend(("Sources/particleve/package_sources.py", "sources.lock.json"))
    difference = invoke(root, "diff", "--quiet", previous, candidate, "--", *paths, check=False)
    require(difference.returncode in (0, 1), "OBS component source comparison failed")
    return difference.returncode == 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        raise Error("OBS source refresh redirects are refused")


def credentials(raw):
    require(isinstance(raw, str) and 0 < len(raw) <= 8192, "missing or oversized OBS service tokens")

    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate OBS service token field")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except json.JSONDecodeError:
        raise Error("invalid OBS service token JSON") from None
    require(isinstance(value, dict) and value.keys() == MARKERS.keys(), "unexpected OBS service token scopes")
    require(
        all(
            isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9+/]{16,512}", token)
            for token in value.values()
        ),
        "invalid OBS service token encoding",
    )
    require(len(set(value.values())) == len(value), "each OBS package requires its own service token")
    return value


def request(opener, path, token=None):
    headers = {"Authorization": "Token " + token} if token is not None else {}
    req = urllib.request.Request(API + path, data=b"" if token is not None else None, headers=headers)
    try:
        with opener.open(req, timeout=20) as response:
            require(response.status == 200, "unexpected OBS source refresh status")
            body = response.read(65537)
            require(len(body) <= 65536, "oversized OBS source refresh response")
            return body
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise Error(f"OBS source refresh returned HTTP {code}") from None
    except urllib.error.URLError:
        raise Error("OBS source refresh transport failed") from None


def package_state(opener, project, package, candidate, root):
    base = "/public/source/" + urllib.parse.quote(project, safe="") + "/" + package
    directory = ET.fromstring(request(opener, base + "?expand=1"))
    require(directory.tag == "directory", "invalid OBS source directory")
    services = directory.findall("serviceinfo")
    require(len(services) == 1, "missing or ambiguous OBS source service status")
    code = services[0].get("code")
    if code == "running":
        return "in_progress"
    if code != "succeeded":
        return "stale"
    entries = {entry.get("name") for entry in directory.findall("entry")}
    if not set(MARKERS[package]) <= entries:
        return "stale"
    for marker in MARKERS[package]:
        body = request(opener, base + "/" + urllib.parse.quote(marker, safe="") + "?expand=1")
        require(len(body) <= 8192, "oversized OBS source commit marker")
        commits = [
            line.removeprefix("commit: ")
            for line in body.decode().splitlines()
            if line.startswith("commit: ")
        ]
        require(len(commits) == 1 and OID.fullmatch(commits[0]), "invalid OBS source commit marker")
        if component_changed(root, package, commits[0], candidate):
            return "stale"
    return "current"


def refresh(root, repository, candidate, raw_tokens):
    require(
        isinstance(candidate, str) and OID.fullmatch(candidate), "source refresh requires an immutable commit"
    )
    require(re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository), "invalid GitHub repository")
    site = read_json(root / ".obs/site.json")
    require(
        site["source_repository"].lower() == f"https://github.com/{repository}.git".lower(),
        "OBS source repository differs from the checked repository",
    )
    require(git(root, "rev-parse", "HEAD").stdout.strip() == candidate, "source refresh checkout differs")
    ref = github(repository, "git/ref/heads/" + urllib.parse.quote(site["source_branch"], safe=""))
    selected = ref.get("object", {})
    require(
        isinstance(selected, dict)
        and selected.get("type") == "commit"
        and isinstance(selected.get("sha"), str)
        and OID.fullmatch(selected["sha"]),
        "invalid checked build ref",
    )
    if selected["sha"] != candidate:
        return {"source_commit": candidate, "selected": False, "packages": {}}
    tokens = credentials(raw_tokens)
    opener = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=system_tls_context())
    )
    states = {
        package: package_state(opener, site["obs_project"], package, candidate, root) for package in MARKERS
    }
    require(
        "in_progress" not in states.values(),
        "OBS source service is already running; retry after it completes",
    )
    for package, state in states.items():
        if state == "current":
            continue
        result = ET.fromstring(request(opener, "/trigger/runservice", tokens[package]))
        require(result.tag == "status" and result.get("code") == "ok", "OBS source refresh was not accepted")
        states[package] = "requested"
    return {"source_commit": candidate, "selected": True, "packages": states}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            refresh(Path.cwd(), args.repository, args.candidate, os.environ.get("OBS_SERVICE_TOKENS", ""))
        )
    )


if __name__ == "__main__":
    main()
