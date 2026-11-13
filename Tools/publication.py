"""Read-only publication monitoring; OBS claims remain inside the producer trust boundary."""

import json
import re
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree

from particleve.common import Error, digest, require
from particleve.config import https_url, integer, version_key
from particleve.release import checksums, verify_directory
from Tools import kernel_freshness, publication_inputs
from Tools.trust import system_tls_context

PACKAGES = {
    "particleve": ("Fedora_45", "particleve:rpm", "particleve"),
    "mkosi": ("Fedora_45", "mkosi", "particleve-build-inputs"),
    "fwupd-efi": ("Fedora_45", "fwupd-efi", "particleve-build-inputs"),
    "kernel": ("Fedora_45", "kernel", "particleve-kernel-inputs"),
    "image": ("Fedora_45_images", "particleve", "particleve"),
}
# OBS has not yet decided success/failure in the signed `finished` transition.
# https://github.com/openSUSE/open-build-service/blob/master/src/api/app/models/buildresult.rb
PENDING = {"building", "signing", "finished", "scheduled", "blocked", "dispatching", "waiting"}


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        parsed = urlsplit(newurl)
        require(
            parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password,
            "publication redirect must retain HTTPS without credentials",
        )
        return super().redirect_request(request, fp, code, message, headers, newurl)


def request(url, *, size_limit=1024 * 1024, method="GET"):
    require(method in ("GET", "HEAD"), "publication observation only permits GET and HEAD")
    parsed = urlsplit(url)
    require(
        parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password,
        "publication requests require HTTPS without credentials",
    )
    opener = urllib.request.build_opener(
        HTTPSRedirects(), urllib.request.HTTPSHandler(context=system_tls_context())
    )
    try:
        opened = opener.open(
            urllib.request.Request(
                url, method=method, headers={"User-Agent": "ParticleVE-publication-check"}
            ),
            timeout=15,
        )
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 400 and exc.reason == "service in progress":
            raise
        raise Error(f"publication HTTP {exc.code}: {parsed.netloc}{parsed.path}") from exc
    with opened as response:
        require(response.status == 200, "publication request did not return HTTP 200")
        if method == "HEAD":
            length = response.headers.get("Content-Length", "")
            require(length.isdecimal(), "artifact availability has no declared size")
            return int(length)
        data = response.read(size_limit + 1)
        require(len(data) <= size_limit, "publication response exceeds its size limit")
        return data


def signed_manifest(feed, keyring, certificate):
    """Verify publication claims without treating HEAD requests as payload verification."""
    with tempfile.TemporaryDirectory(prefix="particleve-publication-") as tmp:
        directory = Path(tmp)
        for name in ("SHA256SUMS", "SHA256SUMS.asc"):
            (directory / name).write_bytes(request(feed + "/" + name, size_limit=8 * 1024**2))
        index = checksums(directory, keyring)
        versions = {
            match[1]: name
            for name in index
            if (match := re.fullmatch(r"ParticleVE_([0-9.-]+)_x86-64\.release\.json", name))
        }
        require(versions, "signed feed contains no release manifest")
        name = versions[max(versions, key=version_key)]
        (directory / name).write_bytes(request(feed + "/" + name, size_limit=2 * 1024**2))
        return verify_directory(directory, keyring, certificate, artifacts=False)


def source_revision(data):
    lines = data.decode().splitlines()
    matches = [line.removeprefix("commit: ") for line in lines if line.startswith("commit: ")]
    require(len(matches) == 1 and re.fullmatch("[0-9a-f]{40}", matches[0]), "invalid OBS source identity")
    return matches[0]


def read_source(url):
    try:
        return source_revision(request(url))
    except urllib.error.HTTPError as exc:
        exc.close()
        # Native OBS temporarily withholds expanded files during obs_scm refresh.
        # This is not evidence of a revision; the pending observation still expires.
        if exc.code == 400 and exc.reason == "service in progress":
            return None
        raise


def source_workflow(value, revision):
    """Observe only the latest push workflow for the exact development commit."""
    require(
        type(value) is dict and type(value.get("total_count")) is int and value["total_count"] >= 0,
        "invalid source workflow response",
    )
    runs = value.get("workflow_runs")
    require(type(runs) is list and len(runs) <= 1, "unbounded source workflow observation")
    if value["total_count"] == 0:
        require(not runs, "inconsistent source workflow count")
        return "pending"
    require(len(runs) == 1, "missing source workflow run")
    run = runs[0]
    require(
        type(run) is dict
        and run.get("head_sha") == revision
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == ".github/workflows/check.yml",
        "source workflow identity differs",
    )
    status = run.get("status")
    require(
        status in {"completed", "queued", "in_progress", "waiting", "requested", "pending"},
        "unknown source workflow state",
    )
    if status != "completed":
        return "pending"
    conclusion = run.get("conclusion")
    require(
        conclusion
        in {
            "success",
            "failure",
            "cancelled",
            "timed_out",
            "action_required",
            "neutral",
            "skipped",
            "stale",
            "startup_failure",
        },
        "unknown source workflow conclusion",
    )
    return "pass" if conclusion == "success" else "fail"


def assess(
    head,
    sources,
    statuses,
    manifest,
    *,
    now,
    grace_seconds,
    previous=None,
    upstreams=None,
    source_matches=None,
    selection=None,
):
    """A pending build must become stale even when it never reports a terminal failure."""
    integer(grace_seconds, 60, "publication grace seconds")
    require(grace_seconds <= 7 * 86400, "publication grace cannot exceed seven days")
    require(re.fullmatch("[0-9a-f]{40}", head), "invalid GitHub source revision")
    require(set(sources) == set(PACKAGES) == set(statuses), "missing publication package observation")
    require(
        all(value is None or re.fullmatch("[0-9a-f]{40}", value) for value in sources.values()),
        "invalid observed source identity",
    )
    checks = []
    if source_matches is not None:
        require(
            type(source_matches) is dict
            and source_matches.keys() == PACKAGES.keys()
            and all(type(value) is bool for value in source_matches.values()),
            "invalid component input comparison",
        )
        require(
            all(not source_matches[name] for name, value in sources.items() if value is None),
            "missing source cannot match",
        )
        require(
            all(not source_matches[name] or sources[name] == head for name in ("particleve", "image")),
            "host and image sources must match the selected commit",
        )
    if selection is not None:
        require(
            type(selection) is dict
            and set(selection) == {"revision", "system_changes", "workflow"}
            and isinstance(selection["revision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", selection["revision"])
            and type(selection["system_changes"]) is int
            and 0 <= selection["system_changes"] <= 100000
            and selection["workflow"] in {"pass", "pending", "fail"},
            "invalid development source observation",
        )
        changed = selection["system_changes"] != 0
        checks.append(
            {
                "name": "source-selection",
                "result": "fail"
                if changed and selection["workflow"] == "fail"
                else "pending"
                if changed
                else "pass",
                **selection,
            }
        )
    for name in PACKAGES:
        code = statuses[name]
        require(re.fullmatch(r"[a-z_]{1,32}", code), "invalid OBS build status")
        state = "pass" if code in {"succeeded", "published"} else "pending" if code in PENDING else "fail"
        checks.append({"name": name + ":build", "result": state, "code": code})
        checks.append(
            {
                "name": name + ":source",
                "result": "pass"
                if (source_matches[name] if source_matches is not None else sources[name] == head)
                else "pending",
                "revision": sources[name],
            }
        )
    if upstreams is not None:
        require(
            isinstance(upstreams, dict) and upstreams.keys() == kernel_freshness.UPSTREAMS,
            "missing kernel upstream observation",
        )
        for name, observation in sorted(upstreams.items()):
            pattern = r"[0-9a-f]{40}"
            if name == "fedora-kernel:upstream":
                pattern = r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,3}-[0-9]{1,8}\.fc45@" + pattern
            require(
                isinstance(observation, dict)
                and set(observation) == {"selected", "available"}
                and all(
                    isinstance(value, str) and re.fullmatch(pattern, value) for value in observation.values()
                ),
                "invalid kernel upstream observation",
            )
            checks.append(
                {
                    "name": name,
                    "result": "pass" if observation["selected"] == observation["available"] else "pending",
                    **observation,
                }
            )
    published = manifest["sources"]["particleve"]
    require(re.fullmatch("[0-9a-f]{40}", published), "invalid signed publication source identity")
    checks.append(
        {
            "name": "signed-feed:source",
            "result": "pass" if published == head else "pending",
            "revision": published,
            "version": manifest["version"],
        }
    )
    old_checks = {}
    if previous is not None:
        require(type(previous) is dict and previous.get("schema") == 1, "unknown publication observer state")
        observed = datetime.fromisoformat(previous["observed_at"])
        require(now >= observed, "publication observer clock moved backwards")
        old_checks = {item["name"]: item for item in previous["checks"]}
        require(len(old_checks) == len(previous["checks"]), "duplicate publication observer check")
    for check in checks:
        if check["result"] != "pending":
            continue
        since = old_checks.get(check["name"], {}).get("pending_since", now.isoformat())
        started = datetime.fromisoformat(since)
        require(started <= now, "publication pending timestamp is in the future")
        check["pending_since"] = started.isoformat()
        if (now - started).total_seconds() > grace_seconds:
            check["result"] = "fail"
            check["reason"] = "publication did not complete within the observer grace period"
    return {
        "schema": 1,
        "observed_at": now.isoformat(),
        "source_revision": head,
        "grace_seconds": grace_seconds,
        "result": "fail"
        if any(c["result"] == "fail" for c in checks)
        else ("pending" if any(c["result"] == "pending" for c in checks) else "pass"),
        "checks": checks,
    }


def collect(site, keyring, certificate, *, grace_seconds=7200, previous=None):
    require(
        previous is None or (type(previous) is dict and previous.get("site_sha256") == digest(site)),
        "observer state is bound to another publication policy; select its own state directory",
    )
    repository = re.fullmatch(
        r"https://github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\.git", site["source_repository"]
    )
    require(repository, "publication monitor requires the declared GitHub source repository")
    project = site["obs_project"]
    require(re.fullmatch(r"[A-Za-z0-9_.:+-]+", project), "invalid OBS project")
    feed = https_url(site["feed"])
    api = "https://api.opensuse.org/public"
    source = f"{api}/source/{project}"
    branch = quote(site["source_branch"], safe="")
    urls = {
        "github": f"https://api.github.com/repos/{repository[1]}/commits/{branch}",
        "development": f"https://api.github.com/repos/{repository[1]}/commits/main",
        "builds": f"{api}/build/{project}/_result?arch=x86_64",
        "maintainers": source + "/_meta",
        **{
            label: f"{source}/{package.split(':', 1)[0]}/_service:obs_scm:{info}.obsinfo?rev=latest&expand=1"
            for label, (_, package, info) in PACKAGES.items()
        },
        **{
            label + ":access": f"{source}/{package.split(':', 1)[0]}/_meta"
            for label, (_, package, _) in PACKAGES.items()
        },
    }
    with ThreadPoolExecutor(max_workers=4) as workers:
        pending = {
            name: workers.submit(read_source if name in PACKAGES else request, url)
            for name, url in urls.items()
        }
        responses = {name: job.result() for name, job in pending.items()}
    github = json.loads(responses["github"])
    development = json.loads(responses["development"])
    maintainers = ElementTree.fromstring(responses["maintainers"])
    require(
        [person.attrib for person in maintainers.findall("person")]
        == [{"userid": site["obs_user"], "role": "maintainer"}]
        and not maintainers.findall("group"),
        "OBS project access differs from the reviewed owner-only policy",
    )
    for package in PACKAGES:
        metadata = ElementTree.fromstring(responses[package + ":access"])
        require(
            [person.attrib for person in metadata.findall("person")]
            in ([], [{"userid": site["obs_user"], "role": "maintainer"}])
            and not metadata.findall("group"),
            "OBS package access differs from the reviewed owner-only policy: " + package,
        )
    inputs = publication_inputs.collect(
        site["source_repository"],
        github["sha"],
        development["sha"],
        {name: responses[name] for name in PACKAGES},
    )
    workflow = "pass"
    if inputs["system_changes"]:
        url = f"https://api.github.com/repos/{repository[1]}/actions/workflows/check.yml/runs?head_sha={development['sha']}&event=push&branch=main&per_page=1"
        workflow = source_workflow(json.loads(request(url)), development["sha"])
    builds = ElementTree.fromstring(responses["builds"])
    statuses = {}
    for label, (repository_name, package, _) in PACKAGES.items():
        matches = [
            status.attrib["code"]
            for result in builds.findall("result")
            if result.get("repository") == repository_name and result.get("arch") == "x86_64"
            for status in result.findall("status")
            if status.get("package") == package
        ]
        require(len(matches) == 1, f"missing or ambiguous build observation: {package}")
        statuses[label] = matches[0]
    manifest = signed_manifest(feed, keyring, certificate)
    with ThreadPoolExecutor(max_workers=4) as workers:
        pending = {
            kind: workers.submit(request, feed + "/" + item["file"], method="HEAD")
            for kind, item in manifest["artifacts"].items()
        }
        for kind, job in pending.items():
            require(
                job.result() == manifest["artifacts"][kind]["size"],
                "published artifact size differs: " + kind,
            )
    result = assess(
        github["sha"],
        {name: responses[name] for name in PACKAGES},
        statuses,
        manifest,
        now=datetime.now(UTC),
        grace_seconds=grace_seconds,
        previous=previous,
        upstreams=kernel_freshness.collect(repository[1], github["sha"]),
        source_matches=inputs["matches"],
        selection={
            "revision": development["sha"],
            "system_changes": inputs["system_changes"],
            "workflow": workflow,
        },
    )
    result["claims"] = (
        "OBS-signed metadata and HTTPS availability; payload bytes require normal release authentication"
    )
    result["site_sha256"] = digest(site)
    return result
