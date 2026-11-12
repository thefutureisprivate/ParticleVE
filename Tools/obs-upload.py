#!/usr/bin/python3
"""Configure Git-managed packages or upload reviewed upstream-package services."""

import argparse
import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import read_json, require
from particleve.config import https_url
from Tools.trust import system_tls_context

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("package", choices=("particleve", "mkosi", "fwupd-efi", "kernel"))
parser.add_argument("directory", nargs="?", type=Path, help="reviewed upstream-package source directory")
parser.add_argument("--credentials", type=Path, required=True)
args = parser.parse_args()
git_managed = args.package in {"particleve", "kernel"}
require(
    (args.directory is None) == git_managed,
    "ParticleVE and kernel sources are Git-managed; supply a source directory for mkosi or fwupd-efi",
)
site = read_json(".obs/site.json")
require(args.credentials.stat().st_mode & 0o077 == 0, "OBS credentials must be private")
username, password = args.credentials.read_text().splitlines()
require(username == site["obs_user"], "OBS account does not match the configured project owner")
base = "https://api.opensuse.org/source/" + site["obs_project"] + "/" + args.package


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("Refusing to redirect authenticated OBS requests")


opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=system_tls_context()))


def request(url, data, method, kind):
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": "Basic " + base64.b64encode((username + ":" + password).encode()).decode(),
            "Content-Type": kind,
        },
    )
    try:
        with opener.open(req, timeout=60) as response:
            return ET.fromstring(response.read())
    except urllib.error.HTTPError as exc:
        with exc:
            detail = ET.fromstring(exc.read()).findtext("summary")
        raise SystemExit(f"OBS {exc.code}: {detail}") from None


meta = ET.Element("package", project=site["obs_project"], name=args.package)
ET.SubElement(meta, "title").text = "ParticleVE " + args.package
ET.SubElement(
    meta, "description"
).text = "Native ParticleVE build inputs; see the configured source repository."
build = ET.SubElement(meta, "build")
for repository in ("Fedora_45", "Fedora_45_images"):
    enabled = args.package == "particleve" or repository == "Fedora_45"
    ET.SubElement(build, "enable" if enabled else "disable", repository=repository)
if git_managed:
    url = urllib.parse.urlsplit(https_url(site["source_repository"]))
    # Native OBS version tracking sees the committed spec. The kernel also needs
    # the service definition refreshed atomically with its upstream source pins.
    ET.SubElement(meta, "scmsync").text = urllib.parse.urlunsplit(
        (
            url.scheme,
            url.netloc,
            url.path,
            urllib.parse.urlencode({"subdir": ".obs/" + args.package}),
            urllib.parse.quote(site["source_branch"], safe="/"),
        )
    )
request(base + "/_meta", ET.tostring(meta), "PUT", "text/xml")
if git_managed:
    print(
        json.dumps(
            {"project": site["obs_project"], "package": args.package, "scmsync": meta.findtext("scmsync")}
        )
    )
    raise SystemExit(0)
files = ET.Element("directory")
for file in sorted(args.directory.iterdir()):
    require(file.is_file() and not file.is_symlink(), "upload only reviewed regular source files")
    data = file.read_bytes()
    ET.SubElement(files, "entry", name=file.name, md5=hashlib.md5(data, usedforsecurity=False).hexdigest())
    request(
        base + "/" + urllib.parse.quote(file.name) + "?rev=upload", data, "PUT", "application/octet-stream"
    )
result = request(
    base
    + "?"
    + urllib.parse.urlencode(
        {
            "cmd": "commitfilelist",
            "comment": "Update reviewed ParticleVE source and build definitions",
        }
    ),
    ET.tostring(files),
    "POST",
    "text/xml",
)
print(
    json.dumps(
        {
            "project": site["obs_project"],
            "package": args.package,
            "commit": result.attrib,
            "files": [e.attrib["name"] for e in files],
        },
        indent=2,
    )
)
