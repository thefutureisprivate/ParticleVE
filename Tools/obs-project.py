#!/usr/bin/python3
"""Generate reviewable OBS definitions and the dependency recipe from resolved mkosi configuration."""

import argparse
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import atomic_write, read_json, require
from particleve.config import https_url

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--site", type=Path, required=True)
p.add_argument("--summary", type=Path, required=True, help="pinned mkosi --json summary output")
p.add_argument("--output", type=Path, default=Path("build/obs-project"))
args = p.parse_args()
site, summary = read_json(args.site), read_json(args.summary)
project = site["obs_project"]
require(project and "REPLACE" not in project, "configure an owned OBS project")
https_url(site["source_repository"])
args.output.mkdir(parents=True, exist_ok=True)
meta = ET.Element("project", name=project)
ET.SubElement(meta, "title").text = "ParticleVE"
ET.SubElement(meta, "description").text = "⸭ An image-based, secure hypervisor, built on top of Fedora Linux."
ET.SubElement(meta, "person", userid=site["obs_user"], role="maintainer")
for name in ("Fedora_45", "Fedora_45_images"):
    repository = ET.SubElement(meta, "repository", name=name, rebuild="transitive", block="all")
    if name.endswith("images"):
        ET.SubElement(repository, "path", project=project, repository="Fedora_45")
        ET.SubElement(repository, "path", project="system:systemd:stable", repository="fedora_45_images")
    ET.SubElement(repository, "path", project="system:systemd:stable", repository="Fedora_45")
    ET.SubElement(repository, "path", project="openSUSE:Tools", repository="Fedora_45")
    ET.SubElement(
        repository, "path", project=site["fedora_project"], repository=site["fedora_updates_repository"]
    )
    ET.SubElement(
        repository, "path", project=site["fedora_project"], repository=site["fedora_base_repository"]
    )
    ET.SubElement(repository, "arch").text = "x86_64"
ET.indent(meta)
atomic_write(args.output / "_meta", ET.tostring(meta) + b"\n", 0o644)
atomic_write(
    args.output / "prjconf",
    b"Release: <CI_CNT>.<B_CNT>\n"
    b"Prefer: systemd-udev systemd-boot\n"
    b"Prefer: -systemd-standalone-repart -systemd-boot-unsigned\n"
    b'%if "%_repository" == "Fedora_45_images"\nType: mkosi\n'
    b"Repotype: checksumsfile:rawsig staticlinks\nPatterntype: none\n"
    b"%endif\n",
    0o644,
)
services = ET.parse(".obs/particleve/_service").getroot()
service = services.find("service[@name='obs_scm']")
for name, value in {
    "url": site["source_repository"],
    "revision": site["source_branch"],
}.items():
    service.find(f"param[@name='{name}']").text = value
ET.indent(services)
atomic_write(args.output / "_service", ET.tostring(services) + b"\n", 0o644)
# OBS reads this extracted file to schedule all dependencies; the native mkosi builder
# builds the checkout's root mkosi.conf and supplies --image-version=$RELEASE.
images = summary["Images"]
main = next(i for i in images if i["Image"] == "main")
initrd = next(i for i in images if i["Image"] == "default-initrd")
tools = summary["Tools"]
packages = sorted(
    set(main["Packages"] + main["VolatilePackages"] + initrd["Packages"] + initrd["VolatilePackages"])
)
build_packages = sorted(
    set(
        main["BuildPackages"]
        + tools["Packages"]
        + tools["VolatilePackages"]
        + ["mkosi", "particleve-build-tools"]
    )
)
recipe = (
    "# needssslcertforbuild\n[Include]\nInclude=mkosi-obs\n\n[Content]\nPackages=\n        "
    + "\n        ".join(packages)
    + "\n\nBuildPackages=\n        "
    + "\n        ".join(build_packages)
    + "\n"
)
atomic_write(Path(".obs/fedora/x86-64/mkosi.conf"), recipe.encode(), 0o644)
print(args.output.resolve())
