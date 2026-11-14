#!/usr/bin/python3
"""Generate reviewable OBS definitions and the dependency recipe from resolved mkosi configuration."""

import argparse
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import atomic_write, read_json, require
from particleve.config import https_url


def dependency_recipe(summary):
    images = summary["Images"]
    main = next(image for image in images if image["Image"] == "main")
    initrd = next(image for image in images if image["Image"] == "default-initrd")
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
    return (
        "# needssslcertforbuild\n[Include]\nInclude=mkosi-obs\n\n[Content]\nPackages=\n        "
        + "\n        ".join(packages)
        + "\n\nBuildPackages=\n        "
        + "\n        ".join(build_packages)
        + "\n"
    ).encode()


p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--site", type=Path, required=True)
p.add_argument("--summary", type=Path, required=True, help="pinned mkosi --json summary output")
p.add_argument("--output", type=Path, default=Path("build/obs-project"))
p.add_argument("--check", action="store_true", help="check tracked OBS dependencies without writing files")
args = p.parse_args()
site, summary = read_json(args.site), read_json(args.summary)
project = site["obs_project"]
require(project and "REPLACE" not in project, "configure an owned OBS project")
https_url(site["source_repository"])
recipe = dependency_recipe(summary)
recipe_path = Path(".obs/fedora/x86-64/mkosi.conf")
if args.check:
    require(
        recipe_path.is_file() and not recipe_path.is_symlink() and recipe_path.read_bytes() == recipe,
        "OBS dependencies differ from the resolved image; regenerate them with "
        "Tools/obs-project.py --site .obs/site.json --summary build/summary.json",
    )
    print("OBS dependencies match the resolved image")
    raise SystemExit(0)
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
    b'%if "%_repository" == "Fedora_45"\n'
    b"BuildFlags: onlybuild:mkosi onlybuild:fwupd-efi onlybuild:kernel "
    b"onlybuild:kernel:build-policy onlybuild:particleve:rpm onlybuild:particleve:allocator\n"
    b"%endif\n"
    b'%if "%_repository" == "Fedora_45_images"\n'
    b"BuildFlags: onlybuild:particleve excludebuild:particleve:rpm "
    b"excludebuild:particleve:allocator\nType: mkosi\n"
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
# OBS schedules this dependency recipe; the worker builds the checkout's root mkosi.conf.
atomic_write(recipe_path, recipe, 0o644)
print(args.output.resolve())
