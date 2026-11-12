#!/usr/bin/python3
"""Generate tracked, public build inputs for this native ParticleOS fork."""

import argparse
import shutil
from pathlib import Path

from particleve.common import atomic_write, read_json, require, run, write_json
from particleve.config import https_url

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--site", type=Path, default=Path(".obs/site.json"))
args = p.parse_args()
repo = Path(__file__).resolve().parent.parent
pins = read_json(repo / "sources.lock.json")
site = read_json(args.site)
feed = https_url(site["feed"])
packages = https_url(site["package_repository"])
require(site["obs_project"] and "REPLACE" not in site["obs_project"], "configure an owned OBS project")
trust = repo / "mkosi.extra/usr/lib/particleve/trust"
trust.mkdir(parents=True, exist_ok=True)
for name in ("releases.gpg", "secure-boot.crt", "pcr-public-key.pem", "packages.asc"):
    source = Path(site["trust_directory"]).resolve() / name
    require(source.is_file() and source.stat().st_size, f"missing public verification material: {source}")
    require(b"PRIVATE KEY" not in source.read_bytes(), "private keys must stay outside image sources")
    if source != (trust / name).resolve():
        shutil.copy2(source, trust / name)
certificate_key = run(["openssl", "x509", "-in", trust / "secure-boot.crt", "-pubkey", "-noout"]).stdout
require(
    certificate_key.strip() == (trust / "pcr-public-key.pem").read_text().strip(),
    "PCR verification key must match the OBS project certificate",
)
run(["gpg", "--batch", "--show-keys", trust / "packages.asc"])
initrd = repo / "mkosi.initrd.conf/mkosi.extra"
(initrd / "etc/systemd").mkdir(parents=True, exist_ok=True)
shutil.copy2(trust / "pcr-public-key.pem", initrd / "etc/systemd/tpm2-pcr-public-key.pem")
wants = initrd / "usr/lib/systemd/system/initrd-root-fs.target.requires"
wants.mkdir(parents=True, exist_ok=True)
link = wants / "particleve-initrd-storage.service"
if not link.is_symlink():
    link.symlink_to("../particleve-initrd-storage.service")
profile = repo / "mkosi.profiles/particleve"
repo_dir = profile / "repositories"
repo_dir.mkdir(parents=True, exist_ok=True)
for name, url, include, key in (
    ("systemd", pins["systemd_repository"], "systemd* libudev*", "systemd"),
    (
        "packages",
        packages,
        "particleve-* fwupd-efi* kernel-core kernel-modules-core kernel-modules kernel-modules-extra",
        "packages",
    ),
):
    atomic_write(
        repo_dir / f"{name}.repo",
        (
            f"[particleve-{name}]\nname=ParticleVE {name}\nbaseurl={url}\n"
            f"gpgcheck=1\nenabled=1\npriority=1\nincludepkgs={include}\n"
            f"gpgkey=file:///usr/share/pki/rpm-gpg/particleve-{key}.asc\n"
        ).encode(),
        0o644,
    )
conf = "[Build]\n"
for setting in ("SandboxTrees", "ToolsTreeSandboxTrees"):
    for name, key in (
        ("systemd", "mkosi.profiles/particleve/keys/systemd-stable.asc"),
        ("packages", "mkosi.extra/usr/lib/particleve/trust/packages.asc"),
    ):
        conf += (
            f"{setting}=%D/mkosi.profiles/particleve/repositories/{name}.repo:/etc/yum.repos.d/{name}.repo\n"
        )
        conf += f"{setting}=%D/{key}:/usr/share/pki/rpm-gpg/particleve-{name}.asc\n"
conf += "ToolsTreePackages=particleve-build-tools\n"
(profile / "mkosi.conf.d").mkdir(exist_ok=True)
atomic_write(profile / "mkosi.conf.d/10-publication.conf", conf.encode(), 0o644)
write_json(
    repo / "mkosi.extra/usr/lib/particleve/build.json",
    {
        "schema": 1,
        "sources": {name: pin["revision"] for name, pin in pins["sources"].items()},
        "fedora": "45",
        "feed": feed,
        "cpu_baseline": "x86-64-v2",
        "hardware_validation": "unvalidated",
    },
)
print("Public site configuration generated. Review and commit these inputs before OBS builds.")
