"""Generate an ordinary OBS kernel recipe from immutable upstream inputs.

This runs from the trusted base of a dependency PR. Never import code from the
candidate lock or execute an upstream shell/RPM recipe in this generator.
"""

import json
import re
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from particleve.common import atomic_write, require
from particleve.kernelbuild import (
    adapt_spec,
    config_text,
    configuration,
    fedora_version,
    regular,
    replace_once,
    sha256,
    source_manifest,
)
from Tools.sourcegit import git

GENERATED = ("kernel.spec", "kernel-local", "kernel.inputs.json", "_service")
FEDORA_URL = "https://src.fedoraproject.org/rpms/kernel.git"
SECUREBLUE_URL = "https://github.com/secureblue/kernel.git"


def pins(lock):
    result = {name: lock["sources"][name] for name in ("fedora_kernel", "secureblue_kernel")}
    for name, url, branch in (
        ("fedora_kernel", FEDORA_URL, "f" + lock["fedora"]),
        ("secureblue_kernel", SECUREBLUE_URL, "live"),
    ):
        pin = result[name]
        require(
            set(pin) == {"url", "revision", "branch"}
            and pin["url"] == url
            and pin["branch"] == branch
            and re.fullmatch("[0-9a-f]{40}", pin["revision"]),
            "kernel updates require the selected Fedora/secureblue sources and immutable commits",
        )
    return result


def source_files(directory, expected):
    require(git(directory, "rev-parse", "HEAD").stdout.strip() == expected, "kernel checkout pin differs")
    require(not git(directory, "status", "--porcelain").stdout, "kernel source checkout is dirty")
    result = {}
    for row in git(directory, "ls-files", "--stage", "-z").stdout.rstrip("\0").split("\0"):
        fields, name = row.split("\t", 1)
        mode, _blob, stage = fields.split()
        require(
            mode in ("100644", "100755") and stage == "0" and name not in result,
            "kernel source inputs require regular tracked files with unambiguous Git modes",
        )
        result[name] = 0o755 if mode == "100755" else 0o644
    return result


def service_definition(lock, fedora_names, repository):
    services = ET.Element("services")

    def scm(url, revision, filename, extracts, renames):
        element = ET.SubElement(services, "service", name="obs_scm")
        for key, value in (
            ("scm", "git"),
            ("url", url),
            ("revision", revision),
            ("filename", filename),
            ("without-version", "1"),
            *(("extract", name) for name in extracts),
            *(("extract-rename", old + ":" + new) for old, new in renames.items()),
        ):
            ET.SubElement(element, "param", name=key).text = value

    scm(
        repository,
        "build",
        "particleve-kernel-inputs",
        (
            ".obs/kernel/kernel.spec",
            ".obs/kernel/kernel-local",
            ".obs/kernel/kernel.inputs.json",
            "Sources/particleve/kernelbuild.py",
            "Sources/particleve/kernelpayload.py",
        ),
        {
            ".obs/kernel/kernel.spec": "kernel.recipe",
            ".obs/kernel/policy.json": "kernel-policy.json",
            ".obs/kernel/fedora-builtin.pem": "fedora-builtin.pem",
        },
    )
    scm(
        FEDORA_URL,
        lock["fedora_kernel"]["revision"],
        "fedora-kernel-inputs",
        sorted(set(fedora_names) - {".gitignore", "kernel.spec", "kernel-local", "sources"}),
        {
            "kernel.spec": "fedora-kernel.recipe",
            "kernel-local": "fedora-kernel-local",
            "sources": "fedora-sources",
        },
    )
    scm(
        SECUREBLUE_URL,
        lock["secureblue_kernel"]["revision"],
        "secureblue-kernel-inputs",
        ("correct-spectre-flag-behavior.patch",),
        {"LICENSE": "secureblue.LICENSE", "srpm_script.sh": "secureblue-srpm_script.sh"},
    )
    ET.SubElement(services, "service", name="download_files")
    ET.indent(services, space="  ")
    return ET.tostring(services, encoding="unicode") + "\n"


def generate(repo, lock, fedora, secureblue):
    repo, fedora, secureblue = map(Path, (repo, fedora, secureblue))
    locked = pins(lock)
    names = source_files(fedora, locked["fedora_kernel"]["revision"])
    source_files(secureblue, locked["secureblue_kernel"]["revision"])
    manifest = source_manifest(fedora, names)
    policy_data = regular(repo / ".obs/kernel/policy.json")
    policy = json.loads(policy_data)
    retained = policy["retained_builtin"]
    require(
        set(retained) == {"file", "sha256", "baseline_kernel", "certificate_sha256"}
        and retained["file"] == "fedora-builtin.pem"
        and re.fullmatch("[0-9a-f]{64}", retained["sha256"]),
        "retained Fedora built-in trust requires an explicit pinned public bundle",
    )
    builtin = regular(repo / ".obs/kernel/fedora-builtin.pem", 65536)
    require(
        sha256(builtin) == retained["sha256"]
        and b"PRIVATE KEY" not in builtin
        and builtin.count(b"-----BEGIN CERTIFICATE-----") == len(retained["certificate_sha256"]),
        "retained Fedora built-in certificate bundle differs from its approved policy",
    )
    script = regular(secureblue / "srpm_script.sh").decode()
    selected = configuration(script, policy)
    patches = sorted(path.relative_to(secureblue).as_posix() for path in (secureblue / "patches").iterdir())
    require(
        set(patches) == set(policy["spec_patches"]) | set(policy["excluded_patches"])
        and not set(policy["spec_patches"]) & set(policy["excluded_patches"]),
        "secureblue packaging patches require an explicit adoption or exclusion decision",
    )
    original = regular(fedora / "kernel.spec").decode()
    # git apply treats the pinned patch as data and uses no shell evaluation.
    with tempfile.TemporaryDirectory(prefix="particleve-kernel-recipe-") as temporary:
        tree = Path(temporary)
        (tree / "kernel.spec").write_text(original)
        for name in policy["spec_patches"]:
            patch = secureblue / name
            regular(patch)
            git(tree, "apply", "--check", patch.resolve())
            git(tree, "apply", patch.resolve())
        spec = adapt_spec((tree / "kernel.spec").read_text(), manifest)
    spec = spec.replace(
        "%prep\n",
        "%prep\npython3 %{SOURCE5000} --prepare-sources %{_sourcedir} --manifest %{SOURCE5001}\n"
        "test -s %{_sourcedir}/_projectcert.crt\n"
        "openssl x509 -in %{_sourcedir}/_projectcert.crt -noout\n",
        1,
    )
    require(spec.count("%prep\n") == 1, "Fedora prep section changed")
    boundary = "    %{make} %{?_smp_mflags} mrproper\n    cp configs/$Config .config\n"
    require(spec.count(boundary) == 1, "Fedora certificate installation boundary changed")
    spec = spec.replace(
        boundary,
        "    %{make} %{?_smp_mflags} mrproper\n"
        "    install -m0644 %{SOURCE5009} certs/particleve-fedora.pem\n"
        "    cp configs/$Config .config\n",
    )
    declaration = """Source5000: kernelbuild.py
Source5001: kernel.inputs.json
Source5002: kernel-policy.json
Source5003: kernel.recipe
Source5004: fedora-kernel.recipe
Source5005: fedora-kernel-local
Source5006: secureblue.LICENSE
Source5007: secureblue-srpm_script.sh
Source5008: fedora-sources
Source5009: fedora-builtin.pem
Source5010: kernelpayload.py
"""
    require(spec.count("Source4002: gating.yaml\n") == 1, "Fedora source declarations changed")
    spec = spec.replace("Source4002: gating.yaml\n", "Source4002: gating.yaml\n\n" + declaration)
    spec = (
        "# needssslcertforbuild\nBuildRequires: pesign-obs-integration >= 10\nBuildRequires: pesign\n"
        "BuildRequires: particleve-kernel-build\n" + spec
    )
    # Native Fedora debug/strip steps still run. Its first RPM contains .ko
    # files; the standard OBS continuation signs those bodies, then compresses
    # them and updates the RPM file lists. Compressing before that step would
    # silently leave modules outside the signer's supported input set.
    spec = replace_once(spec, "%global zipmodules 1\n", "%global zipmodules 0\n")
    spec = replace_once(
        spec,
        "  %{__modsign_install_post}\n",
        "  %{__modsign_install_post}\\\n"
        "  python3 %{SOURCE5010} --modules %{buildroot}/lib/modules "
        "--source-manifest %{SOURCE5001} --certificate %{_sourcedir}/_projectcert.crt\\\n"
        "  export BRP_PESIGN_COMPRESS_MODULE=xz\\\n"
        "  /usr/lib/rpm/brp-suse.d/brp-99-pesign "
        "--files '/lib/modules/*/vmlinuz /lib/modules/*/*.ko'\\\n"
        "  test -s %{_topdir}/OTHER/kernel.cpio.rsasign\\\n"
        "  test -s %{_topdir}/OTHER/pesign-repackage.spec\\\n"
        "  python3 %{SOURCE5010} --prepare-signing-continuation "
        "%{_topdir}/OTHER/pesign-repackage.spec\n",
    )
    # This identity belongs to kernel-core, so it survives module subpackage
    # selection and follows the same exact uname-r as its kernel image.
    spec = replace_once(
        spec,
        "/lib/modules/%{KVERREL}%{?3:+%{3}}/vmlinuz\\\n",
        "/lib/modules/%{KVERREL}%{?3:+%{3}}/vmlinuz\\\n"
        "/lib/modules/%{KVERREL}%{?3:+%{3}}/particleve-kernel.json\\\n",
    )
    local = config_text(selected)
    rename = {
        "kernel.spec": "fedora-kernel.recipe",
        "kernel-local": "fedora-kernel-local",
        "sources": "fedora-sources",
    }
    files = {
        rename.get(name, name): {"algorithm": "sha256", "digest": digest, "mode": manifest["git_modes"][name]}
        for name, digest in manifest["git_files"].items()
    }
    files.update(
        {
            name: {"algorithm": "sha512", "digest": digest, "mode": 0o644}
            for name, digest in manifest["lookaside_sha512"].items()
        }
    )
    for name, data in {
        "kernel.recipe": spec.encode(),
        "kernel-local": local.encode(),
        "kernel-policy.json": policy_data,
        "kernelbuild.py": regular(repo / "Sources/particleve/kernelbuild.py"),
        "kernelpayload.py": regular(repo / "Sources/particleve/kernelpayload.py"),
        "fedora-builtin.pem": builtin,
        "secureblue.LICENSE": regular(secureblue / "LICENSE"),
        "secureblue-srpm_script.sh": script.encode(),
        "correct-spectre-flag-behavior.patch": regular(secureblue / "correct-spectre-flag-behavior.patch"),
    }.items():
        require(name not in files, "kernel source input collision")
        files[name] = {"algorithm": "sha256", "digest": sha256(data), "mode": 0o644}
    identity = {
        "schema": 1,
        "upstream": locked,
        "fedora_version": fedora_version(original),
        "configuration": selected,
        "source_files": files,
        "spec_patches": {name: sha256(regular(secureblue / name)) for name in policy["spec_patches"]},
    }
    site = json.loads(regular(repo / ".obs/site.json").decode())
    return {
        "kernel.spec": spec,
        "kernel-local": local,
        "kernel.inputs.json": json.dumps(identity, sort_keys=True, indent=2) + "\n",
        "_service": service_definition(locked, names, site["source_repository"]),
    }


def write_generated(output, files, *, check=False):
    output = Path(output)
    require(set(files) == set(GENERATED), "unexpected generated kernel source files")
    for name, data in files.items():
        path = output / name
        if check:
            require(regular(path).decode() == data, f"generated kernel source is stale: {name}")
        else:
            atomic_write(path, data.encode(), 0o644)
