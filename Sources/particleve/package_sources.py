"""Standalone RPM source/payload identities; also used by image verification.

This module uses only the standard library so pinned upstream packages can build
without depending on the integration RPM that they help build.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

COMPONENTS = {"mkosi": "mkosi", "fwupd-efi": "fwupd_efi", "hardened_malloc": "hardened_malloc"}
SPEC_PATHS = {
    "mkosi": ".obs/mkosi/mkosi.spec",
    "fwupd-efi": ".obs/fwupd-efi/fwupd-efi.spec",
    "hardened_malloc": ".obs/particleve/allocator.spec",
}


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity(source, component, *, rpm_sources=False):
    source = Path(source)
    pin = json.loads((source / "sources.lock.json").read_text())["sources"][COMPONENTS[component]]
    spec_name = SPEC_PATHS[component]

    def path(name):
        if rpm_sources and name == spec_name:
            return source / f"{component}.recipe"
        return source / (Path(name).name if rpm_sources else name)

    spec = path(spec_name).read_text()
    revision = re.search(r"^%global upstream_commit ([0-9a-f]{40})$", spec, re.M)
    if not revision or revision[1] != pin["revision"]:
        raise ValueError(f"{component} recipe does not match its locked upstream revision")
    version = re.search(r"^Version:\s+(\S+)\s*$", spec, re.M)
    if not version or version[1] != pin["version"]:
        raise ValueError(f"{component} recipe does not match its locked upstream version")
    url = re.search(r"^Source0:\s+(\S+)\s*$", spec, re.M)
    expected = pin["url"].removesuffix(".git") + "/archive/" + pin["revision"] + ".tar.gz"
    if not url or url[1].replace("%{upstream_commit}", pin["revision"]) != expected:
        raise ValueError(f"{component} source URL does not match its lock")
    patches = [p.strip() for p in re.findall(r"^[ \t]*Patch[0-9]*[ \t]*:[ \t]*(.*)$", spec, re.M | re.I)]
    if any(not re.fullmatch(r"[A-Za-z0-9_.+-]+\.patch", name) for name in patches):
        raise ValueError("upstream patches must be explicit local filenames")
    names = [
        spec_name,
        "Sources/particleve/package_sources.py",
        *(str(Path(spec_name).parent / p) for p in patches),
    ]
    if component == "hardened_malloc":
        names.extend(
            [
                ".obs/particleve/hardened_malloc.allowed_signers",
                "Tests/acceptance/allocator/chacha-boundaries.c",
            ]
        )
    if component == "mkosi":
        names.append(".obs/mkosi/mkosi-entrypoint.py")
    for name in names:
        if path(name).is_symlink() or not path(name).is_file():
            raise ValueError(f"missing regular source input: {name}")
    return {
        "schema": 1,
        "component": component,
        "upstream": pin,
        "inputs": {name: sha256(path(name)) for name in sorted(names)},
    }


def identity_path(component):
    if component not in COMPONENTS:
        raise ValueError("unknown upstream package component")
    return f"usr/lib/particleve/source-identities/{component}.json"


def payload_paths(root, component):
    root = Path(root)
    if component == "mkosi":
        entries = [*root.glob("usr/bin/mkosi*"), *root.glob("usr/lib*/python*/site-packages/mkosi*")]
        required = root / "usr/bin/mkosi"
    elif component == "fwupd-efi":
        entries = [
            *root.glob("usr/libexec/fwupd/efi/fwupdx64.efi*"),
            *root.glob("usr/lib*/pkgconfig/fwupd-efi.pc"),
        ]
        required = root / "usr/libexec/fwupd/efi/fwupdx64.efi"
    elif component == "hardened_malloc":
        entries = [root / "usr/lib64/libhardened_malloc.so", root / "usr/share/hardened_malloc/default.mk"]
        required = root / "usr/lib64/libhardened_malloc.so"
    else:
        raise ValueError("unknown upstream package component")
    if not required.is_file() or required.is_symlink():
        raise ValueError(f"missing upstream package executable: {required}")
    files = set()
    for entry in entries:
        for path in (entry, *(entry.rglob("*") if entry.is_dir() and not entry.is_symlink() else ())):
            if path.is_file() or path.is_symlink():
                files.add(path.relative_to(root).as_posix())
    return sorted(files)


def payload_value(path):
    if path.is_symlink():
        return {"link": os.readlink(path)}
    if path.name == "fwupdx64.efi":
        # Authenticode excludes the checksum and certificate table changed by
        # off-host PE signing. Certificate trust is checked separately by sbverify.
        result = subprocess.run(
            ["pesign", "--hash", "--padding", "--digest-type=sha256", "--in", str(path)],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
            env={**os.environ, "LC_ALL": "C"},
        )
        hashes = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", result.stdout)
        if result.stderr.strip() or len(hashes) != 1:
            raise ValueError(f"unexpected Authenticode hash diagnostic: {result.stderr or result.stdout}")
        return {"authenticode_sha256": hashes[0].lower()}
    return {"sha256": sha256(path)}


def record_package(root, source, component, revision):
    root = Path(root)
    identity = source_identity(source, component, rpm_sources=True)
    if identity["upstream"]["revision"] != revision:
        raise ValueError("resolved RPM upstream revision differs from its source identity")
    record = {
        "source": identity,
        "files": {name: payload_value(root / name) for name in payload_paths(root, component)},
    }
    destination = root / identity_path(component)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    destination.chmod(0o644)
    return record


def verify_package(root, component, expected):
    root = Path(root)
    record = json.loads((root / identity_path(component)).read_text())
    if record.get("source") != expected:
        raise ValueError(f"{component} RPM does not match the expected source and patches")
    files = record.get("files")
    if not isinstance(files, dict) or set(files) != set(payload_paths(root, component)):
        raise ValueError(f"incomplete {component} package payload identity")
    for name, value in files.items():
        if payload_value(root / name) != value:
            raise ValueError(f"installed {component} payload does not match its identity: {name}")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--rpm-sources", type=Path, required=True)
    parser.add_argument("--component", choices=COMPONENTS, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    record_package(args.root, args.rpm_sources, args.component, args.revision)


if __name__ == "__main__":
    main()
