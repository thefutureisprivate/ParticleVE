"""Authenticated, immutable, architecture-specific releases in one shared feed."""

import base64
import json
import re
import shlex
import uuid
from pathlib import Path

from .common import hash_file, read_json, require, run
from .config import VERITY_SIGNATURE_SIZE, integer, version_key
from .consoles import SERIAL_CONSOLES, uki_profiles

KINDS = ("usr", "verity", "verity_sig", "uki", "bootloader", "fwupd_efi")


def validate(manifest):
    require(manifest.get("schema") == 1, "release schema must be 1")
    require(manifest["architecture"] == "x86-64", "release architecture mismatch")
    require(manifest["cpu_baseline"] == "x86-64-v2", "release CPU baseline mismatch")
    version = version_key(manifest["version"])
    require(manifest["fedora"] == "45", "release must be Fedora 45")
    require(str(version[0]) == manifest["fedora"], "release version and Fedora base differ")
    require(
        isinstance(manifest["persistent_state"], dict) and manifest["persistent_state"],
        "declare the retained-OS filesystem and VM auxiliary-state contract",
    )
    if "implementation_sha256" in manifest:
        require(
            re.fullmatch(r"[0-9a-f]{64}", manifest["implementation_sha256"]),
            "invalid implementation content identity",
        )
    require(re.fullmatch(r"[0-9a-f]{64}", manifest["usr_root_hash"]), "invalid usr verity root hash")
    for revision in ("particleos", "mkosi"):
        require(
            re.fullmatch(r"[0-9a-f]{40}", manifest["sources"][revision]), f"unresolved source pin: {revision}"
        )
    require(set(manifest["artifacts"]) == set(KINDS), "incomplete artifact set")
    for kind in KINDS:
        item = manifest["artifacts"][kind]
        require(
            re.fullmatch(r"[A-Za-z0-9_.+-]+", item["file"]) and not item["file"].startswith("."),
            "artifact names must be plain filenames",
        )
        require(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "invalid artifact hash")
        integer(item["size"], 1, f"{kind} size")
        if kind == "verity_sig":
            require(
                item["size"] == VERITY_SIGNATURE_SIZE,
                "signature payload must completely cover its fixed 1 MiB partition",
            )
        if kind in ("usr", "verity", "verity_sig"):
            require(
                str(uuid.UUID(item["partition_uuid"])) == item["partition_uuid"], "invalid partition UUID"
            )
    require(
        len({i["file"] for i in manifest["artifacts"].values()}) == len(KINDS), "duplicate artifact filenames"
    )
    root_hash = manifest["usr_root_hash"]
    require(
        uuid.UUID(manifest["artifacts"]["usr"]["partition_uuid"]).hex == root_hash[:32],
        "usr UUID does not match verity root hash",
    )
    require(
        uuid.UUID(manifest["artifacts"]["verity"]["partition_uuid"]).hex == root_hash[32:],
        "verity UUID does not match verity root hash",
    )
    return manifest


def checksums(directory, keyring):
    directory = Path(directory)
    run(["gpgv", "--keyring", keyring, directory / "SHA256SUMS.asc", directory / "SHA256SUMS"])
    result = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](?:\./)?([A-Za-z0-9_+.-]+)", line)
        require(match and not match[2].startswith("."), "unsafe signed checksum entry")
        require(match[2] not in result, "duplicate signed checksum entry")
        result[match[2]] = match[1]
    require(result, "signed feed index is empty")
    return result


def verify_directory(directory, keyring, certificate, *, artifacts=True):
    directory = Path(directory)
    index = checksums(directory, keyring)
    files = list(directory.glob("ParticleVE_*_x86-64.release.json"))
    require(len(files) == 1, "select exactly one authenticated release manifest")
    metadata = files[0]
    require(
        metadata.name in index and hash_file(metadata) == index[metadata.name],
        "release metadata hash mismatch",
    )
    manifest = validate(read_json(metadata))
    require(
        metadata.name == f"ParticleVE_{manifest['version']}_x86-64.release.json",
        "release metadata identity mismatch",
    )
    for kind, item in manifest["artifacts"].items():
        require(index.get(item["file"]) == item["sha256"], "release artifact missing from signed OBS index")
        if artifacts:
            path = directory / item["file"]
            require(path.is_file() and not path.is_symlink(), f"artifact missing: {path}")
            require(
                path.stat().st_size == item["size"] and hash_file(path) == item["sha256"],
                f"artifact hash/size mismatch: {kind}",
            )
            if kind in ("uki", "bootloader", "fwupd_efi"):
                run(["sbverify", "--cert", certificate, path])
    if artifacts:
        inspect_uki(directory / manifest["artifacts"]["uki"]["file"], manifest)
    return manifest


def inspect_uki(path, manifest):
    response = run(["/usr/lib/systemd/ukify", "--json=short", "inspect", path])
    require(not response.stderr.strip(), "UKI inspection produced diagnostics")
    sections = json.loads(response.stdout)

    def text(section):
        require(
            type(section) is dict and type(section.get("text")) is str, "invalid or duplicate UKI section"
        )
        return section["text"].strip("\x00 \n")

    osrel = text(sections[".osrel"])
    values = dict(line.split("=", 1) for line in osrel.splitlines() if "=" in line)
    require(values["IMAGE_ID"].strip('"') == "ParticleVE", "UKI image identity mismatch")
    require(values["IMAGE_VERSION"].strip('"') == manifest["version"], "UKI version mismatch")
    cmdline = text(sections[".cmdline"]).split()
    for expected in (
        f"usrhash={manifest['usr_root_hash']}",
        "audit=1",
        "enforcing=1",
        "zswap.enabled=1",
        "systemd.ssh_auto=no",
        "kvm_intel.nested=0",
        "kvm_amd.nested=0",
        "rfkill.default_state=0",
    ):
        key = expected.split("=", 1)[0]
        require(
            [word for word in cmdline if word.split("=", 1)[0] == key] == [expected],
            "UKI security command line differs: " + key,
        )
    require(
        [word for word in cmdline if word.startswith("console=")] == ["console=tty0"],
        "base UKI recovery console differs",
    )
    expected_profiles = [{"ID": "main"}, *(p["Profile"] for p in uki_profiles())]
    profiles = sections.get("_profiles")
    require(type(profiles) is list and len(profiles) == len(expected_profiles), "UKI console profiles differ")
    policies = set()
    for index, (profile, expected) in enumerate(zip(profiles, expected_profiles, strict=True)):
        require(
            set(profile) == {".profile", ".pcrsig", *([".cmdline"] if index else [])},
            "unexpected UKI profile override or missing PCR signature",
        )
        metadata = shlex.split(text(profile[".profile"]))
        require(
            len(metadata) == len(expected) and dict(word.split("=", 1) for word in metadata) == expected,
            "UKI profile identity/order differs",
        )
        if index:
            require(
                text(profile[".cmdline"]).split() == [*cmdline, SERIAL_CONSOLES[expected["ID"]]],
                "UKI console profile changes other kernel arguments",
            )
        signature = json.loads(text(profile[".pcrsig"]))
        require(set(signature) == {"sha256"} and signature["sha256"], "UKI lacks SHA256 PCR authorization")
        for entry in signature["sha256"]:
            require(
                11 in entry.get("pcrs", [])
                and re.fullmatch(r"[0-9a-f]{64}", entry.get("pol", ""))
                and re.fullmatch(r"[0-9a-f]{64}", entry.get("pkfp", ""))
                and len(base64.b64decode(entry.get("sig", ""), validate=True)) == 512,
                "UKI profile lacks a complete RSA4096 PCR signature",
            )
            # The initrd-only authorization can share a digest with a different PolicyRef.
            policy = (entry["pol"], entry.get("ref"))
            require(policy not in policies, "UKI profiles reuse a PCR policy")
            policies.add(policy)
