"""Finalize the native OBS signing pipeline and describe only verified final artifacts."""

import base64
import json
import os
import re
import shutil
import struct
import tempfile
import uuid
from pathlib import Path

from .common import Error, atomic_write, hash_file, read_json, require, run, write_json
from .config import VERITY_SIGNATURE_SIZE, VERSION
from .kernels import verify_modules
from .layout import TYPES, os_label
from .provenance import verify_package, verify_upstream_package
from .release import inspect_uki, validate
from .security import check_privileges, kernel_baseline


def verify_mount_constraints(root, version):
    """The verity-protected constraints must permit the deployed slot geometry."""
    expected = {
        "user.validatefs.mount_point": {b"/usr"},
        "user.validatefs.gpt_label": {os_label(version).encode()},
        "user.validatefs.gpt_type_uuid": {TYPES[kind].encode() for kind in ("usr", "verity", "verity_sig")},
    }
    try:
        names = {name for name in os.listxattr(root) if name.startswith("user.validatefs.")}
        require(names == expected.keys(), "missing or unknown protected filesystem mount constraints")
        for name, values in expected.items():
            value = os.getxattr(root, name)
            # Native repart uses NUL-separated strings, optionally terminated
            # by one NUL. An empty/extra choice must not broaden the contract.
            require(
                0 < len(value) <= 4096 and set(value.removesuffix(b"\0").split(b"\0")) == values,
                "protected filesystem mount constraint differs from installed slots: " + name,
            )
    except OSError as exc:
        raise Error("cannot inspect protected filesystem mount constraints") from exc


def extract_security_metadata(image, destination):
    """Preserve capabilities and prove the extractor/worker can round-trip them."""
    destination = Path(destination)

    def extract(source, target):
        result = run(
            [
                "fsck.erofs",
                f"--extract={target}",
                "--xattrs",
                "--no-preserve-owner",
                "--preserve-perms",
                source,
            ],
            timeout=600,
        )
        require(not result.stderr.strip(), "EROFS metadata extraction diagnostics: " + result.stderr.strip())

    with tempfile.TemporaryDirectory(prefix="particleve-capability-check-", dir=destination.parent) as tmp:
        work = Path(tmp)
        source = work / "source"
        source.mkdir()
        probe = source / "probe"
        probe.write_bytes(b"Non-executable metadata extraction probe\n")
        # A single permitted capability on a non-executable inert file tests
        # metadata handling without executing a privileged program.
        capability = struct.pack("<IIIII", 0x02000001, 1, 0, 0, 0)
        os.setxattr(probe, "security.capability", capability)
        validation = b"/usr"
        os.setxattr(source, "user.validatefs.mount_point", validation)
        result = run(["mkfs.erofs", work / "probe.erofs", source])
        require(not result.stderr.strip(), "EROFS metadata probe diagnostics: " + result.stderr.strip())
        extracted = work / "extracted"
        extract(work / "probe.erofs", extracted)
        require(
            os.getxattr(extracted / "probe", "security.capability") == capability
            and os.getxattr(extracted, "user.validatefs.mount_point") == validation,
            "EROFS extraction lost capability or filesystem-validation metadata",
        )
    extract(image, destination)


def pad_signature_partition(path):
    # The boot parser requires every byte after the JSON object to be NUL. A
    # complete fixed-size payload also clears stale bytes when reusing a slot.
    payload = path.read_bytes().rstrip(b"\0")
    require(0 < len(payload) <= VERITY_SIGNATURE_SIZE, "invalid signature partition payload size")
    atomic_write(path, payload.ljust(VERITY_SIGNATURE_SIZE, b"\0"), 0o644)


def assemble(artifacts, version, root_hash, bootloader, fwupd_efi, verification, sources, output):
    """Build one manifest, after all deferred signatures have been attached."""
    require(VERSION.fullmatch(version), "invalid image version")
    require(verification["tree"] == "usr" and verification["systemd"], "missing image verification")
    manifest = {
        "schema": 1,
        "version": version,
        "architecture": "x86-64",
        "cpu_baseline": "x86-64-v2",
        "fedora": "45",
        "persistent_state": verification["persistent_state"],
        "usr_root_hash": root_hash,
        "sources": sources,
        "packages": verification["packages"],
        "implementation_sha256": verification["implementation_sha256"],
        "package_sources": verification["upstream_inputs"],
        "artifacts": {},
    }
    for kind, suffix in (
        ("usr", "usr-x86-64"),
        ("verity", "usr-x86-64-verity"),
        ("verity_sig", "usr-x86-64-verity-sig"),
    ):
        files = list(artifacts.glob(f"ParticleVE_{version}_x86-64.{suffix}.*.raw"))
        require(len(files) == 1, f"missing/ambiguous final {kind} artifact")
        source = files[0]
        manifest["artifacts"][kind] = {
            "file": source.name,
            "size": source.stat().st_size,
            "sha256": hash_file(source),
            "partition_uuid": str(uuid.UUID(source.name.split(".")[-2])),
        }
        if source.parent != output:
            shutil.copy2(source, output / source.name)
    uki = artifacts / f"ParticleVE_{version}_x86-64.efi"
    for kind, source, name in (
        ("uki", uki, uki.name),
        ("bootloader", bootloader, f"ParticleVE_{version}_x86-64.systemd-bootx64.efi"),
        ("fwupd_efi", fwupd_efi, f"ParticleVE_{version}_x86-64.fwupdx64.efi"),
    ):
        manifest["artifacts"][kind] = {
            "file": name,
            "size": source.stat().st_size,
            "sha256": hash_file(source),
        }
        if source != output / name:
            shutil.copy2(source, output / name)
    validate(manifest)
    return manifest


def carry_signing_hook(output):
    """OBS rebuilds each signing stage from its generated minimal mkosi.conf."""
    config = output / "mkosi.conf"
    require(config.is_file(), "OBS signing stage is missing its continuation recipe")
    ukis = list(output.glob("ParticleVE_*_x86-64.efi"))
    require(len(ukis) == 1, "signing continuation needs one unambiguous PVE image identity")
    version = ukis[0].name.removeprefix("ParticleVE_").removesuffix("_x86-64.efi")
    require(VERSION.fullmatch(version), "invalid signing continuation version")
    atomic_write(output / "particleve.version", (version.rsplit("-", 1)[0] + "\n").encode(), 0o644)
    # Format=none continuations return before postoutput scripts.
    hook = "BuildScripts=/usr/libexec/particleve-obs-postoutput"
    if hook not in config.read_text():
        with config.open("a") as stream:
            stream.write("\n[Content]\n" + hook + "\n\n[Output]\nCompressOutput=no\n")


def postoutput():
    output = Path(os.environ.get("OUTPUTDIR", "/work/src/usr/src/packages/OTHER"))
    if (output / "hashes.cpio.rsasign").exists():
        carry_signing_hook(output)
        return
    # A final stage is complete only after mkosi-obs has attached PCR, PE and verity signatures.
    ukis = list(output.glob("ParticleVE_*_x86-64.efi"))
    require(len(ukis) == 1, "final signing stage must contain exactly one ParticleVE UKI")
    match = re.fullmatch(r"ParticleVE_([0-9.-]+)_x86-64\.efi", ukis[0].name)
    require(match, "invalid final image identity")
    version = match[1]
    usr = list(output.glob(f"ParticleVE_{version}_x86-64.usr-x86-64.*.raw"))
    signatures = list(output.glob(f"ParticleVE_{version}_x86-64.usr-x86-64-verity-sig.*.raw"))
    require(len(usr) == len(signatures) == 1, "final signed partition artifacts missing")
    # OBS's 6.4 worker kernel cannot store user.* xattrs on sandbox tmpfs.
    # Use the file-backed artifact staging filesystem for every final inspection;
    # the canary requires both capability and validatefs metadata there.
    with tempfile.TemporaryDirectory(prefix=".particleve-final-", dir=output) as temporary:
        work = Path(temporary)
        root = work / "usr"
        extract_security_metadata(usr[0], root)
        verify_mount_constraints(root, version)
        verification = read_json(root / "lib/particleve/verification.json")
        view = work / "view"
        view.mkdir()
        (view / "usr").symlink_to(root, target_is_directory=True)
        verify_package(view, "integration", verification["implementation_sha256"])
        verify_package(Path("/"), "build-tools", verification["implementation_sha256"])
        verify_upstream_package(view, "fwupd-efi", verification["upstream_inputs"]["fwupd-efi"])
        verify_upstream_package(Path("/"), "mkosi", verification["upstream_inputs"]["mkosi"])
        require(
            verification["security_baseline"]
            == {"kernel": kernel_baseline(view), "privileged_files": check_privileges(view, image=usr[0])},
            "final image security metadata differs from the verified build",
        )
        kernel_verification = verify_modules(root / "lib/modules")
        build = read_json(root / "lib/particleve/build.json")
        certificate = root / "lib/particleve/trust/secure-boot.crt"
        actual_cert = Path("/usr/src/packages/SOURCES/_projectcert.crt")
        for cert in (certificate, actual_cert):
            require(cert.is_file(), "missing project certificate")
        require(
            run(["openssl", "x509", "-in", certificate, "-outform", "PEM"]).stdout
            == run(["openssl", "x509", "-in", actual_cert, "-outform", "PEM"]).stdout,
            "image trust does not match the OBS signing project",
        )
        signature = json.loads(signatures[0].read_bytes().rstrip(b"\0"))
        root_hash = signature["rootHash"]
        require(re.fullmatch(r"[0-9a-f]{64}", root_hash), "invalid signed verity root hash")
        (work / "roothash").write_text(root_hash)
        (work / "roothash.p7s").write_bytes(base64.b64decode(signature["signature"], validate=True))
        run(
            [
                "openssl",
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                work / "roothash.p7s",
                "-content",
                work / "roothash",
                "-nointern",
                "-certfile",
                certificate,
                "-noverify",
            ]
        )
        disk = output / f"ParticleVE_{version}_x86-64.raw"
        partitions = json.loads(run(["systemd-repart", "--json=short", disk]).stdout)
        esps = [part for part in partitions if part["type"] == "esp"]
        require(len(esps) == 1, "final DDI lacks an unambiguous ESP")
        bootloader = work / "systemd-bootx64.efi"
        run(["mcopy", "-i", f"{disk}@@{esps[0]['offset']}", "::EFI/systemd/systemd-bootx64.efi", bootloader])
        helper = root / "libexec/fwupd/efi/fwupdx64.efi.signed"
        pad_signature_partition(signatures[0])
        manifest = assemble(
            output, version, root_hash, bootloader, helper, verification, build["sources"], output
        )
        manifest["kernel_verification"] = kernel_verification
        for kind in ("uki", "bootloader", "fwupd_efi"):
            run(["sbverify", "--cert", certificate, output / manifest["artifacts"][kind]["file"]])
        inspect_uki(ukis[0], manifest)
        run(
            ["veritysetup", "verify", usr[0], output / manifest["artifacts"]["verity"]["file"], root_hash],
            timeout=600,
        )
        write_json(output / f"ParticleVE_{version}_x86-64.release.json", manifest)
        # Intermediate mkosi checksums precede final signatures. OBS publishes its own signed index.
        for file in output.glob("*.sha256"):
            file.unlink()
        atomic_write(output / "particleve-build-verified", (version + "\n").encode(), 0o644)
