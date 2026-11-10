"""Test native PE signature authority with ephemeral keys, without booting an image."""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path


def run(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=30, check=True)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_offset(path):
    """Select one code byte; certificate-table edits would not change the digest."""
    data = path.read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe : pe + 4] == b"PE\0\0"
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    sections = pe + 24 + optional_size
    assert 0 < count <= 96 and sections + count * 40 <= len(data)
    for index in range(count):
        offset = sections + index * 40
        if data[offset : offset + 8].rstrip(b"\0") == b".text":
            size, start = struct.unpack_from("<II", data, offset + 16)
            assert size and start + size <= len(data)
            return start
    raise AssertionError("input PE image has no code section")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--efi", type=Path, required=True, help="read-only PE input; never executed")
    args = parser.parse_args()
    source = args.efi.resolve(strict=True)
    assert source.is_file() and 0 < source.stat().st_size <= 256 * 1024 * 1024
    before = sha256(source)
    text_offset(source)
    checks = []
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="particleve-pe-trust-") as temporary:
            directory = Path(temporary)
            certificates = {}
            for name in ("old", "new", "unrelated"):
                key = directory / f"{name}.key"
                certificate = directory / f"{name}.crt"
                run(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-x509",
                        "-newkey",
                        "rsa:4096",
                        "-nodes",
                        "-sha256",
                        "-days",
                        "1",
                        "-subj",
                        f"/CN=ParticleVE disposable {name}/",
                        "-keyout",
                        str(key),
                        "-out",
                        str(certificate),
                    ]
                )
                assert key.stat().st_mode & 0o777 == 0o600
                certificates[name] = certificate
                run(
                    [
                        "sbsign",
                        "--key",
                        str(key),
                        "--cert",
                        str(certificate),
                        "--output",
                        str(directory / f"{name}.efi"),
                        str(source),
                    ]
                )
            run(
                [
                    "sbsign",
                    "--key",
                    str(directory / "new.key"),
                    "--cert",
                    str(certificates["new"]),
                    "--output",
                    str(directory / "overlap.efi"),
                    str(directory / "old.efi"),
                ]
            )

            def verify(image, authority, expected):
                result = subprocess.run(
                    ["sbverify", "--cert", str(certificates[authority]), str(directory / f"{image}.efi")],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                diagnostic = result.stdout + result.stderr
                assert (result.returncode == 0) == expected, (image, authority, diagnostic)
                if expected:
                    assert "Signature verification OK" in diagnostic, diagnostic
                else:
                    assert result.returncode == 1 and (
                        "Signature verification failed" in diagnostic or "Hash doesn't match" in diagnostic
                    ), diagnostic
                checks.append({"image": image, "authority": authority, "accepted": expected})

            for image, authority, expected in (
                ("old", "old", True),
                ("new", "old", False),
                ("overlap", "old", True),
                ("overlap", "new", True),
                ("new", "new", True),
                ("old", "new", False),
                ("unrelated", "old", False),
                ("unrelated", "new", False),
                ("overlap", "unrelated", False),
            ):
                verify(image, authority, expected)
            altered = bytearray((directory / "new.efi").read_bytes())
            altered[text_offset(directory / "new.efi")] ^= 1
            (directory / "tampered.efi").write_bytes(altered)
            verify("tampered", "new", False)
            fingerprints = {
                name: run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"])
                .stdout.strip()
                .split("=", 1)[1]
                for name, path in certificates.items()
            }
        assert sha256(source) == before, "read-only PE input changed"
    finally:
        os.umask(previous_umask)
    print(
        json.dumps(
            {
                "result": "pass",
                "cases": checks,
                "input_sha256": before,
                "certificate_sha256": fingerprints,
                "temporary_keys_removed": not directory.exists(),
                "sbverify_version": run(["sbverify", "--version"]).stdout.strip(),
                "scope": "native PE signatures; no firmware db/dbx, module, TPM or boot acceptance",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
