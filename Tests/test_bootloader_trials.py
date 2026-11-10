"""Check the compiled EFI trial wire identity; lifecycle faults are Rust tests."""

import struct
import tempfile
import uuid
from pathlib import Path

from Tests.runtime import RustDriverTests


class LoaderIdentityTests(RustDriverTests):
    def test_loader_path_accepts_only_canonical_sha256(self):
        sha = "a" * 64
        self.assertEqual(self.evaluate("loader-path", sha256=sha), f"EFI/ParticleVE/loaders/{sha}.efi")
        for value in ("", "A" * 64, "a" * 63, "../" + "a" * 64, "g" * 64):
            self.assertIn("error", self.request("loader-path", sha256=value))

    def test_firmware_option_ownership_binds_description_path_and_esp(self):
        sha, esp = "a" * 64, uuid.uuid4()
        loader = f"\\EFI\\ParticleVE\\loaders\\{sha}.efi\0".encode("utf-16-le")
        label = f"ParticleVE trial {sha}\0".encode("utf-16-le")
        payload = struct.pack("<IIH", 7, 1, len(loader) + 16) + label + esp.bytes_le + loader
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Boot00AF"
            path.write_bytes(payload)
            self.assertTrue(
                self.evaluate("loader-owned-entry", path=str(path), sha256=sha, esp_uuid=str(esp))
            )
            self.assertFalse(
                self.evaluate("loader-owned-entry", path=str(path), sha256=sha, esp_uuid=str(uuid.uuid4()))
            )
            self.assertFalse(
                self.evaluate("loader-owned-entry", path=str(path), sha256="b" * 64, esp_uuid=str(esp))
            )
            for malformed in (b"", bytes(11), bytes(10) + b"x\0" * 8):
                path.write_bytes(malformed)
                self.assertIn(
                    "error", self.request("loader-owned-entry", path=str(path), sha256=sha, esp_uuid=str(esp))
                )
