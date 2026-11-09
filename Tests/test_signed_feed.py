"""Exercise the actual GPG trust boundary using a disposable test-only signing identity."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve.common import Error, canonical
from particleve.release import checksums, verify_directory
from Tests.fixtures import release
from Tools.publication import signed_manifest


class SignedFeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.home = Path(cls.temporary.name)
        cls.env = {**os.environ, "GNUPGHOME": str(cls.home)}
        cls.gpg(
            "--passphrase",
            "",
            "--quick-generate-key",
            "ParticleVE test <test@invalid>",
            "ed25519",
            "sign",
            "0",
        )
        cls.keyring = cls.home / "trust.gpg"
        with cls.keyring.open("wb") as stream:
            subprocess.run(["gpg", "--batch", "--export"], env=cls.env, stdout=stream, check=True)

    @classmethod
    def gpg(cls, *args):
        return subprocess.run(
            ["gpg", "--batch", "--yes", *args], env=cls.env, capture_output=True, check=True
        )

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=cls.env, check=True, capture_output=True)
        cls.temporary.cleanup()

    def sign(self, directory, lines):
        index = directory / "SHA256SUMS"
        index.write_text("\n".join(lines) + "\n")
        self.gpg("--armor", "--detach-sign", str(index))

    def test_signed_index_rejects_changes_and_unsafe_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.sign(directory, ["a" * 64 + "  artifact.raw"])
            self.assertEqual(checksums(directory, self.keyring), {"artifact.raw": "a" * 64})
            (directory / "SHA256SUMS").write_text("b" * 64 + "  artifact.raw\n")
            with self.assertRaises(Error):
                checksums(directory, self.keyring)
            for filename in ("../artifact.raw", ".hidden", "/etc/passwd"):
                self.sign(directory, ["a" * 64 + "  " + filename])
                with self.assertRaises(Error):
                    checksums(directory, self.keyring)

    def test_complete_manifest_must_be_bound_to_the_signed_artifact_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = release("45.0.1.2-1.1")
            metadata = directory / "ParticleVE_45.0.1.2-1.1_x86-64.release.json"
            metadata.write_bytes(canonical(manifest))
            entries = [hashlib.sha256(metadata.read_bytes()).hexdigest() + "  " + metadata.name]
            entries += [i["sha256"] + "  " + i["file"] for i in manifest["artifacts"].values()]
            self.sign(directory, entries)
            self.assertEqual(verify_directory(directory, self.keyring, "unused", artifacts=False), manifest)
            self.sign(directory, entries[:-1])
            with self.assertRaises(Error):
                verify_directory(directory, self.keyring, "unused", artifacts=False)
            self.sign(directory, entries)
            metadata.write_bytes(metadata.read_bytes() + b" ")
            with self.assertRaises(Error):
                verify_directory(directory, self.keyring, "unused", artifacts=False)

    def test_publication_monitor_authenticates_metadata_and_rejects_changed_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = release("45.0.1.2-1.1")
            metadata = directory / "ParticleVE_45.0.1.2-1.1_x86-64.release.json"
            metadata.write_bytes(canonical(manifest))
            entries = [hashlib.sha256(metadata.read_bytes()).hexdigest() + "  " + metadata.name]
            entries += [item["sha256"] + "  " + item["file"] for item in manifest["artifacts"].values()]
            self.sign(directory, entries)

            def fetch(url, **_kwargs):
                return (directory / url.rsplit("/", 1)[1]).read_bytes()

            with patch("Tools.publication.request", side_effect=fetch):
                self.assertEqual(signed_manifest("https://example.org", self.keyring, "unused"), manifest)
                (directory / "SHA256SUMS").write_text("b" * 64 + "  " + metadata.name + "\n")
                with self.assertRaises(Error):
                    signed_manifest("https://example.org", self.keyring, "unused")


if __name__ == "__main__":
    unittest.main()
