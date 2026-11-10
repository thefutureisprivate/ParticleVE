"""Exercise release-key introduction and retirement through real native GPG."""

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from particleve.common import Error
from particleve.release import checksums
from Tests.runtime import RustDriverTests


class ReleaseTrustTests(RustDriverTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.temporary = tempfile.TemporaryDirectory(prefix="particleve-release-trust-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.home = cls.directory / "gnupg"
        cls.home.mkdir(mode=0o700)
        cls.environment = os.environ | {"GNUPGHOME": str(cls.home)}
        cls.addClassCleanup(cls.stop_agent)
        cls.keys = {}
        for name in ("old", "new", "unrelated"):
            uid = f"ParticleVE disposable {name} <{name}@example.invalid>"
            cls.gpg("--quick-generate-key", uid, "ed25519", "sign", "1d")
            listing = cls.gpg("--with-colons", "--list-keys", uid).decode()
            cls.keys[name] = next(row.split(":")[9] for row in listing.splitlines() if row.startswith("fpr:"))
        cls.rings = {}
        for name, keys in (
            ("old", ["old"]),
            ("overlap", ["old", "new"]),
            ("new", ["new"]),
        ):
            path = cls.directory / f"{name}.gpg"
            path.write_bytes(cls.gpg("--export", *(cls.keys[key] for key in keys)))
            cls.rings[name] = path
        # Establish a real, otherwise trusted default keyring. The explicitly
        # selected release keyring must remain the only source of authority.
        (cls.home / "trustedkeys.gpg").write_bytes(cls.gpg("--export", cls.keys["unrelated"]))

    @classmethod
    def gpg(cls, *arguments):
        return subprocess.run(
            [
                "gpg",
                "--no-options",
                "--homedir",
                str(cls.home),
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                *arguments,
            ],
            capture_output=True,
            check=True,
            timeout=30,
            env=cls.environment,
        ).stdout

    @classmethod
    def stop_agent(cls):
        subprocess.run(
            ["gpgconf", "--homedir", str(cls.home), "--kill", "all"],
            capture_output=True,
            check=True,
            timeout=15,
            env=cls.environment,
        )

    def sign(self, text, key):
        directory = self.directory / "feed"
        directory.mkdir(exist_ok=True)
        (directory / "SHA256SUMS").write_text(text)
        self.gpg(
            "--armor",
            "--detach-sign",
            "--local-user",
            self.keys[key],
            "--output",
            str(directory / "SHA256SUMS.asc"),
            str(directory / "SHA256SUMS"),
        )
        return directory

    def verify(self, directory, ring, *, accepted):
        paths = {path.name: path.read_bytes() for path in directory.iterdir()}
        response = self.request(
            "release-checksums",
            directory=str(directory),
            keyring=str(self.rings[ring]),
            environment=self.environment,
        )
        if accepted:
            self.assertEqual(response, {"ok": {"artifact.raw": hashlib.sha256(b"artifact").hexdigest()}})
            with mock.patch.dict(os.environ, self.environment, clear=True):
                self.assertEqual(checksums(directory, self.rings[ring]), response["ok"])
        else:
            self.assertIn("error", response)
            with mock.patch.dict(os.environ, self.environment, clear=True), self.assertRaises(Error):
                checksums(directory, self.rings[ring])
        self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, paths)

    def test_introduction_overlap_and_retirement(self):
        text = hashlib.sha256(b"artifact").hexdigest() + "  artifact.raw\n"
        for signer, ring, accepted in (
            ("old", "old", True),
            ("new", "old", False),
            ("old", "overlap", True),
            ("new", "overlap", True),
            ("new", "new", True),
            ("old", "new", False),
        ):
            with self.subTest(signer=signer, ring=ring):
                self.verify(self.sign(text, signer), ring, accepted=accepted)

    def test_default_keyring_cannot_restore_unrelated_authority(self):
        directory = self.sign(hashlib.sha256(b"artifact").hexdigest() + "  artifact.raw\n", "unrelated")
        subprocess.run(
            ["gpgv", str(directory / "SHA256SUMS.asc"), str(directory / "SHA256SUMS")],
            env=self.environment,
            capture_output=True,
            check=True,
            timeout=15,
        )
        for ring in self.rings:
            with self.subTest(ring=ring):
                self.verify(directory, ring, accepted=False)

    def test_tampering_and_unsafe_signed_indices_remain_rejected_during_overlap(self):
        text = hashlib.sha256(b"artifact").hexdigest() + "  artifact.raw\n"
        directory = self.sign(text, "new")
        (directory / "SHA256SUMS").write_text(text.replace("artifact.raw", "changed.raw"))
        self.verify(directory, "overlap", accepted=False)
        for invalid in ("", text + text, text.replace("artifact.raw", "../artifact.raw")):
            with self.subTest(index=invalid):
                self.verify(self.sign(invalid, "new"), "overlap", accepted=False)
