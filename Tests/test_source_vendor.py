import hashlib
import io
import tarfile
import tempfile
import unittest
from compression import zstd
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from Tools.source_releases import main as publish_releases
from Tools.source_releases import publish_vendor, vendor_digest
from Tools.trust import system_trust_paths


class SourceVendorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / "vendor.tar.zst"
        self.lock = b"version = 4\r\n"
        self.release = {"tag": "v45.0.2.6"}

    def write_archive(self, *, duplicate=False, link=False):
        with tarfile.open(self.archive, "w:zst") as output:
            for _ in range(2 if duplicate else 1):
                entry = tarfile.TarInfo("Cargo.lock")
                entry.size = len(self.lock)
                if link:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "another-lock"
                    entry.size = 0
                output.addfile(entry, io.BytesIO(self.lock) if not link else None)

    def asset(self, digest, state="uploaded"):
        return {"assets": [{"name": "vendor.tar.zst", "state": state, "digest": digest}]}

    def test_digest_binds_exact_lock_bytes_and_archive(self):
        self.write_archive()
        expected = "sha256:" + hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(vendor_digest(self.archive, self.lock), expected)
        with self.assertRaisesRegex(Error, "another lockfile"):
            vendor_digest(self.archive, self.lock.replace(b"\r\n", b"\n"))

    def test_duplicate_and_link_lockfiles_are_rejected(self):
        for options in ({"duplicate": True}, {"link": True}):
            with self.subTest(options=options):
                self.write_archive(**options)
                with self.assertRaisesRegex(Error, "exactly one bounded lockfile"):
                    vendor_digest(self.archive, self.lock)

    def test_oversized_entry_is_rejected_before_reading_its_payload(self):
        entry = tarfile.TarInfo("vendor/oversized")
        entry.size = 64 * 1024**2 + 1
        self.archive.write_bytes(zstd.compress(entry.tobuf() + bytes(1024)))
        with self.assertRaisesRegex(Error, "expands beyond"):
            vendor_digest(self.archive, self.lock)

    def test_matching_existing_asset_is_reused_without_upload(self):
        with (
            patch("Tools.source_releases.github", return_value=self.asset("sha256:checked")),
            patch("Tools.source_releases.run") as command,
        ):
            publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
        command.assert_not_called()

    def test_mismatched_or_incomplete_existing_asset_is_never_replaced(self):
        for asset in (self.asset("sha256:other"), self.asset("sha256:checked", "starter")):
            with (
                self.subTest(asset=asset),
                patch("Tools.source_releases.github", return_value=asset),
                patch("Tools.source_releases.run") as command,
                self.assertRaisesRegex(Error, "does not match"),
            ):
                publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
            command.assert_not_called()

    def test_upload_uses_system_trust_and_verifies_server_digest(self):
        with (
            patch(
                "Tools.source_releases.github",
                side_effect=[{"assets": []}, self.asset("sha256:checked")],
            ),
            patch("Tools.source_releases.run") as command,
        ):
            publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[:4], ["gh", "release", "upload", self.release["tag"]])
        self.assertNotIn("--clobber", arguments)
        self.assertEqual(arguments[-1], "github.com/owner/repository")
        self.assertEqual(command.call_args.kwargs["env"]["SSL_CERT_FILE"], system_trust_paths()["cafile"])

    def test_failed_or_mismatched_upload_does_not_succeed(self):
        for response in ({"assets": []}, self.asset("sha256:other")):
            with (
                self.subTest(response=response),
                patch("Tools.source_releases.github", side_effect=[{"assets": []}, response]),
                patch("Tools.source_releases.run"),
                self.assertRaises(Error),
            ):
                publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")

    def test_wrong_lock_aborts_before_any_release_publication(self):
        self.write_archive()
        with (
            patch("Tools.source_releases.release_plan", return_value=[{"commit": "a" * 40}]),
            patch("Tools.source_releases.git", return_value=SimpleNamespace(stdout=b"other lock\n")),
            patch("Tools.source_releases.github") as api,
            patch(
                "sys.argv",
                [
                    "source_releases",
                    "--repository",
                    "owner/repository",
                    "--publish",
                    "--vendor-archive",
                    str(self.archive),
                ],
            ),
            self.assertRaisesRegex(Error, "another lockfile"),
        ):
            publish_releases()
        api.assert_not_called()
