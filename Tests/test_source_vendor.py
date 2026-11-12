import contextlib
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from compression import zstd
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from Tools.source_releases import main as publish_releases
from Tools.source_releases import publish_vendor, release_id, vendor_digest
from Tools.trust import system_trust_paths


class SourceVendorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / "vendor.tar.zst"
        self.lock = b"version = 4\r\n"
        self.release = {"tag": "v45.0.2.6"}
        lookup = patch("Tools.source_releases.release_id", return_value="42")
        lookup.start()
        self.addCleanup(lookup.stop)

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

    def asset(self, digest, state="uploaded", *, draft=False):
        return {"draft": draft, "assets": [{"name": "vendor.tar.zst", "state": state, "digest": digest}]}

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
                side_effect=[
                    {"draft": True, "assets": []},
                    self.asset("sha256:checked", draft=True),
                    self.asset("sha256:checked"),
                ],
            ),
            patch("Tools.source_releases.run") as command,
        ):
            publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
        arguments = command.call_args_list[0].args[0]
        self.assertEqual(arguments[:4], ["gh", "release", "upload", self.release["tag"]])
        self.assertNotIn("--clobber", arguments)
        self.assertEqual(arguments[-1], "github.com/owner/repository")
        self.assertEqual(command.call_args.kwargs["env"]["SSL_CERT_FILE"], system_trust_paths()["cafile"])
        self.assertEqual(command.call_count, 2)
        self.assertIn("--draft=false", command.call_args.args[0])
        self.assertIn("--latest", command.call_args.args[0])

    def test_failed_or_mismatched_upload_does_not_succeed(self):
        for response in ({"draft": True, "assets": []}, self.asset("sha256:other")):
            with (
                self.subTest(response=response),
                patch("Tools.source_releases.github", side_effect=[{"draft": True, "assets": []}, response]),
                patch("Tools.source_releases.run") as command,
                self.assertRaises(Error),
            ):
                publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][2], "upload")

    def test_published_release_without_asset_cannot_be_mutated(self):
        with (
            patch("Tools.source_releases.github", return_value={"draft": False, "assets": []}),
            patch("Tools.source_releases.run") as command,
            self.assertRaisesRegex(Error, "before publishing an immutable release"),
        ):
            publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
        command.assert_not_called()

    def test_completed_draft_upload_is_resumed_without_reupload(self):
        with (
            patch(
                "Tools.source_releases.github",
                side_effect=[self.asset("sha256:checked", draft=True), self.asset("sha256:checked")],
            ) as api,
            patch("Tools.source_releases.run") as command,
        ):
            publish_vendor("owner/repository", self.release, self.archive, "sha256:checked")
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][2], "edit")
        self.assertTrue(all(call.args[1] == "releases/42" for call in api.call_args_list))

    def test_draft_lookup_uses_paginated_list_and_exact_tag(self):
        with patch("Tools.source_releases.run", return_value=SimpleNamespace(stdout="42\n")) as command:
            self.assertEqual(release_id("owner/repository", self.release["tag"]), "42")
        arguments = command.call_args.args[0]
        self.assertIn("--paginate", arguments)
        self.assertIn('select(.tag_name == "v45.0.2.6")', arguments[-1])
        self.assertEqual(arguments[-3], "repos/owner/repository/releases")

    def test_missing_or_ambiguous_release_id_stops_publication(self):
        for response in ("", "41\n42\n", "not-an-id\n", "0\n"):
            with (
                self.subTest(response=response),
                patch("Tools.source_releases.run", return_value=SimpleNamespace(stdout=response)),
                self.assertRaisesRegex(Error, "missing or ambiguous"),
            ):
                release_id("owner/repository", self.release["tag"])

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

    def test_publication_requires_dependency_archive_before_any_remote_call(self):
        with (
            patch("Tools.source_releases.run") as command,
            patch("sys.argv", ["source_releases", "--repository", "owner/repository", "--publish"]),
            self.assertRaisesRegex(Error, "requires --vendor-archive"),
        ):
            publish_releases()
        command.assert_not_called()

    def publication(self, *, existing=False, fail=False):
        self.write_archive()
        release = {**self.release, "version": "45.0.2.6", "commit": "a" * 40, "notes": "Changes\n"}
        events = []
        output = self.archive.parent / "release-output"
        stdout = io.StringIO()

        def command(arguments, **options):
            if arguments[:2] == ["gh", "api"]:
                self.assertIn("--paginate", arguments)
                self.assertEqual(arguments[-1], ".[] | .tag_name")
                return SimpleNamespace(stdout=release["tag"] + "\n" if existing else "")
            self.assertEqual(arguments[:3], ["gh", "release", "create"])
            self.assertIn("--draft", arguments)
            self.assertIn("--latest=false", arguments)
            events.append("create-draft")
            return SimpleNamespace(stdout="draft created")

        def git(_root, *arguments, **options):
            if arguments[0] == "show":
                self.assertFalse(options["text"])
                return SimpleNamespace(stdout=self.lock)
            return SimpleNamespace(stdout="", returncode=1)

        def finish(*_arguments):
            events.append("verify-assets-and-publish")
            if fail:
                raise Error("publication incomplete")

        with (
            contextlib.redirect_stdout(stdout),
            patch("Tools.source_releases.release_plan", return_value=[release]),
            patch("Tools.source_releases.git", side_effect=git),
            patch("Tools.source_releases.ensure_tag"),
            patch("Tools.source_releases.run", side_effect=command),
            patch("Tools.source_releases.publish_vendor", side_effect=finish),
            patch(
                "sys.argv",
                [
                    "source_releases",
                    "--repository",
                    "owner/repository",
                    "--publish",
                    "--vendor-archive",
                    str(self.archive),
                    "--output",
                    str(output),
                ],
            ),
        ):
            if fail:
                with self.assertRaisesRegex(Error, "publication incomplete"):
                    publish_releases()
            else:
                publish_releases()
        self.assertEqual((output / "releases.json").exists(), not fail)
        if not fail:
            self.assertTrue(json.loads(stdout.getvalue())["published"])
        return events

    def test_new_release_is_created_as_draft_before_assets_are_published(self):
        self.assertEqual(self.publication(), ["create-draft", "verify-assets-and-publish"])

    def test_existing_draft_is_resumed_without_duplicate_release_creation(self):
        self.assertEqual(self.publication(existing=True), ["verify-assets-and-publish"])

    def test_failed_draft_publication_has_no_completed_release_record(self):
        self.assertEqual(self.publication(fail=True), ["create-draft", "verify-assets-and-publish"])
