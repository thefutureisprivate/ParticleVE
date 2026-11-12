import contextlib
import io
import json
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from particleve.config import version_key
from particleve.versioning import bump, mkosi_args, source_key, verify_obs_sources
from Tests.fixtures import devices, host, release
from Tests.runtime import RustDriverTests
from Tools.source_releases import ensure_tag, release_plan
from Tools.source_releases import main as publish_releases
from Tools.trust import system_trust_paths


class VersionTests(RustDriverTests):
    def test_fix_feature_and_explicit_major_bumps(self):
        self.assertEqual(bump("45.0.1.1", "patch"), "45.0.1.2")
        self.assertEqual(bump("45.0.1.1", "minor"), "45.0.2.0")
        with self.assertRaisesRegex(ValueError, "owner's explicit approval"):
            bump("45.0.1.1", "major")
        self.assertEqual(bump("45.0.1.1", "major", owner_approved=True), "45.1.0.0")
        self.assertEqual(bump("45.3.4.5", "fedora", fedora=46), "46.3.0.0")

    def test_all_six_numeric_components_order_releases(self):
        versions = [
            "45.0.1.1-87.2",
            "45.0.1.1-87.10",
            "45.0.1.1-88.1",
            "45.0.1.2-1.1",
            "45.0.2.0-1.1",
            "45.1.0.0-1.1",
            "46.0.0.0-1.1",
        ]
        self.assertEqual(sorted(reversed(versions), key=version_key), versions)
        for value in ("87.2", "45.0.1.1-2", "45.0.01.1-87.2", "45.0.1.1-1000000.1", "45.0.1.1-87.2/../x"):
            with self.subTest(value=value), self.assertRaises(Error):
                version_key(value)

    def test_obs_entry_composes_the_example_and_signing_rounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "particleve.version").write_text("45.0.1.1\n")
            arguments = [f"--directory={root}", "--image-version=87.2", "build"]
            self.assertEqual(mkosi_args(arguments)[1], "--image-version=45.0.1.1-87.2")
            self.assertEqual(mkosi_args(mkosi_args(arguments)), mkosi_args(arguments))
            with self.assertRaises(ValueError):
                mkosi_args([f"--directory={root}", "--image-version=45.0.1.2-87.2"])
            (root / "particleve.version").unlink()
            self.assertEqual(mkosi_args(arguments), arguments)

    def test_source_versions_are_canonical_and_bounded(self):
        self.assertEqual(source_key("45.0.1.1"), (45, 0, 1, 1))
        for value in ("45.0.1", "0.0.1.1", "45.00.1.1", "45.0.1.1-1.1", "45.0.1.1000000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                source_key(value)

    def test_long_versions_fit_gpt_and_payload_types_remain_distinct(self):
        value = "45.0.999999.999999-999999.999999"
        version_key(value)
        result = self.evaluate("layout-calculate", config=host(), devices=devices(), release=release(value))
        for disk in result["devices"]:
            parts = [part for part in disk["partitions"] if part["role"].startswith("a_")]
            self.assertEqual({part["label"] for part in parts}, {"PVE_" + value})
            self.assertEqual(len(parts[0]["label"].encode("utf-16-le")), 72)
            self.assertEqual(len({part["type"] for part in parts}), 3)
            self.evaluate("sfdisk-script", device=disk)


class OBSSourceIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.outer = Path(temporary.name)
        self.source = self.outer / "particleve"
        self.source.mkdir()
        (self.source / "particleve.version").write_text("45.0.1.2\n")
        self.bridge = self.outer / "_scmsync.obsinfo"
        self.recipe = self.outer / "rpm.spec"
        self.archive_recipe = self.source / ".obs/particleve/rpm.spec"
        self.archive_recipe.parent.mkdir(parents=True)
        self.bridge.write_text("commit: " + "a" * 40 + "\n")
        (self.outer / "particleve.obsinfo").write_text("commit: " + "b" * 40 + "\n")
        self.recipe.write_text("Version: 45.0.1.2\n")
        self.archive_recipe.write_bytes(self.recipe.read_bytes())

    def test_matching_checkout_retains_native_obs_counters_on_all_signing_rounds(self):
        args = [f"--directory={self.source}", "--image-version=1.3", "build"]
        result = mkosi_args(args)
        self.assertEqual(result[1], "--image-version=45.0.1.2-1.3")
        self.assertEqual(mkosi_args(result), result)

    def test_racing_source_update_is_rejected_on_initial_and_continuation_rounds(self):
        self.recipe.write_text("Version: 45.0.1.1\n")
        for version in ("1.1", "45.0.1.2-1.1"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "differs from"):
                mkosi_args([f"--directory={self.source}", "--image-version=" + version])

    def test_incomplete_mismatched_and_oversized_recipe_fails(self):
        self.archive_recipe.unlink()
        with self.assertRaises(FileNotFoundError):
            verify_obs_sources(self.outer, self.source)
        for content in ("", "Version: 45.0.1.3\n", "x" * 65537):
            with self.subTest(content=content[:40]):
                self.archive_recipe.write_text(content)
                with self.assertRaises(ValueError):
                    verify_obs_sources(self.outer, self.source)
        self.bridge.unlink()
        verify_obs_sources(self.outer, self.source)

    def test_native_rpm_transformations_preserve_version_but_do_not_authorize_the_image_recipe(self):
        self.recipe.write_text("Version: 45.0.1.2\nRelease: 13.1\nBuildRequires: python3\n")
        verify_obs_sources(self.outer, self.source, rpm=True)
        with self.assertRaisesRegex(ValueError, "differs from"):
            mkosi_args([f"--directory={self.source}", "--image-version=1.1"])
        for content in ("", "Version: 45.0.1.2\nVersion: 45.0.1.2\n", "Version: %{source_version}\n"):
            self.recipe.write_text(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                verify_obs_sources(self.outer, self.source, rpm=True)

    def test_rpm_identity_entry_point_rejects_mismatches_before_recording_payloads(self):
        script = Path(__file__).resolve().parents[1] / "Tools/package-identity.py"
        arguments = [
            str(script),
            "--root",
            str(self.outer / "payload"),
            "--source",
            str(self.source),
            "--component",
            "integration",
            "--obs-sources",
            str(self.outer),
        ]
        with patch("sys.argv", arguments), patch("particleve.provenance.record_package") as record:
            self.recipe.write_text("Version: 45.0.1.2\nRelease: 13.1\nBuildRequires: python3\n")
            runpy.run_path(str(script), run_name="__main__")
            record.assert_called_once()
            record.reset_mock()
            self.recipe.write_text("Version: 45.0.1.3\n")
            with self.assertRaisesRegex(ValueError, "differs from"):
                runpy.run_path(str(script), run_name="__main__")
            record.assert_not_called()


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q", "--initial-branch=main")
        (self.root / "README").write_text("disposable upstream fixture\n")
        self.commit("Upstream base")
        base = self.git("rev-parse", "HEAD")
        (self.root / "sources.lock.json").write_text(
            json.dumps({"sources": {"particleos": {"revision": base}}})
        )
        (self.root / "Cargo.lock").write_text("version = 4\n")

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()

    def commit(self, subject):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            subject,
        )

    def version(self, value, subject):
        (self.root / "particleve.version").write_text(value + "\n")
        self.commit(subject)

    def test_each_version_gets_its_own_commit_range(self):
        self.version("45.0.1.1", "Initial PVE version")
        (self.root / "fix").write_text("fix\n")
        self.commit("Fix a boot path")
        self.version("45.0.1.2", "Release the fix")
        self.version("45.0.2.0", "Large feature")
        plan = release_plan(self.root, "owner/repository")
        self.assertEqual([item["tag"] for item in plan], ["v45.0.1.1", "v45.0.1.2", "v45.0.2.0"])
        self.assertNotIn("Upstream base", plan[0]["notes"])
        self.assertIn("Fix a boot path", plan[1]["notes"])
        self.assertNotIn("Initial PVE version", plan[1]["notes"])
        self.assertNotIn("Fix a boot path", plan[2]["notes"])

    def test_reusing_or_decreasing_a_version_cannot_rewrite_release_history(self):
        self.version("45.0.1.2", "Initial PVE version")
        self.version("45.0.1.1", "Accidental downgrade")
        with self.assertRaisesRegex(Error, "must increase"):
            release_plan(self.root, "owner/repository")

    def test_ancillary_changes_are_included_in_the_next_source_release(self):
        self.version("45.0.1.1", "Initial PVE version")
        (self.root / "README").write_text("updated instructions\n")
        self.commit("Improve documentation")
        self.assertEqual(len(release_plan(self.root, "owner/repository")), 1)
        (self.root / "runtime").write_text("system fix\n")
        self.commit("Fix system behavior")
        self.version("45.0.1.2", "Release the system fix")
        plan = release_plan(self.root, "owner/repository")
        self.assertEqual(len(plan), 2)
        self.assertIn("Improve documentation", plan[1]["notes"])
        self.assertIn("Fix system behavior", plan[1]["notes"])

    def test_publication_skips_existing_versions_and_preserves_the_commit_range(self):
        self.version("45.0.1.1", "Initial PVE version")
        self.version("45.0.1.2", "Fix the loader")
        expected = release_plan(self.root, "owner/repository")[1]
        output = self.root / "release-output"
        from Tools import source_releases

        real_run = source_releases.run
        created = []

        def command(arguments, **kwargs):
            if arguments[0] == "gh":
                self.assertEqual(kwargs["env"]["GH_HOST"], "github.com")
                self.assertEqual(kwargs["env"]["SSL_CERT_FILE"], system_trust_paths()["cafile"])
                self.assertEqual(kwargs["env"]["SSL_CERT_DIR"], system_trust_paths()["capath"])
            if arguments[:2] == ["gh", "api"]:
                self.assertEqual(arguments[arguments.index("--hostname") + 1], "github.com")
                if "--paginate" in arguments:
                    return SimpleNamespace(stdout="v45.0.1.1\t41\n")
                if "git/matching-refs/tags/" in arguments[4]:
                    return SimpleNamespace(stdout="[]")
                if arguments[4] == "repos/owner/repository/releases":
                    body = json.loads(kwargs["input"])
                    created.append(body)
                    return SimpleNamespace(
                        stdout=json.dumps({"id": 42, "tag_name": body["tag_name"], "draft": True})
                    )
                self.assertEqual(
                    json.loads(kwargs["input"]), {"ref": "refs/tags/v45.0.1.2", "sha": expected["commit"]}
                )
                return SimpleNamespace(
                    stdout=json.dumps({"object": {"type": "commit", "sha": expected["commit"]}})
                )
            return real_run(arguments, **kwargs)

        with (
            patch.dict(
                os.environ,
                {
                    "SSL_CERT_FILE": "/alternate/cli-ca",
                    "SSL_CERT_DIR": "/alternate/cli-directory",
                    "GH_HOST": "alternate.invalid",
                },
            ),
            patch("Tools.source_releases.Path.cwd", return_value=self.root),
            patch("Tools.source_releases.run", side_effect=command),
            patch("Tools.source_releases.vendor_digest", return_value="sha256:checked"),
            patch("Tools.source_releases.publish_vendor"),
            patch(
                "sys.argv",
                [
                    "source_releases",
                    "--repository",
                    "owner/repository",
                    "--output",
                    str(output),
                    "--publish",
                    "--vendor-archive",
                    "vendor.tar.zst",
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            publish_releases()
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["tag_name"], "v45.0.1.2")
        self.assertNotIn("target_commitish", created[0])
        self.assertTrue(created[0]["draft"])
        self.assertIn("Fix the loader", (output / "v45.0.1.2.md").read_text())

    def test_publication_failure_is_not_recorded_as_a_completed_release(self):
        self.version("45.0.1.1", "Initial PVE version")
        output = self.root / "release-output"
        from Tools import source_releases

        real_run = source_releases.run

        def command(arguments, **kwargs):
            if arguments[:2] == ["gh", "api"]:
                if "--paginate" in arguments:
                    return SimpleNamespace(stdout="")
                raise Error("GitHub unavailable")
            return real_run(arguments, **kwargs)

        with (
            patch("Tools.source_releases.Path.cwd", return_value=self.root),
            patch("Tools.source_releases.run", side_effect=command),
            patch("Tools.source_releases.ensure_tag"),
            patch("Tools.source_releases.vendor_digest", return_value="sha256:checked"),
            patch(
                "sys.argv",
                [
                    "source_releases",
                    "--repository",
                    "owner/repository",
                    "--output",
                    str(output),
                    "--publish",
                    "--vendor-archive",
                    "vendor.tar.zst",
                ],
            ),
            self.assertRaisesRegex(Error, "GitHub unavailable"),
        ):
            publish_releases()
        self.assertFalse((output / "releases.json").exists())

    def test_existing_annotated_tag_is_verified_without_moving_it(self):
        release = {"tag": "v45.0.1.2", "commit": "b" * 40}
        responses = [
            [
                {"ref": "refs/tags/v45.0.1.20", "object": {"type": "commit", "sha": "c" * 40}},
                {"ref": "refs/tags/v45.0.1.2", "object": {"type": "tag", "sha": "a" * 40}},
            ],
            {"object": {"type": "commit", "sha": release["commit"]}},
        ]
        with patch("Tools.source_releases.github", side_effect=responses) as api:
            ensure_tag("owner/repository", release)
        self.assertEqual(api.call_count, 2)
        self.assertTrue(all(len(call.args) == 2 for call in api.call_args_list))

    def test_wrong_existing_remote_tag_is_rejected_without_replacement(self):
        release = {"tag": "v45.0.1.2", "commit": "b" * 40}
        response = [{"ref": "refs/tags/v45.0.1.2", "object": {"type": "commit", "sha": "c" * 40}}]
        with (
            patch("Tools.source_releases.github", return_value=response) as api,
            self.assertRaisesRegex(Error, "another commit"),
        ):
            ensure_tag("owner/repository", release)
        self.assertEqual(api.call_count, 1)

    def test_tag_creation_failure_is_not_treated_as_release_success(self):
        release = {"tag": "v45.0.1.2", "commit": "b" * 40}
        with (
            patch("Tools.source_releases.github", side_effect=[[], Error("GitHub refused tag creation")]),
            self.assertRaisesRegex(Error, "refused tag"),
        ):
            ensure_tag("owner/repository", release)
