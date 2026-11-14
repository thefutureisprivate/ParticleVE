import io
import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from particleve.common import Error
from Tools.obs_refresh import API, MARKERS, NoRedirect, component_changed, credentials, refresh, request


class Response(io.BytesIO):
    status = 200


class OBSRefreshTests(unittest.TestCase):
    candidate = "a" * 40

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".obs").mkdir()
        (self.root / ".obs/site.json").write_text(
            json.dumps(
                {
                    "source_repository": "https://github.com/owner/ParticleVE.git",
                    "source_branch": "build",
                    "obs_project": "home:owner:particleve",
                }
            )
        )
        self.tokens = {package: str(index) * 32 for index, package in enumerate(MARKERS, 1)}
        self.raw = json.dumps(self.tokens)
        self.calls = []
        self.stale = set()
        self.running = set()
        self.component_difference = 1

    def open(self, req, *, timeout):
        self.assertEqual(timeout, 20)
        self.calls.append(req)
        self.assertEqual(urlsplit(req.full_url).netloc, "api.opensuse.org")
        if req.get_method() == "POST":
            self.assertEqual(req.full_url, API + "/trigger/runservice")
            return Response(b'<status code="ok"/>')
        self.assertIsNone(req.get_header("Authorization"))
        path = unquote(urlsplit(req.full_url).path).split("/")
        package = path[4]
        if len(path) == 5:
            code = "running" if package in self.running else "succeeded"
            entries = "".join(f'<entry name="{name}"/>' for name in MARKERS[package])
            return Response(f'<directory><serviceinfo code="{code}"/>{entries}</directory>'.encode())
        commit = "b" * 40 if (package, path[5]) in self.stale else self.candidate
        return Response(f"name: fixture\ncommit: {commit}\n".encode())

    def run_refresh(self, *, selected=None, raw=None):
        def git(root, *arguments, **options):
            return SimpleNamespace(
                stdout=self.candidate + "\n",
                returncode=self.component_difference if arguments[0] == "diff" else 0,
            )

        with (
            patch("Tools.obs_refresh.git", side_effect=git),
            patch(
                "Tools.obs_refresh.github",
                return_value={"object": {"type": "commit", "sha": selected or self.candidate}},
            ),
            patch("Tools.obs_refresh.urllib.request.build_opener", return_value=self),
        ):
            return refresh(self.root, "owner/ParticleVE", self.candidate, self.raw if raw is None else raw)

    def test_ancillary_commit_uses_no_obs_credential_or_network(self):
        result = self.run_refresh(selected="b" * 40, raw="")
        self.assertFalse(result["selected"])
        self.assertEqual(result["packages"], {})
        self.assertEqual(self.calls, [])

    def test_completed_delivery_is_idempotent_on_workflow_retry(self):
        result = self.run_refresh()
        self.assertEqual(set(result["packages"].values()), {"current"})
        self.assertTrue(self.calls)
        self.assertTrue(all(req.get_method() == "GET" for req in self.calls))

    def test_only_stale_packages_receive_their_scoped_tokens(self):
        self.stale = {("kernel", MARKERS["kernel"][1]), ("fwupd-efi", MARKERS["fwupd-efi"][0])}
        result = self.run_refresh()
        posts = [req for req in self.calls if req.get_method() == "POST"]
        self.assertEqual(
            [req.get_header("Authorization") for req in posts],
            ["Token " + self.tokens[package] for package in ("kernel", "fwupd-efi")],
        )
        self.assertEqual(
            result["packages"],
            {"particleve": "current", "kernel": "requested", "mkosi": "current", "fwupd-efi": "requested"},
        )
        self.assertNotIn(self.tokens["kernel"], json.dumps(result))

    def test_runtime_update_does_not_restart_unchanged_kernel_or_tools(self):
        self.stale = {(package, marker) for package, markers in MARKERS.items() for marker in markers}
        self.component_difference = 0
        result = self.run_refresh()
        posts = [req for req in self.calls if req.get_method() == "POST"]
        self.assertEqual(
            [req.get_header("Authorization") for req in posts], ["Token " + self.tokens["particleve"]]
        )
        self.assertEqual(result["packages"]["kernel"], "current")

    def test_native_component_comparison_keeps_kernel_independent_of_host_releases(self):
        env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}

        def git(*arguments):
            return subprocess.run(
                ["git", "-C", str(self.root), *arguments],
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            ).stdout.strip()

        def commit():
            git("add", ".")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "Fixture update",
            )
            return git("rev-parse", "HEAD")

        git("init", "-q", "--initial-branch=main")
        kernel = self.root / ".obs/kernel/kernel.inputs.json"
        kernel.parent.mkdir()
        kernel.write_text("reviewed kernel inputs\n")
        worker = kernel.parent / "build-policy.spec"
        worker.write_text("Name: particleve-kernel-build\nVersion: 1\n")
        host = self.root / ".obs/particleve/particleve.spec"
        host.parent.mkdir()
        host.write_text("Name: particleve\nVersion: 45.0.3.5\n")
        cargo = self.root / "Cargo.lock"
        cargo.write_text("first runtime lock\n")
        base = commit()
        cargo.write_text("updated runtime lock\n")
        host.write_text("Name: particleve\nVersion: 45.0.3.6\n")
        updated = commit()
        for package in ("kernel", "mkosi", "fwupd-efi"):
            self.assertFalse(component_changed(self.root, package, base, updated))
        self.assertTrue(component_changed(self.root, "particleve", base, updated))
        kernel.write_text("new reviewed kernel inputs\n")
        selected = commit()
        self.assertTrue(component_changed(self.root, "kernel", base, selected))
        self.assertTrue(component_changed(self.root, "kernel", "f" * 40, selected))
        worker.write_text("Name: particleve-kernel-build\nVersion: 2\n")
        self.assertTrue(component_changed(self.root, "kernel", selected, commit()))

    def test_in_flight_delivery_does_not_force_another_revision(self):
        self.stale = {("particleve", MARKERS["particleve"][0])}
        self.running = {"kernel"}
        with self.assertRaisesRegex(Error, "already running"):
            self.run_refresh()
        self.assertTrue(all(req.get_method() == "GET" for req in self.calls))

    def test_bad_credentials_fail_before_any_obs_request(self):
        bad = [
            "",
            "x" * 8193,
            "null",
            "[]",
            "{",
            '{"kernel":"one","kernel":"two"}',
            json.dumps(self.tokens | {"other": "a" * 32}),
            json.dumps(dict.fromkeys(MARKERS, "a" * 32)),
            json.dumps(self.tokens | {"kernel": "newline\n"}),
        ]
        for raw in bad:
            with self.subTest(raw_length=len(raw)), self.assertRaises(Error):
                self.run_refresh(raw=raw)
        self.assertEqual(self.calls, [])
        self.assertEqual(credentials(self.raw), self.tokens)

    def test_redirects_and_http_error_bodies_cannot_disclose_credentials(self):
        with self.assertRaisesRegex(Error, "redirects are refused"):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example/")
        failure = urllib.error.HTTPError(
            API + "/trigger/runservice", 401, "denied", {}, io.BytesIO(self.raw.encode())
        )
        with (
            patch.object(self, "open", side_effect=failure),
            self.assertRaisesRegex(Error, "HTTP 401") as caught,
        ):
            request(self, "/trigger/runservice", self.tokens["kernel"])
        self.assertNotIn(self.tokens["kernel"], str(caught.exception))
