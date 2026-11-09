import contextlib
import io
import json
import runpy
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

from particleve.common import Error


class OBSUploadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.credentials = self.root / "credentials"
        self.credentials.write_text("fixture-owner\ndisposable-fixture-password\n")
        self.credentials.chmod(0o600)
        self.site = {
            "obs_user": "fixture-owner",
            "obs_project": "home:fixture-owner:particleve",
            "source_repository": "https://github.com/fixture-owner/particleve.git",
            "source_branch": "build",
        }
        self.script = Path(__file__).resolve().parents[1] / "Tools/obs-upload.py"
        self.requests = []

    def upload(self, *arguments, failure=None):
        def request(req, **kwargs):
            self.requests.append(req)
            if failure:
                raise failure
            return io.BytesIO(b'<status code="ok"><summary>Ok</summary></status>')

        opener = Mock()
        opener.open.side_effect = request
        with (
            patch("sys.argv", [str(self.script), *arguments, "--credentials", str(self.credentials)]),
            patch("particleve.common.read_json", return_value=self.site),
            patch("urllib.request.build_opener", return_value=opener) as factory,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            try:
                runpy.run_path(str(self.script), run_name="__main__")
            except SystemExit as exc:
                if exc.code != 0:
                    raise
        return json.loads(output.getvalue()), factory.call_args.args[0]

    def test_particleve_uses_native_git_version_tracking_without_raw_source_commits(self):
        result, handler = self.upload("particleve")
        self.assertEqual(len(self.requests), 1)
        request = self.requests[0]
        self.assertEqual(request.method, "PUT")
        self.assertTrue(request.full_url.endswith("/particleve/_meta"))
        meta = ET.fromstring(request.data)
        expected = self.site["source_repository"] + "?subdir=.obs%2Fparticleve#build"
        self.assertEqual(meta.findtext("scmsync"), expected)
        self.assertEqual(result["scmsync"], expected)
        self.assertEqual(
            [entry.get("repository") for entry in meta.findall("build/enable")],
            ["Fedora_45", "Fedora_45_images"],
        )
        with self.assertRaisesRegex(urllib.error.URLError, "Refusing to redirect"):
            handler.redirect_request(None, None, 302, "redirect", {}, "https://other.example/")

    def test_upstream_services_still_use_atomic_source_commits(self):
        sources = self.root / "sources"
        sources.mkdir()
        (sources / "_service").write_bytes(b"<services/>\n")
        result, _ = self.upload("mkosi", str(sources))
        self.assertEqual(result["files"], ["_service"])
        self.assertEqual([request.method for request in self.requests], ["PUT", "PUT", "POST"])
        self.assertIsNone(ET.fromstring(self.requests[0].data).find("scmsync"))
        self.assertIn("cmd=commitfilelist", self.requests[-1].full_url)

    def test_obsolete_particleve_upload_and_missing_upstream_sources_fail_before_network(self):
        for arguments in (("particleve", str(self.root)), ("mkosi",)):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(Error, "Git-managed"):
                self.upload(*arguments)
        self.assertEqual(self.requests, [])

    def test_private_credentials_and_safe_source_url_are_required_before_metadata_write(self):
        self.credentials.chmod(0o644)
        with self.assertRaisesRegex(Error, "credentials must be private"):
            self.upload("particleve")
        self.credentials.chmod(0o600)
        self.site["source_repository"] += "#unreviewed-ref"
        with self.assertRaises(Error):
            self.upload("particleve")
        self.assertEqual(self.requests, [])

    def test_metadata_failure_is_not_reported_as_success(self):
        failure = urllib.error.HTTPError(
            "https://api.opensuse.org/unused",
            403,
            "Forbidden",
            {},
            io.BytesIO(b"<status><summary>Denied</summary></status>"),
        )
        with self.assertRaisesRegex(SystemExit, "OBS 403: Denied"):
            self.upload("particleve", failure=failure)
        self.assertEqual(len(self.requests), 1)
