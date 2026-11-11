"""Native Git source identity and TLS policy remain independent of caller overrides."""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from Tools.sourcegit import fetch, git
from Tools.trust import system_trust_paths


class SourceGitTests(unittest.TestCase):
    def initialize(self, directory):
        git(directory, "init", "--quiet", "--initial-branch=source")

    def commit(self, directory, contents):
        (directory / "payload").write_text(contents)
        git(directory, "add", "payload")
        git(
            directory,
            "-c",
            "user.name=Source fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "Public source fixture",
        )
        return git(directory, "rev-parse", "HEAD").stdout.strip()

    def test_url_specific_and_environment_overrides_cannot_disable_tls(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.initialize(directory)
            url = "https://localhost:44460/source.git"
            git(directory, "config", f"http.{url}.sslVerify", "false")
            git(directory, "config", f"http.{url}.sslCAInfo", "/alternate/local-ca")
            injected = directory / "injected.conf"
            injected.write_text(f'[http "{url}"]\nsslVerify=false\nsslCAInfo=/alternate/global-ca\n')
            with patch.dict(
                os.environ,
                {
                    "GIT_CONFIG_GLOBAL": str(injected),
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": f"http.{url}.sslVerify",
                    "GIT_CONFIG_VALUE_0": "false",
                    "GIT_SSL_NO_VERIFY": "1",
                    "GIT_SSL_CAINFO": "/alternate/environment-ca",
                    "SSL_CERT_FILE": "/alternate/openssl-ca",
                },
            ):
                verified = git(
                    directory, "config", "get", "--type=bool", f"--url={url}", "http.sslVerify", remote=url
                )
                # The native helper's own configuration environment is also
                # visible to Git, not just a mocked subprocess argument list.
                roots = git(directory, "var", "GIT_CONFIG_GLOBAL")
            self.assertEqual(verified.stdout.strip(), "true")
            self.assertEqual(roots.stdout.strip(), os.devnull)
            self.assertTrue(Path(system_trust_paths()["cafile"]).is_file())

    def test_inherited_repository_and_replacement_objects_cannot_change_pinned_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, alternate = root / "source", root / "alternate"
            source.mkdir()
            alternate.mkdir()
            self.initialize(source)
            original = self.commit(source, "original pinned contents")
            replacement = self.commit(source, "replacement contents")
            git(source, "replace", original, replacement)
            self.initialize(alternate)
            self.commit(alternate, "redirected repository")
            with patch.dict(os.environ, {"GIT_DIR": str(alternate / ".git")}):
                result = git(source, "show", original + ":payload")
                archive = git(source, "archive", original, text=False)
            self.assertEqual(result.stdout, "original pinned contents")
            self.assertIsInstance(archive.stdout, bytes)
            self.assertNotIn(b"replacement contents", archive.stdout)

    def test_invalid_source_urls_and_revisions_fail_before_git_runs(self):
        for url, revision in (
            ("http://source.example/repository.git", "a" * 40),
            ("file:///local/source.git", "a" * 40),
            ("https://user:password@source.example/repository.git", "a" * 40),
            ("https://source.example/repository.git?credential=private", "a" * 40),
            ("https://source.example/repository.git", "--upload-pack=unexpected"),
            ("https://source.example/repository.git\x00", "a" * 40),
            ("https://source.example/repository.git.sslVerify=false", "a" * 40),
            (123, "a" * 40),
            ("https://source.example/repository.git", None),
            ("https://source.example/repository.git", "refs/tags/v" + "1" * 129),
        ):
            with (
                self.subTest(url=url, revision=revision),
                patch("Tools.sourcegit.run") as process,
                self.assertRaises(Error),
            ):
                fetch(Path("/unused"), url, revision)
            process.assert_not_called()

    def test_local_url_rewrites_are_rejected_before_a_network_fetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.initialize(directory)
            git(directory, "config", "url.https://alternate.invalid/.insteadOf", "https://source.invalid/")
            from Tools import sourcegit

            with (
                patch("Tools.sourcegit.run", wraps=sourcegit.run) as process,
                self.assertRaisesRegex(Error, "source URL rewrites are unsupported"),
            ):
                fetch(directory, "https://source.invalid/repository.git", "a" * 40)
            self.assertFalse(any("fetch" in call.args[0] for call in process.call_args_list))

    def test_branch_transport_cannot_authorize_a_different_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.initialize(directory)
            original = self.commit(directory, "reviewed original")
            tip = self.commit(directory, "newer branch tip")
            git(directory, "checkout", "--quiet", "--orphan", "unrelated")
            unrelated = self.commit(directory, "unrelated history")
            git(directory, "checkout", "--quiet", "source")
            from Tools import sourcegit

            native = sourcegit.run

            def transport(arguments, **kwargs):
                if "fetch" in arguments:
                    # Replace only network I/O. Git still checks the real
                    # commit graph rather than accepting the advertised tip.
                    (directory / ".git/FETCH_HEAD").write_text(tip + "\n")
                    return SimpleNamespace(stdout="", stderr="", returncode=0)
                return native(arguments, **kwargs)

            with patch("Tools.sourcegit.run", side_effect=transport):
                fetch(directory, "https://source.invalid/repository.git", original, branch="f45")
                self.assertEqual(git(directory, "rev-parse", "HEAD").stdout.strip(), tip)
                with self.assertRaises(Error):
                    fetch(directory, "https://source.invalid/repository.git", unrelated, branch="f45")

    def test_invalid_branch_transport_fails_before_git_runs(self):
        for branch in ("../f45", "--upload-pack=unexpected", "f45.lock", "f45\n", 45):
            with (
                self.subTest(branch=branch),
                patch("Tools.sourcegit.run") as process,
                self.assertRaises(Error),
            ):
                fetch(Path("/unused"), "https://source.invalid/repository.git", "a" * 40, branch=branch)
            process.assert_not_called()
