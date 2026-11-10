"""The reusable PTY mechanism must retain the installed-host entry point's guards."""

import io
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

PROBE = Path(__file__).resolve().parents[1] / "Tools/run0-pty-probe.py"


class Run0ProbeGuards(unittest.TestCase):
    def load(self):
        with patch("pty.fork", side_effect=AssertionError("unexpected PTY during import")):
            return runpy.run_path(str(PROBE))

    def test_image_checks_precede_password_read_and_process_creation(self):
        functions = self.load()
        for release, message in (
            ({"IMAGE_ID": "fedora"}, "not a ParticleVE OS"),
            ({"IMAGE_ID": "ParticleVE", "IMAGE_VERSION": "invalid"}, "invalid running image"),
        ):
            password = io.StringIO('{"password":"must remain unread"}')
            with (
                self.subTest(release=release),
                patch("platform.freedesktop_os_release", return_value=release),
                patch("sys.stdin", password),
                patch("pty.fork", side_effect=AssertionError("guard did not block PTY")),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                functions["main"]()
            self.assertEqual(password.tell(), 0)

    def test_installed_entry_point_rejects_root_before_reading_a_password(self):
        functions = self.load()
        password = io.StringIO('{"password":"must remain unread"}')
        with (
            patch(
                "platform.freedesktop_os_release",
                return_value={"IMAGE_ID": "ParticleVE", "IMAGE_VERSION": "45.0.2.1-1.1"},
            ),
            patch("os.geteuid", return_value=0),
            patch("sys.stdin", password),
            patch("pty.fork", side_effect=AssertionError("root must not produce acceptance evidence")),
            self.assertRaisesRegex(SystemExit, "non-root SSH session"),
        ):
            functions["main"]()
        self.assertEqual(password.tell(), 0)

    def test_component_caller_also_rejects_a_root_session(self):
        functions = self.load()
        with (
            patch("os.geteuid", return_value=0),
            patch("pty.fork", side_effect=AssertionError("root must not produce acceptance evidence")),
            self.assertRaisesRegex(SystemExit, "non-root SSH session"),
        ):
            functions["exercise"]("unused password")
