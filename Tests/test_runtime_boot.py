import os
import tempfile
import unittest
from pathlib import Path

from particleve import common
from Tests.fixtures import host
from Tests.runtime import RustDriverTests


class RuntimeBootTests(RustDriverTests):
    def test_public_daemon_configuration_is_readable_with_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = os.umask(0o077)
            try:
                self.evaluate("network-write", config=host(), root=str(root))
            finally:
                os.umask(previous)
            for name in (
                "etc",
                "etc/systemd",
                "etc/systemd/network",
            ):
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                (root / "etc/systemd/network/30-particleve-mgmt0.network").stat().st_mode & 0o777,
                0o644,
            )
            self.assertEqual((root / "etc/chrony.conf").stat().st_mode & 0o777, 0o644)
            common.write_json(root / "private/state.json", {})
            self.assertEqual((root / "private").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "private/state.json").stat().st_mode & 0o777, 0o600)

    def test_public_config_does_not_follow_an_output_directory_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "output"
            root.mkdir()
            outside = Path(temporary) / "private"
            outside.mkdir(mode=0o700)
            (root / "etc").symlink_to(outside, target_is_directory=True)
            self.assertIn("symlink", self.request("network-write", config=host(), root=str(root))["error"])
            self.assertEqual(outside.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
