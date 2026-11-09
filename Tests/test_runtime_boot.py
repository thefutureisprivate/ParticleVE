import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import cli, common, inventory, network
from particleve.common import Error
from Tests.fixtures import host


class RuntimeBootTests(unittest.TestCase):
    def test_unprivileged_firewall_command_cannot_change_packet_filtering(self):
        args = cli.parser().parse_args(["apply-firewall"])
        with (
            patch.object(cli, "read_json", return_value=host()),
            patch.object(cli.os, "geteuid", return_value=1000),
            patch.object(cli, "run") as commands,
            self.assertRaisesRegex(Error, "requires root"),
        ):
            cli.execute(args)
        commands.assert_not_called()

    def test_public_daemon_configuration_is_readable_with_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = os.umask(0o077)
            try:
                network.write(host(), root)
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
            with self.assertRaisesRegex(Error, "symlink"):
                network.write(host(), root)
            self.assertEqual(outside.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(outside.iterdir()), [])

    def test_one_active_service_does_not_hide_a_failed_required_service(self):
        def active(arguments, **kwargs):
            self.assertEqual(len(arguments), 4)
            return SimpleNamespace(returncode=int(arguments[-1] == "firewall.service"))

        with (
            patch.object(common, "run", side_effect=active),
            self.assertRaisesRegex(Error, "firewall.service"),
        ):
            common.require_active_services("network.service", "firewall.service")

    def test_tpm_device_without_firmware_log_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch.object(inventory, "run", return_value=SimpleNamespace(returncode=0)),
                patch.object(
                    inventory,
                    "Path",
                    side_effect=lambda value: root if value == "/sys/kernel/security" else Path(value),
                ),
                self.assertRaisesRegex(Error, "firmware TPM event log"),
            ):
                inventory.measured_boot()


if __name__ == "__main__":
    unittest.main()
