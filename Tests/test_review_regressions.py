import copy
import errno
import json
import runpy
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from particleve import install
from particleve.common import Deferred, Error, digest, write_json
from particleve.config import validate
from particleve.linux import Linux
from particleve.vms import process_identity
from Tests.fixtures import host


class FirmwareStateTests(unittest.TestCase):
    def test_numeric_needs_reboot_alone_inhibits_os_work(self):
        backend = Linux.__new__(Linux)
        with tempfile.TemporaryDirectory() as tmp:
            backend.esp = Mock(side_effect=lambda _: nullcontext(Path(tmp)))
            for state in range(6):
                with (
                    self.subTest(state=state),
                    patch("particleve.linux.Path.glob", return_value=[]),
                    patch("particleve.linux.Path.exists", return_value=False),
                    patch(
                        "particleve.linux.run",
                        return_value=SimpleNamespace(
                            returncode=0, stdout=json.dumps({"Devices": [{"UpdateState": state}]})
                        ),
                    ),
                ):
                    if state in (1, 4):
                        with self.assertRaisesRegex(Deferred, "staged firmware"):
                            backend.check_firmware_clear()
                    else:
                        backend.check_firmware_clear()

    def test_unrecognized_firmware_state_cannot_be_declared_clear(self):
        for state in (True, "needs-reboot", 6, -1):
            with (
                self.subTest(state=state),
                patch("particleve.linux.Path.glob", return_value=[]),
                patch("particleve.linux.Path.exists", return_value=False),
                patch(
                    "particleve.linux.run",
                    return_value=SimpleNamespace(returncode=0, stdout=json.dumps({"UpdateState": state})),
                ),
                self.assertRaisesRegex(Error, "unknown fwupd"),
            ):
                Linux.__new__(Linux).check_firmware_clear()


class ReplacementPreflightTests(unittest.TestCase):
    def test_absent_disk_with_retained_mapper_rejects_before_journal_or_disk_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            write_json(directory / "state.json", {"maintenance": {"reason": "replace"}, "pending": None})
            backend = SimpleNamespace(
                directory=directory,
                disk=lambda role: {"path": "/dev/disk/by-id/old-" + role},
            )
            with (
                patch("particleve.install.Path.exists", return_value=False),
                patch("particleve.install.Path.lstat", return_value=SimpleNamespace()),
                patch("particleve.install.inventory.observe_disk") as observe,
                patch("particleve.install.run") as commands,
                patch("particleve.install.write_json") as journal,
                self.assertRaisesRegex(Error, "reboot degraded"),
            ):
                install.replace({}, backend, "b", {}, confirmation="unused", keyfile="unused")
            observe.assert_not_called()
            journal.assert_not_called()
            commands.assert_not_called()


class ProcessInspectionTests(unittest.TestCase):
    def test_installed_stop_entrypoint_retries_inspection_failure(self):
        entrypoint = Path(__file__).resolve().parent.parent / "Sources/bin/particleve-vm-stop"
        with (
            patch("sys.argv", [str(entrypoint), "test"]),
            patch(
                "particleve.vms.stop_instance", side_effect=[PermissionError("inspection denied"), None]
            ) as stop,
            patch("time.sleep") as delay,
            patch("builtins.print") as notice,
        ):
            runpy.run_path(str(entrypoint), run_name="__main__")
        self.assertEqual(stop.call_count, 2)
        delay.assert_called_once_with(1)
        self.assertIn("waiting for owner assistance", notice.call_args.args[0])

    def test_only_confirmed_disappearance_is_absence(self):
        for failure in (FileNotFoundError(), ProcessLookupError()):
            with patch("particleve.processes.os.open", side_effect=failure):
                self.assertIsNone(process_identity(123))
        for failure in (PermissionError(), OSError(errno.EIO, "I/O error")):
            with (
                self.subTest(failure=failure),
                patch("particleve.processes.os.open", side_effect=failure),
                self.assertRaises(type(failure)),
            ):
                process_identity(123)
        for content in ("truncated", "123 (qemu) S", "123 (qemu) " + " ".join(["S"] + ["0"] * 18 + ["bad"])):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as tmp:
                proc = Path(tmp)
                (proc / "123").mkdir()
                (proc / "123/stat").write_text(content)
                with self.assertRaisesRegex(Error, "cannot parse"):
                    process_identity(123, proc=proc)


class AddressAssessmentTests(unittest.TestCase):
    def test_expanded_ipv6_passes_health_without_changing_configuration_identity(self):
        config = host()
        config["network"]["addresses"] = ["2001:0db8:0001:0000:0000:0000:0000:0010/64"]
        validate(config)
        original = copy.deepcopy(config)
        identity = digest(config)
        backend = Linux.__new__(Linux)
        backend.config = config
        backend.check_storage = Mock()
        backend.current_esp_role = Mock()
        backend.check_usr_boot_disk = Mock()
        backend.check_dns = Mock()

        class ReachedNextHealthCheck(Exception):
            pass

        with (
            patch("particleve.accounts.check"),
            patch("particleve.linux.console_baseline"),
            patch("particleve.linux.inventory.kvm_available", return_value=True),
            patch("particleve.linux.inventory.secure_boot", return_value=True),
            patch("particleve.linux.inventory.measured_boot"),
            patch("particleve.security.live_baseline"),
            patch("particleve.security.ssh_baseline"),
            patch("particleve.security.selinux_baseline"),
            patch("particleve.security.selinux_access"),
            patch("particleve.startup.check"),
            patch("particleve.timesync.check_configuration"),
            patch("particleve.radio.baseline"),
            patch("particleve.linux.require_active_services"),
            patch("particleve.linux.Path.read_text", return_value="1"),
            patch(
                "particleve.linux.run",
                side_effect=[
                    SimpleNamespace(stdout=json.dumps([{"addr_info": [{"local": "2001:db8:1::10"}]}])),
                    ReachedNextHealthCheck(),
                ],
            ),
            self.assertRaises(ReachedNextHealthCheck),
        ):
            backend.health()
        self.assertEqual(config, original)
        self.assertEqual(digest(config), identity)
