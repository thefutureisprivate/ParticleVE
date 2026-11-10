"""Compiled TPM/swap interfaces; token and enrollment authority predicates are Rust tests."""

import json
import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests, native_environment


class TPMEnrollmentTests(RustDriverTests):
    @staticmethod
    def manifest():
        return {
            "devices": [
                {"role": "a", "state_luks_uuid": "state-a"},
                {"role": "b", "state_luks_uuid": "state-b"},
            ],
            "swap": {"luks_uuid": "swap"},
        }

    def test_replacement_crypttab_changes_only_selected_identity_and_keeps_state_noauto(self):
        manifest = self.manifest()
        manifest["devices"][0]["state_luks_uuid"] = "replacement-a"
        contents = self.evaluate("install-crypttab", manifest=manifest)
        self.assertIn("particleve-state-a UUID=replacement-a - noauto,tpm2-device=auto", contents)
        self.assertIn("particleve-state-b UUID=state-b - noauto,tpm2-device=auto", contents)
        self.assertIn("particleve-swap UUID=swap - tpm2-device=auto\n", contents)
        self.assertNotIn("UUID=state-a ", contents)
        self.assertEqual(
            self.evaluate("install-enrollment-uuids", manifest=manifest), ["replacement-a", "state-b", "swap"]
        )

    def test_recovery_installer_never_enrolls_its_own_boot_measurements(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "commands.jsonl"
            environment = native_environment(directory, {"cryptsetup": {"stdout": "test-uuid\n"}})
            environment["PVE_NATIVE_COMMAND_LOG"] = str(log)
            self.assertEqual(
                self.evaluate(
                    "install-format-encrypted",
                    source="/dev/disposable-fixture",
                    name="fixture-state",
                    keyfile="/run/disposable-fixture-key",
                    enroll=False,
                    environment=environment,
                ),
                "test-uuid",
            )
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([command[1] for command in commands], ["luksFormat", "open", "luksUUID"])
            self.assertTrue(all(command[0] == "cryptsetup" for command in commands))
            self.assertFalse(any("wipe-slot" in value for command in commands for value in command))

    def test_replacement_copy_uses_foreground_native_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "commands.jsonl"
            arguments = ("btrfs", "replace", "start", "-B", "1", "/dev/mapper/owned-disposable-fixture", "/")
            environment = native_environment(directory, {arguments: {}})
            environment["PVE_NATIVE_COMMAND_LOG"] = str(log)
            self.evaluate(
                "install-replace-btrfs",
                devid=1,
                mapper="/dev/mapper/owned-disposable-fixture",
                environment=environment,
            )
            self.assertEqual([json.loads(line) for line in log.read_text().splitlines()], [list(arguments)])
