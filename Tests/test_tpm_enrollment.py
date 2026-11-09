import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import commission, install
from particleve.common import Error, digest, hash_file, read_json, write_json


class TPMEnrollmentTests(unittest.TestCase):
    def setUp(self):
        original = Path.read_bytes

        def contents(path):
            return b"test public key" if str(path) == install.TPM_PUBLIC_KEY else original(path)

        self.enterContext(patch.object(Path, "read_bytes", contents))

    def policy(self):
        return {
            "type": "systemd-tpm2",
            "keyslots": ["1"],
            "tpm2-pcrs": [7],
            "tpm2-pcr-bank": "sha256",
            "tpm2_pubkey_pcrs": [11],
            "tpm2_pubkey": base64.b64encode(b"test public key").decode(),
        }

    def test_enrollment_rejects_implicit_pcrlock_and_unexpected_policy(self):
        for field, value in (
            ("tpm2_pcrlock", True),
            ("tpm2-pin", True),
            ("tpm2-pcrs", []),
            ("tpm2_pubkey_pcrs", []),
            ("tpm2_pubkey", base64.b64encode(b"another key").decode()),
        ):
            token = {**self.policy(), field: value}
            with (
                self.subTest(field=field),
                patch.object(install.inventory, "measured_boot", return_value=True),
                patch.object(
                    install,
                    "run",
                    side_effect=[
                        SimpleNamespace(stdout=""),
                        SimpleNamespace(stdout=json.dumps({"tokens": {"0": token}})),
                    ],
                ),
                self.assertRaisesRegex(Error, "without pcrlock or PIN"),
            ):
                install.enroll_source("/dev/disposable", "/run/test-key")

    def test_selected_policy_can_be_added_without_erasing_other_owner_slots(self):
        tokens = {
            "0": {**self.policy(), "tpm2_pcrlock": True},
            "1": {**self.policy(), "keyslots": ["2"]},
        }
        with (
            patch.object(install.inventory, "measured_boot", return_value=True),
            patch.object(
                install,
                "run",
                side_effect=[
                    SimpleNamespace(stdout=""),
                    SimpleNamespace(stdout=json.dumps({"tokens": tokens})),
                ],
            ) as commands,
        ):
            install.enroll_source("/dev/disposable", "/run/test-key")
        self.assertFalse(any("wipe-slot" in str(a) for a in commands.call_args_list[0].args[0]))

    def test_commissioning_rechecks_live_policy_even_with_a_matching_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            backend = self.backend(directory)
            backend.health = lambda: None
            backend.check_resources = lambda **kwargs: None
            proof = directory / "proof"
            proof.write_text("disposable unit-test evidence")
            evidence = {
                "schema": 1,
                "approved_by": "test owner",
                "installation_sha256": digest(backend.manifest),
                "config_sha256": digest(backend.config),
                "image_version": "1",
                "measured_minimum_ram_mib": 2048,
                "hardware_coverage": "unit test only",
                "validation_gaps": [],
                "scenarios": {
                    name: {"result": "pass", "evidence": str(proof), "sha256": hash_file(proof)}
                    for name in commission.SCENARIOS
                },
                "firmware_flash": {"result": "no-eligible-update", "evidence": str(proof)},
            }
            path = directory / "acceptance.json"
            write_json(path, evidence)
            write_json(
                directory / "tpm-enrollment.json",
                {
                    "schema": 1,
                    "policy": backend.config["tpm_policy"],
                    "luks_uuids": install.enrollment_uuids(backend.manifest),
                },
            )
            for required in ("physical_interface_policy", "resource_limits"):
                proof = evidence["scenarios"].pop(required)
                write_json(path, evidence)
                with (
                    self.subTest(required=required),
                    patch.object(
                        backend, "health", side_effect=AssertionError("required evidence must precede health")
                    ) as health,
                    self.assertRaisesRegex(Error, required),
                ):
                    commission.commission(backend, path)
                health.assert_not_called()
                evidence["scenarios"][required] = proof
            write_json(path, evidence)
            with (
                patch.object(install, "member", side_effect=lambda d, role: "/dev/test-" + d["role"]),
                patch.object(install, "verify_tpm_policy", side_effect=Error("unexpected live policy")),
                self.assertRaisesRegex(Error, "unexpected live policy"),
            ):
                commission.commission(backend, path)
            self.assertFalse((directory / "commissioned.json").exists())

    def test_replacement_crypttab_tracks_new_luks_identity_and_preserves_peer_swap(self):
        manifest = self.backend(Path("/unused")).manifest
        manifest["devices"][0]["state_luks_uuid"] = "replacement-a"
        text = install.crypttab(manifest)
        self.assertIn("particleve-state-a UUID=replacement-a - ", text)
        self.assertIn("particleve-state-b UUID=state-b - ", text)
        self.assertIn("particleve-swap UUID=swap - tpm2-device=auto\n", text)
        self.assertNotIn("UUID=state-a ", text)

    def test_replacement_copy_stays_owned_until_completion_without_short_timeout(self):
        with patch.object(install, "run") as command:
            install.replace_btrfs(1, "/dev/mapper/particleve-state-a")
        self.assertEqual(
            command.call_args.args[0],
            ["btrfs", "replace", "start", "-B", "1", "/dev/mapper/particleve-state-a", "/"],
        )
        self.assertIsNone(command.call_args.kwargs["timeout"])

    def test_recovery_installer_formats_without_binding_its_pcr7(self):
        with patch.object(install, "run", return_value=SimpleNamespace(stdout="test-uuid\n")) as commands:
            install.format_encrypted("/dev/disposable", "test", "/run/test-key", enroll=False)
        self.assertEqual([c.args[0][0] for c in commands.call_args_list], ["cryptsetup"] * 3)

    def backend(self, directory):
        manifest = {
            "devices": [
                {"role": "a", "state_luks_uuid": "state-a"},
                {"role": "b", "state_luks_uuid": "state-b"},
            ],
            "swap": {"luks_uuid": "swap"},
        }
        calls = []
        return SimpleNamespace(
            directory=directory,
            config={"tpm_policy": "pcr7+signed-pcr11"},
            manifest=manifest,
            current_version=lambda: "1",
            boot_id=lambda: "normal-boot",
            check_storage=lambda **kwargs: calls.append("storage"),
            check_firmware_clear=lambda: calls.append("firmware"),
            release=lambda version: {"version": version},
            verify_disk=lambda *args, **kwargs: True,
        )

    def test_only_verified_normal_boot_enrolls_all_three_and_preserves_slots(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            backend = self.backend(directory)
            with (
                patch.object(install, "validate_keyfile"),
                patch.object(install.inventory, "secure_boot", return_value=True),
                patch.object(install.inventory, "measured_boot", return_value=True),
                patch.object(install, "member", side_effect=lambda d, role: "/dev/test-" + d["role"]),
                patch.object(
                    install,
                    "run",
                    side_effect=lambda args, **kwargs: SimpleNamespace(
                        stdout=json.dumps({"tokens": {"0": self.policy()}}) if args[0] == "cryptsetup" else ""
                    ),
                ) as commands,
            ):
                install.enroll_tpm(backend, "/run/test-key", {"pending": None, "maintenance": None})
            enrollments = [c for c in commands.call_args_list if c.args[0][0] == "systemd-cryptenroll"]
            self.assertEqual(len(enrollments), 3)
            self.assertEqual(len(commands.call_args_list), 6)
            for call in enrollments:
                self.assertIn("--tpm2-pcrs=7", call.args[0])
                self.assertIn("--tpm2-pcrlock=", call.args[0])
                self.assertIn("--tpm2-public-key-pcrs=11", call.args[0])
                self.assertFalse(any("wipe-slot" in str(a) for a in call.args[0]))
            record = read_json(directory / "tpm-enrollment.json")
            self.assertEqual(record["boot_id"], "normal-boot")
            self.assertEqual(record["luks_uuids"], ["state-a", "state-b", "swap"])

    def test_unmeasured_boot_cannot_enroll_a_volume(self):
        with (
            patch.object(install.inventory, "measured_boot", side_effect=Error("unmeasured boot")),
            patch.object(install, "run") as commands,
            self.assertRaisesRegex(Error, "unmeasured boot"),
        ):
            install.enroll_source("/dev/disposable", "/run/test-key")
        commands.assert_not_called()

    def test_interruption_never_records_completion_and_can_be_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            backend = self.backend(directory)
            with (
                patch.object(install, "validate_keyfile"),
                patch.object(install.inventory, "secure_boot", return_value=True),
                patch.object(install, "member", side_effect=lambda d, role: "/dev/test-" + d["role"]),
                patch.object(install, "enroll_source", side_effect=[None, Error("interrupted")]),
                self.assertRaises(Error),
            ):
                install.enroll_tpm(backend, "/run/test-key", {"pending": None, "maintenance": None})
            self.assertFalse((directory / "tpm-enrollment.json").exists())
            with (
                patch.object(install, "validate_keyfile"),
                patch.object(install.inventory, "secure_boot", return_value=True),
                patch.object(install, "member", side_effect=lambda d, role: "/dev/test-" + d["role"]),
                patch.object(install, "enroll_source"),
            ):
                install.enroll_tpm(backend, "/run/test-key", {"pending": None, "maintenance": None})
            self.assertTrue((directory / "tpm-enrollment.json").exists())

    def test_pending_update_or_commissioned_host_without_maintenance_cannot_enroll(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            backend = self.backend(directory)
            for pending, commissioned in (({"version": "2"}, False), (None, True)):
                if commissioned:
                    (directory / "commissioned.json").write_text("{}")
                with (
                    patch.object(install, "validate_keyfile"),
                    patch.object(install, "enroll_source") as enroll,
                ):
                    with self.assertRaises(Error):
                        install.enroll_tpm(
                            backend, "/run/test-key", {"pending": pending, "maintenance": None}
                        )
                    enroll.assert_not_called()


if __name__ == "__main__":
    unittest.main()
