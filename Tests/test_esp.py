"""Use real temporary ESP directories to check boot counters and firmware staging preservation."""

import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve.bootloaders import Loaders
from particleve.common import Error, hash_file, read_json, write_json
from particleve.layout import TYPES
from particleve.linux import Linux
from Tests.fixtures import release


class ESPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.backend = Linux.__new__(Linux)
        self.backend.config = {}
        self.backend.directory = self.root / "state"
        self.backend.cache = self.root / "cache"
        self.manifest = release("45.0.1.2-1.1")
        cache = self.backend.cache / "45.0.1.2-1.1"
        cache.mkdir(parents=True)
        for kind, item in self.manifest["artifacts"].items():
            path = cache / item["file"]
            path.write_bytes(kind.encode())
            item["size"] = path.stat().st_size
            item["sha256"] = hash_file(path)
        self.esps = {role: self.root / role for role in ("a", "b")}
        for esp in self.esps.values():
            (esp / "EFI/Linux").mkdir(parents=True)
            (esp / "EFI/UpdateCapsule").mkdir()
            (esp / "EFI/UpdateCapsule/owner.cap").write_bytes(b"firmware")
            (esp / "loader").mkdir()
            (esp / "loader/loader.conf").write_text("timeout 9\neditor no\ndefault old.efi\n")
        self.backend.esp = lambda role: contextlib.nullcontext(self.esps[role])
        self.backend.local_release = lambda version: self.manifest
        self.backend.matching_partition = lambda role, manifest, kind: (
            cache / manifest["artifacts"][kind]["file"]
        )
        loaders = Loaders(self.backend)
        loaders.seed(self.manifest)
        state = read_json(loaders.path)
        state["good"] = state["seed"]
        write_json(loaders.path, state)
        self.enterContext(patch.object(Loaders, "bless", return_value={}))
        self.active = self.enterContext(patch("particleve.linux.require_active_services"))

    def test_current_partition_identity_and_both_boot_paths_verify_together(self):
        # Exercise the real selector with readback files and native shared-label geometry.
        del self.backend.matching_partition
        self.backend.manifest = {"devices": [{"role": role, "path": role} for role in ("a", "b")]}
        parts = [
            {
                "type": "part",
                "name": str(self.backend.cache / self.manifest["version"] / item["file"]),
                "partlabel": "PVE_" + self.manifest["version"],
                "parttype": TYPES[kind],
                "partuuid": item["partition_uuid"],
                "size": item["size"],
            }
            for kind, item in self.manifest["artifacts"].items()
            if kind in ("usr", "verity", "verity_sig")
        ]
        for role in ("a", "b"):
            self.backend.expose_boot(role, self.manifest)
        with patch("particleve.linux.inventory.block_tree", return_value=parts):
            for role in ("a", "b"):
                self.assertTrue(self.backend.verify_disk(role, self.manifest, boot=True))
            Path(parts[0]["name"]).write_bytes(b"corrupt partition content")
            self.assertFalse(self.backend.verify_disk("a", self.manifest, boot=True))

    def test_existing_boot_counter_and_capsules_survive_preparation(self):
        for role, esp in self.esps.items():
            self.backend.expose_boot(role, self.manifest)
            entry = esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi"
            entry.rename(esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+1-2.efi")
            self.backend.expose_boot(role, self.manifest)
            self.assertFalse(entry.exists())
            self.assertTrue((esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+1-2.efi").exists())
            self.assertEqual((esp / "EFI/UpdateCapsule/owner.cap").read_bytes(), b"firmware")
        self.backend.prove_fallback("45.0.1.2-1.1")
        self.backend.select("45.0.1.2-1.1")
        for esp in self.esps.values():
            text = (esp / "loader/loader.conf").read_text()
            self.assertIn("timeout 9", text)
            self.assertIn("default ParticleVE_*_x86-64*.efi", text)

    def test_preparation_pins_current_but_activation_allows_native_fallback_ordering(self):
        for role, esp in self.esps.items():
            self.backend.expose_boot(role, self.manifest)
            (esp / "EFI/Linux/ParticleVE_45.0.1.1-1.1_x86-64.efi").write_bytes(b"retained UKI")
        self.backend.protect_current("45.0.1.1-1.1", "45.0.1.2-1.1")
        for esp in self.esps.values():
            self.assertIn(
                "default ParticleVE_45.0.1.1-1.1_x86-64*.efi", (esp / "loader/loader.conf").read_text()
            )
        self.backend.select("45.0.1.2-1.1")
        for esp in self.esps.values():
            self.assertIn("default ParticleVE_*_x86-64*.efi", (esp / "loader/loader.conf").read_text())
            self.assertTrue((esp / "EFI/Linux/ParticleVE_45.0.1.1-1.1_x86-64.efi").exists())

    def test_pinning_preserves_retained_ukis_counters_and_capsules(self):
        for role, esp in self.esps.items():
            self.backend.expose_boot(role, self.manifest)
            (esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi").rename(
                esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+1-2.efi"
            )
            (esp / "EFI/Linux/ParticleVE_45.0.1.1-1.1_x86-64.efi").write_bytes(b"retained UKI")
        before = {
            role: {p.relative_to(esp): p.read_bytes() for p in (esp / "EFI").rglob("*") if p.is_file()}
            for role, esp in self.esps.items()
        }
        self.backend.pin_current(self.manifest["version"])
        for role, esp in self.esps.items():
            self.assertEqual(
                {p.relative_to(esp): p.read_bytes() for p in (esp / "EFI").rglob("*") if p.is_file()},
                before[role],
            )
            self.assertEqual(
                (esp / "loader/loader.conf").read_text(),
                "timeout 9\neditor no\ndefault ParticleVE_45.0.1.2-1.1_x86-64*.efi\n",
            )

    def test_pinning_failure_on_second_esp_preserves_both_retained_entries(self):
        for role, esp in self.esps.items():
            self.backend.expose_boot(role, self.manifest)
            (esp / "EFI/Linux/ParticleVE_45.0.1.1-1.1_x86-64.efi").write_bytes(b"retained UKI")

        def selected(role):
            if role == "b":
                raise Error("ESP unavailable")
            return contextlib.nullcontext(self.esps[role])

        self.backend.esp = selected
        with self.assertRaisesRegex(Error, "ESP unavailable"):
            self.backend.pin_current(self.manifest["version"])
        for esp in self.esps.values():
            self.assertEqual(
                (esp / "EFI/Linux/ParticleVE_45.0.1.1-1.1_x86-64.efi").read_bytes(), b"retained UKI"
            )

    def test_activation_refuses_an_exhausted_candidate_without_resetting_it(self):
        for role, esp in self.esps.items():
            self.backend.expose_boot(role, self.manifest)
            (esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi").rename(
                esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+0-3.efi"
            )
        with self.assertRaisesRegex(Error, "eligible candidate"):
            self.backend.select("45.0.1.2-1.1")
        for esp in self.esps.values():
            self.assertTrue((esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+0-3.efi").exists())

    def test_exhausted_counter_never_becomes_a_fallback_or_gets_reset(self):
        self.backend.expose_boot("a", self.manifest)
        esp = self.esps["a"]
        entry = esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi"
        entry.rename(esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+0-3.efi")
        with self.assertRaises(Error):
            self.backend.expose_boot("a", self.manifest)
        with self.assertRaises(Error):
            self.backend.prove_fallback("45.0.1.2-1.1")
        self.assertTrue((esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+0-3.efi").exists())

    def test_blessing_uses_only_booted_esp_and_rejects_modified_uki(self):
        for role in self.esps:
            self.backend.expose_boot(role, self.manifest)
        self.backend.current_version = lambda: "45.0.1.2-1.1"
        self.backend.current_esp_role = lambda: "a"
        with patch("particleve.linux.run") as command:
            self.backend.bless_current()
            command.assert_called_once_with(
                ["/usr/lib/systemd/systemd-bless-boot", f"--path={self.esps['a']}", "good"]
            )
        self.assertTrue((self.esps["b"] / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi").exists())
        (self.esps["a"] / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi").write_bytes(b"modified")
        with patch("particleve.linux.run") as command, self.assertRaisesRegex(Error, "authenticated"):
            self.backend.bless_current()
        command.assert_not_called()

    def test_unblessed_boot_cannot_be_used_as_fallback(self):
        self.active.side_effect = Error("systemd-bless-boot.service is not active")
        with self.assertRaisesRegex(Error, "systemd-bless-boot"):
            self.backend.prove_fallback("45.0.1.2-1.1")

    def test_healthy_boot_of_an_already_blessed_uki_does_not_require_a_counter(self):
        self.backend.expose_boot("a", self.manifest)
        esp = self.esps["a"]
        counted = esp / "EFI/Linux/ParticleVE_45.0.1.2-1.1_x86-64+3.efi"
        good = counted.with_name("ParticleVE_45.0.1.2-1.1_x86-64.efi")
        counted.rename(good)
        self.backend.current_version = lambda: "45.0.1.2-1.1"
        self.backend.current_esp_role = lambda: "a"
        with patch("particleve.linux.run") as command:
            self.assertEqual(self.backend.bless_current(), {"boot_blessed": "45.0.1.2-1.1", "esp_role": "a"})
        command.assert_not_called()
        self.assertTrue(good.exists())

    def test_firmware_esp_identity_must_belong_to_selected_pair(self):
        selected = "d75dc3d4-767e-4de2-a013-20fa67cea6f1"
        self.backend.manifest = {
            "devices": [
                {"role": "a", "partitions": [{"role": "esp", "uuid": selected}]},
                {"role": "b", "partitions": []},
            ]
        }
        with patch.object(
            Path, "read_bytes", return_value=b"\x07\0\0\0" + (selected.upper() + "\0").encode("utf-16-le")
        ):
            self.assertEqual(self.backend.current_esp_role(), "a")
        foreign = "2fac3387-1ab2-468b-a2f9-02a243d38afb"
        with (
            patch.object(
                Path, "read_bytes", return_value=b"\x07\0\0\0" + (foreign + "\0").encode("utf-16-le")
            ),
            self.assertRaisesRegex(Error, "outside the selected disk pair"),
        ):
            self.backend.current_esp_role()


if __name__ == "__main__":
    unittest.main()
