"""Exercise real ESP file parsing and default writes through the compiled backend."""

import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests

VERSION = "45.0.1.2-1.1"


class ESPTests(RustDriverTests):
    def test_native_boot_counts_and_uncounted_blessed_entries_are_preserved(self):
        for suffix, attempts in (("", None), ("+3", 3), ("+1-2", 1), ("+0-3", 0)):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                esp = Path(directory)
                linux = esp / "EFI/Linux"
                linux.mkdir(parents=True)
                selected = linux / f"ParticleVE_{VERSION}_x86-64{suffix}.efi"
                selected.write_bytes(b"signed fixture UKI")
                (linux / "ParticleVE_45.0.1.1-1.1_x86-64.efi").write_bytes(b"retained")
                (linux / f"ParticleVE_{VERSION}_aarch64.efi").write_bytes(b"other architecture")
                self.assertEqual(
                    self.evaluate("linux-boot-entries", esp=directory, version=VERSION),
                    [{"path": str(selected), "attempts": attempts}],
                )
                self.assertEqual(selected.read_bytes(), b"signed fixture UKI")

    def test_default_selection_preserves_ukis_counters_capsules_and_other_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            esp = Path(directory)
            for name, data in {
                f"EFI/Linux/ParticleVE_{VERSION}_x86-64+0-3.efi": b"exhausted candidate",
                "EFI/Linux/ParticleVE_45.0.1.1-1.1_x86-64.efi": b"retained UKI",
                "EFI/UpdateCapsule/owner.cap": b"staged owner firmware",
            }.items():
                path = esp / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            loader = esp / "loader/loader.conf"
            loader.parent.mkdir()
            loader.write_text("timeout 9\neditor no\ndefault old.efi\n")
            before = {
                str(p.relative_to(esp)): p.read_bytes() for p in (esp / "EFI").rglob("*") if p.is_file()
            }
            self.evaluate("linux-default", esp=directory, config={}, version=VERSION)
            self.assertEqual(
                loader.read_text(), f"timeout 9\neditor no\ndefault ParticleVE_{VERSION}_x86-64*.efi\n"
            )
            self.evaluate("linux-default", esp=directory, config={}, version=None)
            self.assertEqual(loader.read_text(), "timeout 9\neditor no\ndefault ParticleVE_*_x86-64*.efi\n")
            self.assertEqual(
                {str(p.relative_to(esp)): p.read_bytes() for p in (esp / "EFI").rglob("*") if p.is_file()},
                before,
            )

    def test_serial_default_uses_the_signed_uki_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            self.evaluate(
                "linux-default", esp=directory, config={"console": "console=ttyS1,115200n8"}, version=VERSION
            )
            self.assertIn(
                f"default ParticleVE_{VERSION}_x86-64*.efi@serial1-115200\n",
                (Path(directory) / "loader/loader.conf").read_text(),
            )
