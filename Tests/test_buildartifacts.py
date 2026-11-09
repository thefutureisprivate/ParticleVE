import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve.buildartifacts import (
    carry_signing_hook,
    pad_signature_partition,
    postoutput,
    verify_mount_constraints,
)
from particleve.common import Error
from particleve.config import VERITY_SIGNATURE_SIZE
from particleve.install import write_os
from particleve.layout import TYPES


class BuildSigningTests(unittest.TestCase):
    def test_protected_constraints_match_the_installed_geometry_without_extra_choices(self):
        expected = {
            "user.validatefs.mount_point": b"/usr\0",
            "user.validatefs.gpt_label": b"PVE_45.0.1.5-1.1\0",
            "user.validatefs.gpt_type_uuid": (
                "\0".join(TYPES[kind] for kind in ("usr", "verity", "verity_sig")) + "\0"
            ).encode(),
        }
        # The OBS kernel need not support user.* on tmpfs. Use the same
        # file-backed filesystem required by final artifact inspection.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            root = Path(temporary)
            for mutation in (
                {},
                {"user.validatefs.mount_point": b"/usr"},
                {"user.validatefs.gpt_label": b"ParticleVE_45.0.1.5-1.1\0"},
                {"user.validatefs.gpt_label": b"PVE_45.0.1.5-1.1\0other\0"},
                {"user.validatefs.gpt_label": b"PVE_45.0.1.5-1.1\0\0"},
                {"user.validatefs.gpt_label": b"x" * 4097},
                {"user.validatefs.mount_point": b"/sysroot/usr\0"},
                {"user.validatefs.gpt_type_uuid": TYPES["root"].encode()},
                {"user.validatefs.mount_point": None},
                {"user.validatefs.unknown": b"unreviewed"},
            ):
                for name in os.listxattr(root):
                    if name.startswith("user.validatefs."):
                        os.removexattr(root, name)
                for name, value in (expected | mutation).items():
                    if value is not None:
                        os.setxattr(root, name, value)
                with self.subTest(mutation=mutation):
                    if not mutation or mutation == {"user.validatefs.mount_point": b"/usr"}:
                        verify_mount_constraints(root, "45.0.1.5-1.1")
                    else:
                        with self.assertRaisesRegex(Error, "mount constraint"):
                            verify_mount_constraints(root, "45.0.1.5-1.1")

    def test_final_stage_rejects_the_native_label_mismatch_before_publishing(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            output = Path(temporary)
            for suffix in ("efi", "usr-x86-64.a.raw", "usr-x86-64-verity-sig.a.raw"):
                (output / ("ParticleVE_45.0.1.5-1.1_x86-64." + suffix)).write_bytes(b"fixture")

            def extract(_image, target):
                target.mkdir()
                os.setxattr(target, "user.validatefs.mount_point", b"/usr\0")
                os.setxattr(target, "user.validatefs.gpt_label", b"ParticleVE_45.0.1.5-1.1\0")
                os.setxattr(
                    target,
                    "user.validatefs.gpt_type_uuid",
                    b"\0".join(TYPES[kind].encode() for kind in ("usr", "verity", "verity_sig")),
                )

            with (
                patch.dict(os.environ, OUTPUTDIR=str(output)),
                patch("particleve.buildartifacts.extract_security_metadata", side_effect=extract),
                self.assertRaisesRegex(Error, "gpt_label"),
            ):
                postoutput()
            self.assertEqual(list(output.glob("*.release.json")), [])

    def test_signature_payload_overwrites_a_dirty_slot_completely(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            signature = directory / "signature.raw"
            payload = b'{"rootHash":"test","signature":"test"}'
            signature.write_bytes(payload)
            pad_signature_partition(signature)
            manifest = {"artifacts": {}}
            targets = {}
            for kind, source in (("verity_sig", signature), ("verity", None), ("usr", None)):
                if source is None:
                    source = directory / (kind + ".raw")
                    source.write_bytes(b"new partition bytes")
                data = source.read_bytes()
                manifest["artifacts"][kind] = {
                    "file": source.name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                target = directory / (kind + ".slot")
                target.write_bytes(b"X" * len(data))
                targets["a_" + kind] = target
            with patch("particleve.install.member", side_effect=lambda _, role: targets[role]):
                write_os({}, manifest, directory)
            self.assertEqual(
                targets["a_verity_sig"].read_bytes(),
                payload + b"\0" * (VERITY_SIGNATURE_SIZE - len(payload)),
            )

    def test_oversized_signature_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            signature = Path(temporary) / "signature.raw"
            data = b"X" * (VERITY_SIGNATURE_SIZE + 1)
            signature.write_bytes(data)
            with self.assertRaises(Error):
                pad_signature_partition(signature)
            self.assertEqual(signature.read_bytes(), data)

    def test_none_format_continuation_carries_build_hook_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            recipe = directory / "mkosi.conf"
            recipe.write_text(
                "[Distribution]\nDistribution=custom\n[Output]\nFormat=none\n[Include]\nInclude=mkosi-obs\n"
            )
            (directory / "ParticleVE_45.0.1.1-87.2_x86-64.efi").write_bytes(b"UKI")
            carry_signing_hook(directory)
            carry_signing_hook(directory)
            text = recipe.read_text()
            self.assertEqual(text.count("BuildScripts=/usr/libexec/particleve-obs-postoutput"), 1)
            self.assertNotIn("PostOutputScripts=", text)
            self.assertNotIn("BuildPackages=", text)
            self.assertEqual((directory / "particleve.version").read_text(), "45.0.1.1\n")

    def test_incomplete_native_signing_stage_cannot_publish_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "hashes.cpio.rsasign").write_bytes(b"pending native signatures")
            (directory / "mkosi.conf").write_text("[Output]\nFormat=none\n")
            (directory / "ParticleVE_45.0.1.1-87.2_x86-64.efi").write_bytes(b"UKI")
            with patch.dict(os.environ, {"OUTPUTDIR": temporary}):
                postoutput()
            self.assertEqual(list(directory.glob("*.release.json")), [])
            (directory / "hashes.cpio.rsasign").unlink()
            with patch.dict(os.environ, {"OUTPUTDIR": temporary}), self.assertRaises(Error):
                postoutput()
            self.assertEqual(list(directory.glob("*.release.json")), [])


if __name__ == "__main__":
    unittest.main()
