import hashlib
import lzma
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve.kernelpayload import (
    MAGIC,
    module_parts,
    module_paths,
    prepare_signing_continuation,
    verify_configuration,
)


def elf_body():
    body = bytearray(128)
    body[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", body, 16, 1, 62, 1)
    return bytes(body)


class KernelPayloadTests(unittest.TestCase):
    def test_signing_and_compression_preserve_the_recorded_module_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            body, signature = elf_body(), b"native CMS signature is verified separately"
            signed = (
                body + signature + struct.pack(">5B3sI", 0, 0, 2, 0, 0, b"\0\0\0", len(signature)) + MAGIC
            )
            for name, data, expected in (
                ("plain.ko", body, None),
                ("signed.ko", signed, signature),
                ("compressed.ko.xz", lzma.compress(signed, check=lzma.CHECK_CRC32), signature),
            ):
                with self.subTest(name=name):
                    path = directory / name
                    path.write_bytes(data)
                    actual, attached = module_parts(path)
                    self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(body).digest())
                    self.assertEqual(attached, expected)

    def test_malformed_signature_and_compression_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            body = elf_body()
            header = struct.pack(">5B3sI", 0, 0, 2, 0, 0, b"\0\0\0", 8)
            for name, data in (
                ("short.ko", MAGIC),
                ("length.ko", body + header[:-4] + b"\xff\xff\xff\xff" + MAGIC),
                ("legacy.ko", body + b"12345678" + bytes([1]) + header[1:] + MAGIC),
                ("padding.ko", body + b"12345678" + header[:5] + b"\0\1\0" + header[8:] + MAGIC),
                (
                    "concatenated.ko.xz",
                    lzma.compress(body, check=lzma.CHECK_CRC32) + lzma.compress(body, check=lzma.CHECK_CRC32),
                ),
                ("incomplete.ko.xz", lzma.compress(body, check=lzma.CHECK_CRC32)[:-8]),
                ("unsupported.ko.zst", body),
                ("not-elf.ko", b"not an ELF"),
            ):
                with self.subTest(name=name):
                    path = directory / name
                    path.write_bytes(data)
                    with self.assertRaises((ValueError, lzma.LZMAError)):
                        module_parts(path)

    def test_module_paths_reject_aliases_symlinks_and_unreviewed_compression(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            module = directory / "one.ko"
            module.write_bytes(elf_body())
            alias = directory / "one.ko.xz"
            alias.write_bytes(lzma.compress(elf_body(), check=lzma.CHECK_CRC32))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                module_paths(directory)
            alias.unlink()
            module.unlink()
            module.symlink_to("/etc/passwd")
            with self.assertRaisesRegex(ValueError, "regular"):
                module_paths(directory)
            module.unlink()
            (directory / "one.ko.zst").write_bytes(b"unreviewed transport")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                module_paths(directory)

    def test_compressed_module_expansion_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.ko.xz"
            path.write_bytes(lzma.compress(elf_body() + bytes(4096), check=lzma.CHECK_CRC32))
            with (
                patch("particleve.kernelpayload.MAX_MODULE", 512),
                self.assertRaisesRegex(ValueError, "oversized"),
            ):
                module_parts(path)

    def test_userspace_supported_xz_checks_cannot_hide_kernel_incompatibility(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "module.ko.xz"
            for check in (lzma.CHECK_NONE, lzma.CHECK_CRC64, lzma.CHECK_SHA256):
                with self.subTest(check=check):
                    data = lzma.compress(elf_body(), check=check)
                    self.assertEqual(lzma.decompress(data), elf_body())
                    path.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "CRC32"):
                        module_parts(path)

    def test_native_signing_recipe_selects_kernel_xz_format_before_its_generator(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pesign-repackage.spec"
            recipe = b"Name: native\n%install\n/usr/lib/rpm/pesign/pesign-gen-repackage-spec --compress xz\n"
            path.write_bytes(recipe)
            prepare_signing_continuation(path)
            self.assertEqual(
                path.read_bytes(),
                recipe.replace(
                    b"%install\n", b"%install\nexport XZ_DEFAULTS= XZ_OPT='--check=crc32 --threads=1'\n"
                ),
            )
            with self.assertRaisesRegex(ValueError, "already prepared"):
                prepare_signing_continuation(path)
            for invalid in (b"Name: no install\n", recipe + b"%install\n", recipe + b"\0"):
                path.write_bytes(invalid)
                with self.assertRaisesRegex(ValueError, "unexpected"):
                    prepare_signing_continuation(path)
                self.assertEqual(path.read_bytes(), invalid)

    def test_effective_configuration_rejects_drift_and_duplicate_selections(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = directory / "config"
            config.write_text('CONFIG_REQUIRED=y\nCONFIG_PATH="kernel.sbat"\n# CONFIG_OFF is not set\n')
            expected = {
                "CONFIG_REQUIRED": "y",
                "CONFIG_PATH": '"kernel.sbat"',
                "CONFIG_OFF": "n",
                "CONFIG_DISABLED_PARENT": "n",
            }
            verify_configuration(directory, expected)
            for text in (
                config.read_text().replace("CONFIG_REQUIRED=y", "CONFIG_REQUIRED=m"),
                config.read_text() + "CONFIG_OFF=y\n",
                config.read_text().replace("CONFIG_REQUIRED=y\n", ""),
            ):
                with self.subTest(text=text), self.assertRaisesRegex(ValueError, "configuration differs"):
                    config.write_text(text)
                    verify_configuration(directory, expected)
