"""Global loader policy, early-root ownership and retained-image resolution."""

import os
import tempfile
import unittest
from pathlib import Path

from particleve.common import Error
from particleve.security import allocator_layout
from Tests.runtime import RustDriverTests

ROOT = Path(__file__).resolve().parent.parent
CONFIGURATION = "/usr/lib/particleve/ld.so.preload"


class AllocatorTests(RustDriverTests):
    def test_image_rejects_unreadable_modified_or_redirected_allocator_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / CONFIGURATION.removeprefix("/")
            config.parent.mkdir(parents=True)
            config.write_text("/usr/lib64/libhardened_malloc.so\n")
            config.chmod(0o644)
            library = root / "usr/lib64/libhardened_malloc.so"
            library.parent.mkdir(parents=True)
            library.write_bytes(b"package payload verified separately")
            library.chmod(0o755)
            link = root / "etc/ld.so.preload"
            link.parent.mkdir()
            link.symlink_to(CONFIGURATION)
            allocator_layout(root, ROOT, initrd=True)
            for path, mode in ((config, 0o600), (config, 0o666), (library, 0o4755), (library, 0o775)):
                original = path.stat().st_mode & 0o7777
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(Error):
                    allocator_layout(root, ROOT, initrd=True)
                path.chmod(original)
            config.write_text("/var/lib/allocator.so\n")
            with self.assertRaisesRegex(Error, "reviewed source"):
                allocator_layout(root, ROOT, initrd=True)
            config.write_text("/usr/lib64/libhardened_malloc.so\n")
            link.unlink()
            link.symlink_to("/var/lib/preload")
            with self.assertRaisesRegex(Error, "image-owned"):
                allocator_layout(root, ROOT, initrd=True)

    @unittest.skipUnless(os.geteuid() == 0, "owned-root mutation is tested in the native root namespace")
    def test_early_root_creates_only_the_owned_default_and_preserves_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "etc"
            directory.mkdir(mode=0o755)
            link = directory / "ld.so.preload"
            self.evaluate("allocator-prepare-root", root=str(root))
            self.assertEqual(link.readlink(), Path(CONFIGURATION))
            # A new active image can supply a different /usr without rewriting /etc.
            self.evaluate("allocator-prepare-root", root=str(root))
            for target in ("../usr/lib/particleve/ld.so.preload", "/usr/share/factory/etc/ld.so.preload"):
                link.unlink()
                link.symlink_to(target)
                self.evaluate("allocator-prepare-root", root=str(root))
                self.assertEqual(str(link.readlink()), target)
            link.unlink()
            link.write_text("owner configuration\n")
            self.assertIn("error", self.request("allocator-prepare-root", root=str(root)))
            self.assertEqual(link.read_text(), "owner configuration\n")
            link.unlink()
            link.symlink_to("/var/lib/preload")
            self.assertIn("error", self.request("allocator-prepare-root", root=str(root)))
            self.assertEqual(str(link.readlink()), "/var/lib/preload")
            link.unlink()
            directory.chmod(0o777)
            self.assertIn("error", self.request("allocator-prepare-root", root=str(root)))
            self.assertFalse(link.exists() or link.is_symlink())
