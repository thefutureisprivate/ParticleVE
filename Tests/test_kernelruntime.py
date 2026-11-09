import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import kernelruntime
from particleve.common import Error

SUPPORT = {
    "SECURITY_YAMA": "y",
    "ARCH_MMAP_RND_BITS_MAX": "32",
    "ARCH_MMAP_RND_COMPAT_BITS_MAX": "16",
    "DEVMEM": "y",
    "STRICT_DEVMEM": "y",
    "IO_STRICT_DEVMEM": "y",
}


class KernelRuntimeTests(unittest.TestCase):
    def test_reduced_kernel_entropy_and_unrestricted_memory_are_rejected(self):
        for mutation in (
            {},
            {"SECURITY_YAMA": "n"},
            {"ARCH_MMAP_RND_BITS_MAX": "28"},
            {"ARCH_MMAP_RND_COMPAT_BITS_MAX": "8"},
            {"ARCH_MMAP_RND_COMPAT_BITS_MAX": ""},
            {"STRICT_DEVMEM": "n"},
            {"IO_STRICT_DEVMEM": "n"},
            {"DEVKMEM": "y"},
        ):
            with self.subTest(mutation=mutation):
                if mutation:
                    with self.assertRaises(Error):
                        kernelruntime.kernel_support(SUPPORT | mutation)
                else:
                    self.assertTrue(kernelruntime.kernel_support(SUPPORT)["strict_devmem"])
        self.assertFalse(kernelruntime.kernel_support(SUPPORT | {"DEVMEM": "n"})["strict_devmem"])

    def test_runtime_drift_is_detected_without_rewriting_the_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, expected in kernelruntime.SYSCTLS.items():
                path = root / "sys" / name.replace(".", "/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(expected + "\n")
            result = kernelruntime.baseline(proc=root, dev=root / "absent")
            self.assertEqual(result["sysctls"]["vm.memfd_noexec"], "1")
            for name in kernelruntime.SYSCTLS:
                path = root / "sys" / name.replace(".", "/")
                original = path.read_text()
                path.write_text("unexpected\n")
                with self.subTest(name=name), self.assertRaisesRegex(Error, "runtime policy drift"):
                    kernelruntime.baseline(proc=root, dev=root / "absent")
                self.assertEqual(path.read_text(), "unexpected\n")
                path.write_text(original)
            # Enforced no-executable memfds require a separate decision; stronger
            # numeric values cannot silently change this compatibility contract.
            (root / "sys/vm/memfd_noexec").write_text("2\n")
            with self.assertRaisesRegex(Error, "memfd_noexec"):
                kernelruntime.baseline(proc=root, dev=root / "absent")

    def test_raw_interfaces_cannot_keep_a_group_seat_or_symlink_grant(self):
        for mode, uid, gid, allowed in (
            (stat.S_IFCHR | 0o600, 0, 0, True),
            (stat.S_IFCHR | 0o640, 0, 9, False),
            (stat.S_IFCHR | 0o600, 65534, 0, False),
            (stat.S_IFCHR | 0o600, 0, 9, False),
            (stat.S_IFREG | 0o600, 0, 0, False),
            (stat.S_IFLNK | 0o777, 0, 0, False),
        ):
            metadata = SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)

            def observe(path, metadata=metadata):
                if path.name == "kcore":
                    raise FileNotFoundError
                return metadata

            with (
                self.subTest(mode=mode, uid=uid, gid=gid),
                patch.object(kernelruntime, "SYSCTLS", {}),
                patch.object(Path, "exists", return_value=False),
                patch.object(Path, "is_symlink", return_value=False),
                patch.object(Path, "lstat", observe),
            ):
                if allowed:
                    self.assertEqual(
                        kernelruntime.baseline()["root_only_devices"], {"mem": True, "userfaultfd": True}
                    )
                else:
                    with self.assertRaisesRegex(Error, "root-only character"):
                        kernelruntime.baseline()
        with tempfile.TemporaryDirectory() as tmp, patch.object(kernelruntime, "SYSCTLS", {}):
            dev = Path(tmp)
            (dev / "kmem").symlink_to(dev / "nonexistent")
            with self.assertRaisesRegex(Error, "legacy kmem"):
                kernelruntime.baseline(dev=dev)

    def test_kernel_core_is_inspected_as_metadata_without_opening_memory(self):
        for mode, uid, allowed in (
            (stat.S_IFREG | 0o400, 0, True),
            (stat.S_IFREG | 0o440, 0, False),
            (stat.S_IFREG | 0o400, 65534, False),
            (stat.S_IFLNK | 0o777, 0, False),
        ):
            metadata = SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=0)

            def observe(path, metadata=metadata):
                if path.name == "kcore":
                    return metadata
                raise FileNotFoundError

            with (
                self.subTest(mode=mode, uid=uid),
                patch.object(kernelruntime, "SYSCTLS", {}),
                patch.object(Path, "exists", return_value=False),
                patch.object(Path, "is_symlink", return_value=False),
                patch.object(Path, "lstat", observe),
                patch.object(Path, "read_text", side_effect=AssertionError("must not read kernel memory")),
            ):
                if allowed:
                    self.assertTrue(kernelruntime.baseline()["root_only_kcore"])
                else:
                    with self.assertRaisesRegex(Error, "kernel core"):
                        kernelruntime.baseline()


if __name__ == "__main__":
    unittest.main()
