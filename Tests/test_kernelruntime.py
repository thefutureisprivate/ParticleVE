import json
import tempfile
import unittest
from pathlib import Path

from particleve import kernelruntime
from particleve.common import Error
from Tests.runtime import RustDriverTests

SUPPORT = {
    "SECURITY_YAMA": "y",
    "ARCH_MMAP_RND_BITS_MAX": "32",
    "ARCH_MMAP_RND_COMPAT_BITS_MAX": "16",
    "DEVMEM": "y",
    "STRICT_DEVMEM": "y",
    "IO_STRICT_DEVMEM": "y",
}


class KernelRuntimeTests(RustDriverTests):
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
        self.assertFalse(kernelruntime.kernel_support(SUPPORT)["proc_kcore"])
        self.assertTrue(kernelruntime.kernel_support(SUPPORT | {"PROC_KCORE": "y"})["proc_kcore"])
        self.assertFalse(kernelruntime.kernel_support(SUPPORT)["kexec_core"])
        self.assertTrue(kernelruntime.kernel_support(SUPPORT | {"KEXEC_CORE": "y"})["kexec_core"])

    def test_runtime_drift_is_detected_without_rewriting_fixture_state(self):
        policy = json.loads(Path("Sources/particleve/runtime-policy.json").read_text())["sysctls"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, expected in policy.items():
                path = root / "sys" / name.replace(".", "/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(expected + "\n")
            self.assertEqual(
                self.evaluate(
                    "kernel-runtime-baseline", proc=str(root), dev=str(root / "absent"), kexec_core=True
                )["sysctls"],
                policy,
            )
            for name in policy:
                path = root / "sys" / name.replace(".", "/")
                original = path.read_text()
                for value in ("unexpected", "2") if name == "vm.memfd_noexec" else ("unexpected",):
                    path.write_text(value)
                    with self.subTest(name=name, value=value):
                        self.assertIn(
                            "runtime policy drift",
                            self.request(
                                "kernel-runtime-baseline",
                                proc=str(root),
                                dev=str(root / "absent"),
                                kexec_core=True,
                            )["error"],
                        )
                        self.assertEqual(path.read_text(), value)
                path.write_text(original)
            dev = root / "dev"
            dev.mkdir()
            for name in ("mem", "userfaultfd", "kmem"):
                path = dev / name
                path.write_text("untrusted regular file")
                path.chmod(0o600)
                self.assertIn(
                    "error",
                    self.request("kernel-runtime-baseline", proc=str(root), dev=str(dev), kexec_core=True),
                )
                path.unlink()
                path.symlink_to(root / "missing")
                self.assertIn(
                    "error",
                    self.request("kernel-runtime-baseline", proc=str(root), dev=str(dev), kexec_core=True),
                )
                path.unlink()


if __name__ == "__main__":
    unittest.main()
