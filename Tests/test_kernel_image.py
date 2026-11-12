"""Selected RPMs and signed UKI contents must describe one kernel build."""

import copy
import unittest

from particleve.common import Error
from particleve.kernels import KERNEL_PACKAGES, verify_kernel_packages
from particleve.release import verify_uki_kernel


class KernelImageTests(unittest.TestCase):
    def test_kernel_package_inventory_rejects_mixed_missing_duplicate_and_extra_builds(self):
        kernel = "7.3.3-1.2.x86_64"
        rows = [[name, "7.3.3-1.2", "test producer", "test origin"] for name in sorted(KERNEL_PACKAGES)]
        self.assertEqual(len(verify_kernel_packages(rows, kernel)), 4)
        for changed in (
            rows[:-1],
            rows + [rows[0]],
            rows + [["kernel-devel", "7.3.3-1.2", "test producer", "test origin"]],
            [*rows[:-1], [rows[-1][0], "7.3.3-1.3", "test producer", "test origin"]],
        ):
            with self.subTest(rows=changed), self.assertRaisesRegex(Error, "kernel RPMs differ"):
                verify_kernel_packages(changed, kernel)

    def test_new_images_require_kernel_binding_while_retained_images_remain_inspectable(self):
        verify_uki_kernel({}, {"version": "45.0.2.8-1.1"})
        with self.assertRaisesRegex(Error, "source binding"):
            verify_uki_kernel({}, {"version": "45.0.3.0-1.1"})

    def test_uki_requires_the_actual_verified_kernel_bytes_and_module_release(self):
        manifest = {
            "version": "45.0.3.0-1.1",
            "kernel_verification": {
                "kernel": "7.3.3-1.2.x86_64",
                "kernel_pe_sha256": "a" * 64,
                "source_sha256": "b" * 64,
            },
        }
        sections = {".linux": {"sha256": "a" * 64}, ".uname": {"text": "7.3.3-1.2.x86_64\0"}}
        verify_uki_kernel(sections, manifest)
        for name, changed in (
            (".linux", {"sha256": "c" * 64}),
            (".linux", {}),
            (".uname", {"text": "7.3.3-300.fc45.x86_64"}),
            (".uname", None),
        ):
            value = copy.deepcopy(sections)
            value[name] = changed
            with self.subTest(section=name, value=changed), self.assertRaises(Error):
                verify_uki_kernel(value, manifest)
        for binding in (None, {}, {**manifest["kernel_verification"], "source_sha256": "invalid"}):
            with self.subTest(binding=binding), self.assertRaises(Error):
                verify_uki_kernel(sections, {**manifest, "kernel_verification": binding})
