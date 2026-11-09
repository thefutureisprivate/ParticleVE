import tempfile
import unittest
from pathlib import Path

from particleve.common import Error
from particleve.kernels import REQUIRED_MODULES, verify_modules


class KernelArtifactTests(unittest.TestCase):
    def test_final_artifact_requires_the_verity_driver_after_filtering(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            tree = directory / "test-kernel"
            tree.mkdir()
            (tree / "modules.builtin").write_text("")
            for name in REQUIRED_MODULES - {"dm_verity"}:
                (tree / (name + ".ko.zst")).write_bytes(b"retained module")
            with self.assertRaisesRegex(Error, "dm_verity"):
                verify_modules(directory)
            (tree / "dm-verity.ko.zst").write_bytes(b"retained verity driver")
            self.assertEqual(verify_modules(directory)["module_files"], len(REQUIRED_MODULES))

    def test_compiled_in_drivers_satisfy_the_same_artifact_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            tree = directory / "builtin-kernel"
            tree.mkdir()
            (tree / "modules.builtin").write_text(
                "\n".join("kernel/" + name.replace("_", "-") + ".ko" for name in REQUIRED_MODULES) + "\n"
            )
            result = verify_modules(directory)
            self.assertEqual(result["module_files"], 0)
            self.assertEqual(result["required_drivers"], sorted(REQUIRED_MODULES))


if __name__ == "__main__":
    unittest.main()
