import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class OBSProjectTests(unittest.TestCase):
    def test_dependency_check_rejects_missing_inputs_without_regenerating_them(self):
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".obs/particleve").mkdir(parents=True)
            (root / ".obs/site.json").write_text(
                json.dumps(
                    {
                        "obs_project": "home:fixture:particleve",
                        "obs_user": "fixture",
                        "source_repository": "https://github.com/fixture/particleve.git",
                        "source_branch": "build",
                        "fedora_project": "Fedora:45",
                        "fedora_updates_repository": "update",
                        "fedora_base_repository": "standard",
                    }
                )
            )
            (root / ".obs/particleve/_service").write_text(
                '<services><service name="obs_scm"><param name="url">https://example.org/</param>'
                '<param name="revision">build</param></service></services>'
            )
            summary = {
                "Images": [
                    {"Image": "main", "Packages": ["host"], "VolatilePackages": [], "BuildPackages": []},
                    {"Image": "default-initrd", "Packages": ["early"], "VolatilePackages": []},
                ],
                "Tools": {"Packages": ["builder"], "VolatilePackages": []},
            }
            summary_path = root / "summary.json"
            command = [
                sys.executable,
                "-W",
                "error",
                str(repository / "Tools/obs-project.py"),
                "--site",
                ".obs/site.json",
                "--summary",
                str(summary_path),
            ]

            def invoke(*arguments):
                return subprocess.run(
                    [*command, *arguments],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=os.environ | {"PYTHONPATH": str(repository / "Sources") + ":" + str(repository)},
                    check=False,
                )

            def files():
                return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}

            summary_path.write_text(json.dumps(summary))
            generated = invoke()
            self.assertEqual(generated.returncode, 0, generated.stderr)
            before = files()
            checked = invoke("--check", "--output", "must-not-be-created")
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(files(), before)
            self.assertFalse((root / "must-not-be-created").exists())

            for tree, field in (
                (0, "Packages"),
                (1, "VolatilePackages"),
                ("Tools", "Packages"),
                (0, "BuildPackages"),
            ):
                with self.subTest(tree=tree, field=field):
                    changed = copy.deepcopy(summary)
                    target = changed["Tools"] if tree == "Tools" else changed["Images"][tree]
                    target[field].append("new-dependency")
                    summary_path.write_text(json.dumps(changed))
                    before = files()
                    rejected = invoke("--check")
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("OBS dependencies differ", rejected.stderr)
                    self.assertEqual(files(), before)

            summary["Images"][0]["Packages"].append("node-exporter")
            summary_path.write_text(json.dumps(summary))
            regenerated = invoke()
            self.assertEqual(regenerated.returncode, 0, regenerated.stderr)
            self.assertIn("        node-exporter\n", (root / ".obs/fedora/x86-64/mkosi.conf").read_text())
            self.assertEqual(invoke("--check").returncode, 0)
