import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PrepareObsTests(unittest.TestCase):
    def test_source_cpio_directory_modes_do_not_inherit_the_callers_umask(self):
        project = Path(__file__).resolve().parents[1]
        env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "PYTHONPATH": str(project / "Sources"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {
                "particleve.version": "45.0.1.10\n",
                ".obs/fedora/x86-64/mkosi.conf": "[Config]\n",
                ".obs/particleve/rpm.spec": "Name: particleve\n",
                ".obs/particleve/_multibuild": "<multibuild/>\n",
                "mkosi.extra/usr/lib/systemd/resolved.conf.d/50-particleve.conf": "[Resolve]\n",
                "Sources/bin/fixture": "#!/bin/sh\nexit 0\n",
            }
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                path.chmod(0o755 if name == "Sources/bin/fixture" else 0o644)
            for arguments in (("init", "-q"), ("add", "."), ("write-tree",)):
                result = subprocess.run(
                    ["git", *arguments],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
            tree = result.stdout.strip()
            for mask in (0o002, 0o077):
                with self.subTest(umask=oct(mask)):
                    output = root / f"prepared-{mask:o}"
                    prepared = subprocess.run(
                        [
                            sys.executable,
                            "-W",
                            "error",
                            project / "Tools/prepare-obs.py",
                            "--tree",
                            tree,
                            "--output",
                            output,
                        ],
                        cwd=root,
                        env=env,
                        umask=mask,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(prepared.returncode, 0, prepared.stderr)
                    self.assertEqual(prepared.stderr, "")
                    listed = subprocess.run(
                        [
                            "cpio",
                            "--list",
                            "--verbose",
                            "--quiet",
                            "--numeric-uid-gid",
                            "--file",
                            output / "particleve/particleve.obscpio",
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10,
                    )
                    self.assertEqual(listed.stderr, "")
                    entries = {line.split()[-1]: line.split()[0] for line in listed.stdout.splitlines()}
                    prefix = "particleve-45.0.1.10"
                    self.assertEqual(entries[prefix], "drwxr-xr-x")
                    self.assertEqual(
                        entries[prefix + "/mkosi.extra/usr/lib/systemd/resolved.conf.d"],
                        "drwxr-xr-x",
                    )
                    self.assertTrue(all(mode == "drwxr-xr-x" for mode in entries.values() if mode[0] == "d"))
                    self.assertEqual(entries[prefix + "/Sources/bin/fixture"], "-rwxr-xr-x")
                    self.assertEqual(entries[prefix + "/particleve.version"], "-rw-r--r--")
                    self.assertEqual(
                        (output / "particleve/particleve.obsinfo").read_text().splitlines()[-1],
                        "tree: " + tree,
                    )
