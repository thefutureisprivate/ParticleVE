import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from particleve.common import Error
from Tools.build_source import system_changes


class BuildSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q", "--initial-branch=main")
        self.write("Sources/particleve/runtime.py", "initial system code\n")
        self.write("pyproject.toml", '[project]\nname="fixture"\n[tool.ruff]\nline-length=100\n')
        self.write(
            ".obs/particleve/_service",
            '<services><service name="obs_scm"><param name="revision">main</param>'
            '<param name="extract">recipe.spec</param></service>'
            '<service name="tar" mode="buildtime" /></services>\n',
        )
        self.base = self.commit("Published system inputs")

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self, subject):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            subject,
        )
        return self.git("rev-parse", "HEAD")

    def changes(self, base=None, candidate="HEAD"):
        return system_changes(self.root, base or self.base, candidate)

    def test_ancillary_commits_wait_for_system_changes(self):
        for name in (
            "README.md",
            "Documentation/Operations.md",
            ".github/renovate.json",
            ".github/workflows/check.yml",
            "Tests/test_runtime.py",
            "Tools/source_releases.py",
            "Tools/sourcegit.py",
            "Tools/trust.py",
            "Tools/build_source.py",
            "Tools/Examples/site.json",
            ".obs/site.json",
            ".obs/project.xml",
            "Makefile",
        ):
            self.write(name, "ancillary update\n")
        self.commit("Improve documentation and development tooling")
        self.assertEqual(self.changes(), [])

    def test_compares_to_build_ref_including_changes_before_the_last_push(self):
        self.write("Sources/particleve/runtime.py", "fixed system code\n")
        system = self.commit("Fix system behavior")
        self.write("Documentation/Operations.md", "updated guide\n")
        latest = self.commit("Explain system behavior")
        self.assertEqual(self.changes(system, latest), [])
        self.assertEqual(self.changes(self.base, latest), ["Sources/particleve/runtime.py"])
        self.assertEqual(self.changes(latest, latest), [])

    def test_content_modes_binary_inputs_and_unknown_paths_trigger_builds(self):
        for name in (
            "Tools/check-build.py",
            "Tools/obs-postoutput",
            "Tools/package-identity.py",
            "sources.lock.json",
            "mkosi.extra/etc/systemd/system/example.service",
            ".obs/mkosi/mkosi.spec",
            "new-system-input",
            "Sources/template.md",
        ):
            with self.subTest(path=name):
                parent = self.git("rev-parse", "HEAD")
                self.write(name, "system input\n")
                self.commit("Change " + name)
                self.assertEqual(self.changes(parent), [name])
        parent = self.git("rev-parse", "HEAD")
        binary = self.root / "mkosi.extra/firmware.bin"
        binary.write_bytes(b"\xff\x00\x80")
        self.commit("Add binary firmware")
        self.assertEqual(self.changes(parent), ["mkosi.extra/firmware.bin"])
        parent = self.git("rev-parse", "HEAD")
        binary.chmod(0o755)
        self.commit("Change payload mode")
        self.assertEqual(self.changes(parent), ["mkosi.extra/firmware.bin"])

    def test_removing_or_moving_system_code_to_documentation_still_triggers(self):
        destination = self.root / "Documentation/old-runtime.md"
        destination.parent.mkdir()
        (self.root / "Sources/particleve/runtime.py").rename(destination)
        self.commit("Remove system implementation")
        self.assertEqual(self.changes(), ["Sources/particleve/runtime.py"])

    def test_reverted_system_changes_do_not_rebuild_identical_inputs(self):
        self.write("Sources/particleve/runtime.py", "temporary change\n")
        self.commit("Temporary change")
        self.write("Sources/particleve/runtime.py", "initial system code\n")
        self.commit("Restore system inputs")
        self.assertEqual(self.changes(), [])

    def test_ruff_configuration_waits_but_package_metadata_triggers(self):
        path = self.root / "pyproject.toml"
        path.write_text(path.read_text().replace("line-length=100", "line-length=110"))
        self.commit("Adjust source lint")
        self.assertEqual(self.changes(), [])
        path.write_text(path.read_text().replace('name="fixture"', 'name="new-package"'))
        self.commit("Change installed package")
        self.assertEqual(self.changes(), ["pyproject.toml"])

    def test_source_selection_waits_but_build_operations_and_extractions_trigger(self):
        path = self.root / ".obs/particleve/_service"
        selected = path.read_text().replace(
            '<param name="revision">main</param>',
            '<param name="revision">build</param>'
            '<param name="versionformat">@PARENT_TAG@</param>'
            '<param name="match-tag">v*</param>'
            '<param name="versionrewrite-pattern">v(.*)</param>'
            '<param name="versionrewrite-replacement">\\1</param>',
        )
        path.write_text(selected)
        selection = self.commit("Select checked build ref")
        self.assertEqual(self.changes(), [])
        path.write_text(selected.replace('name="tar"', 'name="recompress"'))
        self.commit("Change buildtime operation")
        self.assertEqual(self.changes(selection), [".obs/particleve/_service"])
        path.write_text(selected.replace("recipe.spec", "other.spec"))
        self.commit("Change native recipe extraction")
        self.assertEqual(self.changes(selection), [".obs/particleve/_service"])

    def test_divergent_or_missing_build_ref_fails_closed(self):
        self.git("checkout", "-qb", "other")
        self.write("README.md", "other history\n")
        other = self.commit("Other history")
        self.git("checkout", "-q", "main")
        self.write("README.md", "main history\n")
        self.commit("Main history")
        with self.assertRaisesRegex(Error, "must be an ancestor"):
            self.changes(other)
        with self.assertRaises(Error):
            self.changes("refs/heads/missing")

    def test_entry_point_selects_exact_checked_tree_and_emits_only_a_boolean_output(self):
        self.write("README.md", "guide\n")
        docs = self.commit("Guide update")
        self.write("Sources/particleve/runtime.py", "system fix\n")
        fixed = self.commit("System fix")
        self.write("Sources/particleve/runtime.py", "uncommitted work is not checked\n")
        output = self.root / "github-output"
        script = Path(__file__).resolve().parents[1] / "Tools/build_source.py"
        env = {
            **self.env,
            "PYTHONPATH": os.pathsep.join((str(script.parents[1] / "Sources"), str(script.parents[1]))),
        }
        for candidate, changed in ((docs, False), (fixed, True)):
            with self.subTest(candidate=candidate):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-W",
                        "error",
                        script,
                        "--base",
                        self.base,
                        "--candidate",
                        candidate,
                        "--github-output",
                        output,
                    ],
                    cwd=self.root,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["advance_build"], changed)
                self.assertEqual(result.stderr, "")
        self.assertEqual(output.read_text(), "changed=false\nchanged=true\n")
