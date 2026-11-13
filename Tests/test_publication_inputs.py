import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Tools.publication_inputs import collect, compare


class PublicationInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "--quiet", "--initial-branch=main")
        for name, content in {
            "Sources/runtime/host.rs": "host code\n",
            ".obs/kernel/kernel.inputs.json": "kernel input\n",
            ".obs/mkosi/mkosi.spec": "mkosi recipe\n",
            ".obs/fwupd-efi/fwupd-efi.spec": "firmware recipe\n",
            "sources.lock.json": "source lock\n",
            "pyproject.toml": '[project]\nname="fixture"\n[tool.ruff]\nline-length=100\n',
        }.items():
            self.write(name, content)
        self.initial = self.commit()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.org",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--message=Fixture",
        )
        return self.git("rev-parse", "HEAD")

    def sources(self, selected):
        return {
            name: selected if name in {"particleve", "image"} else self.initial
            for name in ("particleve", "image", "mkosi", "fwupd-efi", "kernel")
        }

    def test_old_dependency_commits_match_when_their_actual_inputs_are_unchanged(self):
        self.write("Sources/runtime/host.rs", "host fix\n")
        selected = self.commit()
        observed = compare(self.root, selected, selected, self.sources(selected))
        self.assertTrue(all(observed["matches"].values()))
        self.assertEqual(observed["system_changes"], 0)
        self.write(".obs/mkosi/mkosi.spec", "new mkosi recipe\n")
        newer = self.commit()
        observed = compare(self.root, newer, newer, self.sources(newer))
        self.assertFalse(observed["matches"]["mkosi"])
        self.assertTrue(observed["matches"]["kernel"])
        self.assertTrue(observed["matches"]["fwupd-efi"])

    def test_pending_system_changes_are_distinct_from_excluded_ancillary_changes(self):
        self.write("Documentation/Operations.md", "new guide\n")
        self.write(".github/workflows/check.yml", "CI correction\n")
        self.write("pyproject.toml", '[project]\nname="fixture"\n[tool.ruff]\nline-length=90\n')
        ancillary = self.commit()
        self.assertEqual(
            compare(self.root, self.initial, ancillary, self.sources(self.initial))["system_changes"], 0
        )
        self.write("Sources/runtime/host.rs", "unselected system fix\n")
        candidate = self.commit()
        self.assertEqual(
            compare(self.root, self.initial, candidate, self.sources(self.initial))["system_changes"], 1
        )

    def test_missing_sources_cannot_match_and_equal_identities_need_no_fetch(self):
        sources = self.sources(self.initial)
        sources["mkosi"] = None
        with patch("Tools.publication_inputs.git") as native:
            observed = collect("https://github.com/owner/fixture.git", self.initial, self.initial, sources)
        native.assert_not_called()
        self.assertFalse(observed["matches"]["mkosi"])
        self.assertTrue(observed["matches"]["particleve"])

    def test_source_lock_changes_invalidate_both_custom_tool_inputs(self):
        self.write("sources.lock.json", json.dumps({"changed": True}))
        selected = self.commit()
        observed = compare(self.root, selected, selected, self.sources(selected))
        self.assertFalse(observed["matches"]["mkosi"])
        self.assertFalse(observed["matches"]["fwupd-efi"])
