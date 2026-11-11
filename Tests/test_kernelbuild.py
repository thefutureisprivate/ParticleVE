import hashlib
import tempfile
import unittest
from pathlib import Path

from particleve.kernelbuild import (
    config_text,
    configuration,
    lookaside,
    source_manifest,
    verify_build_sources,
    verify_sources,
)


class KernelSourceTests(unittest.TestCase):
    def policy(self):
        return {
            "schema": 1,
            "overrides": {
                "CONFIG_VSOCKETS_DIAG": {"value": "m", "reason": "Required native transport diagnostics."}
            },
            "spec_patches": [],
            "excluded_patches": {},
            "retained_builtin": {},
        }

    def test_literal_config_policy_preserves_explicit_deviation(self):
        script = (
            "configs_to_enable=(\n  CONFIG_ONE\n)\n"
            "configs_to_disable=(\n  # comment\n  CONFIG_VSOCKETS_DIAG\n)\n"
        )
        selected = configuration(script, self.policy())
        self.assertEqual(selected, {"CONFIG_ONE": "y", "CONFIG_VSOCKETS_DIAG": "m"})
        self.assertEqual(config_text(selected), "CONFIG_ONE=y\nCONFIG_VSOCKETS_DIAG=m\n")

    def test_shell_expressions_and_duplicate_config_selections_are_rejected(self):
        for item in ("$(touch /tmp/unwanted)", "CONFIG_ONE\nCONFIG_ONE", "CONFIG_ONE=y"):
            script = f"configs_to_enable=(\n{item}\n)\nconfigs_to_disable=(\nCONFIG_TWO\n)\n"
            with self.subTest(item=item), self.assertRaises(ValueError):
                configuration(script, self.policy())

    def test_lookaside_paths_checksums_and_duplicates_fail_closed(self):
        valid = "SHA512 (linux-7.3.3.tar.xz) = " + "a" * 128
        self.assertEqual(lookaside(valid), {"linux-7.3.3.tar.xz": "a" * 128})
        for invalid in (valid + "\n" + valid, valid.replace("linux-7.3.3", "../linux-7.3.3"), ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                lookaside(invalid)

    def test_payload_is_bound_to_both_git_and_lookaside_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git, sources = root / "git", root / "sources"
            git.mkdir()
            sources.mkdir()
            archive = b"pinned compressed source"
            files = {
                "kernel.spec": b"reviewed Fedora recipe",
                "kernel-local": b"# stock config",
                "sources": ("SHA512 (linux.tar.xz) = " + hashlib.sha512(archive).hexdigest() + "\n").encode(),
            }
            for name, data in files.items():
                (git / name).write_bytes(data)
                if name != "sources":
                    (sources / name).write_bytes(data)
            (sources / "linux.tar.xz").write_bytes(archive)
            identity = source_manifest(git, dict.fromkeys(files, 0o644))
            verify_sources(sources, identity)
            (sources / "kernel.spec").write_bytes(b"modified recipe")
            with self.assertRaisesRegex(ValueError, "digest differs"):
                verify_sources(sources, identity)
            (sources / "kernel.spec").write_bytes(files["kernel.spec"])
            (sources / "linux.tar.xz").write_bytes(b"modified archive")
            with self.assertRaisesRegex(ValueError, "digest differs"):
                verify_sources(sources, identity)
            (sources / "linux.tar.xz").write_bytes(archive)
            (sources / "unexpected").write_bytes(b"not an authenticated source")
            with self.assertRaisesRegex(ValueError, "input set"):
                verify_sources(sources, identity)

    def test_source_symlinks_cannot_escape_the_pinned_file_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sources").write_text("SHA512 (linux.tar.xz) = " + "a" * 128 + "\n")
            (root / "kernel-local").write_text("# stock")
            (root / "kernel.spec").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(ValueError, "regular kernel source"):
                source_manifest(root, dict.fromkeys(["sources", "kernel-local", "kernel.spec"], 0o644))

    def test_build_inputs_retain_their_recorded_git_executable_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "prepare.sh"
            script.write_bytes(b"#!/bin/sh\nexit 0\n")
            script.chmod(0o755)
            identity = {
                "schema": 1,
                "source_files": {
                    "prepare.sh": {
                        "algorithm": "sha256",
                        "digest": hashlib.sha256(script.read_bytes()).hexdigest(),
                        "mode": 0o755,
                    }
                },
            }
            verify_build_sources(root, identity)
            script.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode differs"):
                verify_build_sources(root, identity)
