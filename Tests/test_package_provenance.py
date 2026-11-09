import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve.buildartifacts import postoutput
from particleve.buildcheck import root_check
from particleve.common import Error
from particleve.provenance import implementation_digest, inputs, payload, record_package, verify_package

ROOT = Path(__file__).resolve().parent.parent


class PackageProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "source"
        self.installed = Path(self.tmp.name) / "installed"
        for name in inputs(ROOT):
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        for component in ("integration", "build-tools"):
            for target, origin in payload(self.source, component).items():
                destination = self.installed / target
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(
                    (self.source / origin).read_bytes() if origin else b"compiled policy fixture"
                )
            record_package(self.installed, self.source, component)
        self.identity = implementation_digest(self.source)

    def test_documentation_changes_do_not_invalidate_matching_packages(self):
        (self.source / "README.md").write_text("documentation-only change")
        self.assertEqual(implementation_digest(self.source), self.identity)
        for component in ("integration", "build-tools"):
            verify_package(self.installed, component, self.identity, source=self.source)

    def test_successful_image_webhook_with_stale_runtime_or_tools_rpm_is_rejected(self):
        with (self.source / "Sources/particleve/linux.py").open("a") as stream:
            stream.write("\n# new firmware guard\n")
        expected = implementation_digest(self.source)
        for component in ("integration", "build-tools"):
            with self.subTest(component=component), self.assertRaisesRegex(Error, "does not match the image"):
                verify_package(self.installed, component, expected, source=self.source)

    def test_modified_installed_payload_cannot_pass_an_unchanged_identity_record(self):
        (self.installed / "usr/libexec/particleve-vm-stop").write_text("old helper")
        with self.assertRaisesRegex(Error, "payload does not match"):
            verify_package(self.installed, "integration", self.identity, source=self.source)

    def test_image_build_rejects_stale_payload_before_other_build_checks(self):
        with (self.source / "Sources/particleve/linux.py").open("a") as stream:
            stream.write("\n# implementation changed before the RPM webhook refreshed\n")
        for tree in ("usr", "tools"):
            with (
                self.subTest(tree=tree),
                patch("particleve.buildcheck.run") as command,
                self.assertRaisesRegex(Error, "does not match the image"),
            ):
                root_check(self.installed, tree=tree, source_dir=self.source)
            command.assert_not_called()

    def test_final_signing_stage_cannot_publish_stale_runtime(self):
        import json

        with (self.source / "Sources/particleve/linux.py").open("a") as stream:
            stream.write("\n# new expected implementation\n")
        output = Path(self.tmp.name) / "output"
        output.mkdir()
        for name in (
            "ParticleVE_45.0.1.1-47.1_x86-64.efi",
            "ParticleVE_45.0.1.1-47.1_x86-64.usr-x86-64.a.raw",
            "ParticleVE_45.0.1.1-47.1_x86-64.usr-x86-64-verity-sig.a.raw",
        ):
            (output / name).write_bytes(b"fixture")

        def extract(_image, target):
            shutil.copytree(self.installed / "usr", target)
            (target / "lib/particleve/verification.json").write_text(
                json.dumps({"implementation_sha256": implementation_digest(self.source)})
            )

        with (
            patch.dict("os.environ", OUTPUTDIR=str(output)),
            patch("particleve.buildartifacts.extract_security_metadata", side_effect=extract),
            self.assertRaisesRegex(Error, "does not match the image"),
        ):
            postoutput()
        self.assertEqual(list(output.glob("*.release.json")), [])
