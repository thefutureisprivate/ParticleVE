import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import package_sources
from particleve.buildartifacts import postoutput
from particleve.buildcheck import root_check
from particleve.common import Error
from particleve.provenance import implementation_digest, inputs, verify_upstream_package

ROOT = Path(__file__).resolve().parent.parent


class UpstreamProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source, self.installed = self.base / "source", self.base / "root"
        names = set(inputs(ROOT)) | {"sources.lock.json"}
        for component in package_sources.COMPONENTS:
            names.update(package_sources.source_identity(ROOT, component)["inputs"])
        for name in names:
            destination = self.source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        files = {
            "usr/bin/mkosi": b"console entrypoint",
            "usr/lib/python3.14/site-packages/mkosi/__init__.py": b"mkosi source",
            "usr/lib/python3.14/site-packages/mkosi/__pycache__/__init__.cpython-314.pyc": b"bytecode",
            "usr/libexec/fwupd/efi/fwupdx64.efi": b"PE executable|unsigned",
            "usr/lib64/pkgconfig/fwupd-efi.pc": b"package configuration",
        }
        for name, value in files.items():
            path = self.installed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        (self.installed / "usr/libexec/fwupd/efi/fwupdx64.efi.signed").symlink_to("fwupdx64.efi")
        self.pesign = patch("particleve.package_sources.subprocess.run", side_effect=self.hash_pe)
        self.pesign.start()
        self.addCleanup(self.pesign.stop)
        self.expected = {}
        for component in package_sources.COMPONENTS:
            identity = package_sources.source_identity(self.source, component)
            self.expected[component] = identity
            sources = self.base / (component + "-sources")
            sources.mkdir()
            for name in (*identity["inputs"], "sources.lock.json"):
                target = (
                    component + ".recipe" if name == f".obs/{component}/{component}.spec" else Path(name).name
                )
                shutil.copyfile(self.source / name, sources / target)
            package_sources.record_package(
                self.installed, sources, component, identity["upstream"]["revision"]
            )

    def hash_pe(self, args, **kwargs):
        self.assertEqual(args[:4], ["pesign", "--hash", "--padding", "--digest-type=sha256"])
        data = Path(args[-1]).read_bytes().split(b"|", 1)[0]
        return SimpleNamespace(stdout="hash: " + hashlib.sha256(data).hexdigest(), stderr="")

    def test_matching_packages_survive_documentation_changes_and_pe_signing(self):
        (self.source / "README.md").write_text("new documentation")
        (self.installed / "usr/libexec/fwupd/efi/fwupdx64.efi").write_bytes(
            b"PE executable|project signature"
        )
        for component, expected in self.expected.items():
            self.assertEqual(package_sources.source_identity(self.source, component), expected)
            verify_upstream_package(self.installed, component, expected)

    def test_complete_unmodified_recipe_is_verified(self):
        for component in package_sources.COMPONENTS:
            spec = self.source / f".obs/{component}/{component}.spec"
            spec.write_text(spec.read_text().replace("Release:        1%{?dist}", "Release: 52.3"))
            self.assertNotEqual(
                package_sources.source_identity(self.source, component), self.expected[component]
            )
            with self.assertRaisesRegex(Error, "expected source and patches"):
                verify_upstream_package(
                    self.installed, component, package_sources.source_identity(self.source, component)
                )

    def test_version_update_requires_matching_recipe_and_lock(self):
        for component in package_sources.COMPONENTS:
            with self.subTest(component=component):
                spec = self.source / f".obs/{component}/{component}.spec"
                pins = json.loads((self.source / "sources.lock.json").read_text())
                pin = pins["sources"][package_sources.COMPONENTS[component]]
                spec.write_text(
                    spec.read_text().replace(f"Version:        {pin['version']}", "Version:        999")
                )
                with self.assertRaisesRegex(ValueError, "locked upstream version"):
                    package_sources.source_identity(self.source, component)
                pin["version"] = "999"
                (self.source / "sources.lock.json").write_text(json.dumps(pins))
                identity = package_sources.source_identity(self.source, component)
                self.assertEqual(identity["upstream"]["version"], "999")

    def test_patch_headers_cannot_silently_omit_source_inputs(self):
        for component in package_sources.COMPONENTS:
            spec = self.source / f".obs/{component}/{component}.spec"
            header = " \tpatch0 \t:"
            spec.write_text(spec.read_text().replace("Patch0:", header))
            before = package_sources.source_identity(self.source, component)
            patch_name = next(name for name in before["inputs"] if name.endswith(".patch"))
            path = self.source / patch_name
            path.write_text(path.read_text() + "\n# changed patch\n")
            after = package_sources.source_identity(self.source, component)
            self.assertNotEqual(before["inputs"][patch_name], after["inputs"][patch_name])
            spec.write_text(spec.read_text().replace(header, "Patch0: %{name}"))
            with self.assertRaisesRegex(ValueError, "explicit local filenames"):
                package_sources.source_identity(self.source, component)

    def test_pin_recipe_and_patch_changes_reject_independently_stale_packages(self):
        implementation = implementation_digest(self.source)
        for component in package_sources.COMPONENTS:
            for kind in ("pin", "recipe", "patch"):
                with self.subTest(component=component, kind=kind):
                    original = {p: p.read_bytes() for p in self.source.rglob("*") if p.is_file()}
                    spec = self.source / f".obs/{component}/{component}.spec"
                    if kind == "pin":
                        pins = json.loads((self.source / "sources.lock.json").read_text())
                        pin = pins["sources"][package_sources.COMPONENTS[component]]
                        old = pin["revision"]
                        pin["revision"] = "a" * 40
                        (self.source / "sources.lock.json").write_text(json.dumps(pins))
                        spec.write_text(spec.read_text().replace(old, pin["revision"]))
                    else:
                        target = (
                            spec
                            if kind == "recipe"
                            else next(self.source.glob(f".obs/{component}/{component}-*.patch"))
                        )
                        target.write_text(target.read_text() + "\n# reviewed change\n")
                    expected = package_sources.source_identity(self.source, component)
                    self.assertEqual(implementation_digest(self.source), implementation)
                    with self.assertRaisesRegex(Error, "expected source and patches"):
                        verify_upstream_package(self.installed, component, expected)
                    for path, data in original.items():
                        path.write_bytes(data)

    def test_modified_or_missing_payload_is_rejected(self):
        for component, filename in (
            ("mkosi", "usr/lib/python3.14/site-packages/mkosi/__init__.py"),
            ("fwupd-efi", "usr/libexec/fwupd/efi/fwupdx64.efi"),
        ):
            path = self.installed / filename
            original = path.read_bytes()
            path.write_bytes(b"modified executable")
            with self.subTest(component=component), self.assertRaisesRegex(Error, "payload does not match"):
                verify_upstream_package(self.installed, component, self.expected[component])
            path.write_bytes(original)
        path = self.installed / "usr/lib/python3.14/site-packages/mkosi/__pycache__/__init__.cpython-314.pyc"
        path.unlink()
        with self.assertRaisesRegex(Error, "incomplete mkosi"):
            verify_upstream_package(self.installed, "mkosi", self.expected["mkosi"])

    def test_build_checks_reject_stale_upstream_package_before_rpm_queries(self):
        for component, tree in (("mkosi", "tools"), ("fwupd-efi", "usr")):
            spec = self.source / f".obs/{component}/{component}.spec"
            spec.write_text(spec.read_text() + "\n# new recipe\n")
            with (
                self.subTest(component=component),
                patch("particleve.buildcheck.verify_package"),
                patch("particleve.buildcheck.run") as commands,
                self.assertRaisesRegex(Error, "expected source and patches"),
            ):
                root_check(self.installed, tree=tree, source_dir=self.source)
            commands.assert_not_called()

    def test_final_signing_rechecks_both_upstream_packages_before_publication(self):
        for component in package_sources.COMPONENTS:
            with self.subTest(component=component):
                output = self.base / (component + "-output")
                output.mkdir()
                for suffix in ("efi", "usr-x86-64.a.raw", "usr-x86-64-verity-sig.a.raw"):
                    (output / ("ParticleVE_45.0.1.1-52.1_x86-64." + suffix)).write_bytes(b"fixture")
                expected = json.loads(json.dumps(self.expected))
                expected[component]["inputs"][f".obs/{component}/{component}.spec"] = "0" * 64

                def extract(_image, target, expected=expected):
                    shutil.copytree(self.installed / "usr", target, symlinks=True)
                    record = target / "lib/particleve/verification.json"
                    record.write_text(
                        json.dumps({"implementation_sha256": "0" * 64, "upstream_inputs": expected})
                    )

                def check(root, package, identity):
                    return verify_upstream_package(
                        self.installed if package == "mkosi" else root, package, identity
                    )

                with (
                    patch.dict("os.environ", OUTPUTDIR=str(output)),
                    patch("particleve.buildartifacts.extract_security_metadata", side_effect=extract),
                    patch("particleve.buildartifacts.verify_mount_constraints"),
                    patch("particleve.buildartifacts.verify_package"),
                    patch("particleve.buildartifacts.verify_upstream_package", side_effect=check),
                    self.assertRaisesRegex(Error, "expected source and patches"),
                ):
                    postoutput()
                self.assertFalse(list(output.glob("*.release.json")))
                self.assertFalse((output / "particleve-build-verified").exists())
