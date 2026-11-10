"""Validate real Rust partition selection and full artifact readback with inert lsblk."""

import copy
import hashlib
import json
import tempfile
from pathlib import Path

from particleve.layout import MIB, TYPES
from Tests.fixtures import release
from Tests.runtime import RustDriverTests, native_environment


class PartitionIdentityTests(RustDriverTests):
    def setUp(self):
        self.release = release("45.0.1.5-1.1")
        self.manifest = {
            "devices": [{"role": role, "path": f"/dev/disk/by-id/test-{role}"} for role in ("a", "b")]
        }
        self.parts = [
            {
                "type": "part",
                "name": f"/dev/test-{kind}",
                "partlabel": "PVE_45.0.1.5-1.1",
                "parttype": TYPES[kind],
                "partuuid": self.release["artifacts"][kind]["partition_uuid"],
                "size": self.release["artifacts"][kind]["size"],
            }
            for kind in ("usr", "verity", "verity_sig")
        ]

    def selection(self, parts, role="a", kind="usr"):
        with tempfile.TemporaryDirectory() as directory:
            environment = native_environment(
                directory,
                {"lsblk": {"stdout": json.dumps({"blockdevices": [{"type": "disk", "children": parts}]})}},
            )
            return self.evaluate(
                "linux-matching-partition",
                manifest=self.manifest,
                release=self.release,
                role=role,
                kind=kind,
                environment=environment,
            )

    def test_shared_label_selects_each_kind_on_the_requested_disk(self):
        for role in ("a", "b"):
            for kind in ("usr", "verity", "verity_sig"):
                self.assertEqual(self.selection(self.parts, role, kind), f"/dev/test-{kind}")

    def test_changed_identity_capacity_or_ambiguous_partition_is_rejected(self):
        for field, value in (
            ("type", "crypt"),
            ("partlabel", "ParticleVE_45.0.1.5-1.1"),
            ("partlabel", "PVE_45.0.1.4-1.1"),
            ("parttype", TYPES["verity"]),
            ("partuuid", "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
            ("size", self.parts[0]["size"] - 1),
        ):
            parts = copy.deepcopy(self.parts)
            parts[0][field] = value
            with self.subTest(field=field, value=value):
                self.assertIsNone(self.selection(parts))
        self.assertIsNone(self.selection([*self.parts, dict(self.parts[0])]))

    def test_write_os_overwrites_signature_padding_and_verifies_all_native_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts, nodes, partitions = {}, [], []
            for number, kind in enumerate(("verity_sig", "verity", "usr"), 1):
                content = (
                    (b'{"signature":"owned"}\0' + bytes(MIB - 22))
                    if kind == "verity_sig"
                    else (kind * 200).encode()
                )
                if kind == "verity_sig":
                    content = content[:MIB].ljust(MIB, b"\0")
                source, target = root / f"{kind}.raw", root / f"{kind}.partition"
                source.write_bytes(content)
                target.write_bytes(b"x" * len(content))
                artifacts[kind] = {
                    "file": source.name,
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                nodes.append({"partn": number, "name": str(target)})
                partitions.append({"number": number, "role": "a_" + kind})
            environment = native_environment(root, {"lsblk": {"stdout": json.dumps({"blockdevices": nodes})}})
            (Path(environment["PATH"]) / "dd").symlink_to("/usr/bin/dd")
            device = {"path": str(root / "selected-disk"), "partitions": partitions}
            self.evaluate(
                "install-write-os",
                device=device,
                release={"artifacts": artifacts},
                directory=directory,
                environment=environment,
            )
            for kind in artifacts:
                self.assertEqual(
                    (root / f"{kind}.partition").read_bytes(), (root / f"{kind}.raw").read_bytes()
                )
            self.assertEqual((root / "verity_sig.partition").stat().st_size, MIB)

    def test_successful_native_writer_status_cannot_hide_a_bad_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "sig.raw", root / "sig.partition"
            source.write_bytes(b"expected")
            target.write_bytes(b"old data")
            environment = native_environment(
                root,
                {
                    "lsblk": {"stdout": json.dumps({"blockdevices": [{"partn": 1, "name": str(target)}]})},
                    "dd": {},
                },
            )
            response = self.request(
                "install-write-os",
                device={"path": "fixture-disk", "partitions": [{"number": 1, "role": "a_verity_sig"}]},
                release={
                    "artifacts": {
                        "verity_sig": {
                            "file": source.name,
                            "size": len(b"expected"),
                            "sha256": hashlib.sha256(b"expected").hexdigest(),
                        }
                    }
                },
                directory=directory,
                environment=environment,
            )
            self.assertIn("failed readback", response["error"])
