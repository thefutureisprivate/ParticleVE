import copy
import unittest
from unittest.mock import patch

from particleve import install
from particleve.common import Error
from particleve.layout import TYPES, calculate
from particleve.linux import Linux
from Tests.fixtures import devices, host, release


class PartitionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.release = release("45.0.1.5-1.1")
        self.backend = Linux.__new__(Linux)
        self.backend.manifest = {
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

    def test_shared_label_selects_each_kind_only_on_the_requested_disk(self):
        tree = [{"type": "disk", "children": self.parts}]
        with patch("particleve.linux.inventory.block_tree", return_value=tree) as observe:
            for role in ("a", "b"):
                for kind in ("usr", "verity", "verity_sig"):
                    with self.subTest(role=role, kind=kind):
                        self.assertEqual(
                            self.backend.matching_partition(role, self.release, kind), f"/dev/test-{kind}"
                        )
                        observe.assert_called_with(f"/dev/disk/by-id/test-{role}")

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
            with (
                self.subTest(field=field, value=value),
                patch("particleve.linux.inventory.block_tree", return_value=parts),
            ):
                self.assertIsNone(self.backend.matching_partition("a", self.release, "usr"))
        parts = [*self.parts, dict(self.parts[0])]
        with patch("particleve.linux.inventory.block_tree", return_value=parts):
            self.assertIsNone(self.backend.matching_partition("a", self.release, "usr"))

    def test_fresh_install_rejects_a_partial_os_label_without_state_or_esp_labels(self):
        config, manifest = host(), release()
        proposed = calculate(config, devices(), manifest)
        for label in ("PVE_45.0.1.5-1.1", "ParticleVE-state-a"):
            with (
                self.subTest(label=label),
                patch("particleve.install.plan", return_value=proposed),
                patch("particleve.install.inventory.block_tree", return_value=[{"partlabel": label}]),
                self.assertRaisesRegex(Error, "fresh install refuses existing/partial"),
            ):
                install.validate_plan(config, manifest, proposed, proposed["confirmation"])
        with (
            patch("particleve.install.plan", return_value=proposed),
            patch("particleve.install.inventory.block_tree", return_value=[]),
        ):
            install.validate_plan(config, manifest, proposed, proposed["confirmation"])
