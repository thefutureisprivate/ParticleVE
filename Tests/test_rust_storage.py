"""Check compiled mirror policies and layout wire contracts without a Python runtime oracle."""

import random
import uuid

from particleve.common import digest
from particleve.layout import GIB, MIB, TYPES
from Tests.fixtures import devices, host, release
from Tests.runtime import RustDriverTests


class RustStorageTests(RustDriverTests):
    @staticmethod
    def witness():
        return {
            "schema": 1,
            "installation_uuid": str(uuid.uuid4()),
            "btrfs_uuid": str(uuid.uuid4()),
            "members": {
                role: {kind: str(uuid.uuid4()) for kind in ("state", "swap", "esp", "luks")}
                for role in ("a", "b")
            },
            "allowed": ["a", "b"],
            "active": False,
            "nonce": str(uuid.uuid4()),
            "wait_seconds": 5,
        }

    def test_admission_decision_table_and_strict_schema(self):
        record = self.witness()
        for allowed in ([], ["a"], ["b"], ["a", "b"]):
            for present in ([], ["a"], ["b"], ["a", "b"]):
                for active in (False, True):
                    candidate = record | {"allowed": allowed, "active": active}
                    response = self.request("admission-choose", record=candidate, present=present)
                    authoritative = [role for role in allowed if role in present]
                    if active or not authoritative:
                        self.assertIn("error", response)
                    else:
                        observed = response["ok"]
                        self.assertEqual(str(uuid.UUID(observed["nonce"])), observed["nonce"])
                        expected = candidate | {
                            "allowed": authoritative,
                            "active": True,
                            "nonce": observed["nonce"],
                        }
                        self.assertEqual(observed, expected)
        for candidate in (
            record | {"extra": 1},
            record | {"schema": True},
            record | {"active": 0},
            record | {"wait_seconds": 4},
            record | {"wait_seconds": 121},
            record | {"allowed": ["a", "a"]},
            record | {"allowed": ["c"]},
            record | {"nonce": record["nonce"].upper()},
        ):
            self.assertIn("error", self.request("admission-validate", record=candidate))

    def check_layout(self, value, config, observed, manifest):
        original = {key: item for key, item in value.items() if key != "confirmation"}
        self.assertEqual(value["confirmation"], digest(original))
        self.assertEqual(value["config_sha256"], digest(config))
        self.assertEqual(value["release_sha256"], digest(manifest))
        self.assertEqual(value["release"], manifest["version"])
        self.assertEqual(value["storage_admission"], "uefi-witness-v1")
        self.assertEqual(
            value["storage_policy"],
            {
                "filesystem": "btrfs",
                "data": "raid1",
                "metadata": "raid1",
                "factory_reset": False,
                "subvolumes": ["/var"],
            },
        )
        generated = [value["installation_uuid"]]
        expected_roles = [
            "esp",
            "a_verity_sig",
            "a_verity",
            "a_usr",
            "b_verity_sig",
            "b_verity",
            "b_usr",
            "state",
            "swap",
        ]
        end = (min(device["size"] for device in observed) // MIB - 1) * MIB
        for index, disk in enumerate(value["devices"]):
            self.assertEqual(disk["observed"], observed[index])
            self.assertEqual(disk["path"], config["disks"][index]["path"])
            self.assertEqual([part["role"] for part in disk["partitions"]], expected_roles)
            generated.append(disk["disk_uuid"])
            offset = MIB
            for number, part in enumerate(disk["partitions"], 1):
                self.assertEqual(part["number"], number)
                self.assertEqual(part["offset"], offset)
                self.assertEqual(part["offset"] % observed[index]["logical_sector"], 0)
                self.assertEqual(part["size"] % MIB, 0)
                self.assertGreater(part["size"], 0)
                offset += part["size"]
                role = part["role"]
                if role.startswith(("a_", "b_")):
                    kind = role[2:]
                    self.assertEqual(part["type"], TYPES[kind])
                    self.assertGreaterEqual(part["size"], manifest["artifacts"][kind]["size"])
                    if kind == "verity_sig":
                        self.assertEqual(part["size"], MIB)
                    if role.startswith("a_"):
                        self.assertEqual(part["uuid"], manifest["artifacts"][kind]["partition_uuid"])
                        self.assertEqual(part["label"], "PVE_" + manifest["version"])
                        continue
                    self.assertEqual(part["label"], "_empty")
                generated.append(part["uuid"])
                if role == "state":
                    self.assertEqual(part["size"], value["state_usable_bytes"] + 32 * MIB)
            self.assertEqual(offset, end)
        self.assertEqual(len(generated), len(set(generated)))
        for value in generated:
            self.assertEqual(str(uuid.UUID(value)), value)

    def test_layout_geometry_hashes_and_capacity_boundaries(self):
        generator = random.Random(0x505645)
        for _ in range(30):
            config, observed, manifest = host(), devices(), release()
            for device in observed:
                device["size"] = generator.randrange(80, 1024) * GIB
                device["logical_sector"] = generator.choice((512, 4096))
            config["storage"]["usr_growth_percent"] = generator.randrange(0, 60)
            config["storage"]["reserve_percent"] = generator.randrange(1, 20)
            actual = self.evaluate("layout-calculate", config=config, devices=observed, release=manifest)
            self.check_layout(actual, config, observed, manifest)
        for size in (0, 1, MIB, 16 * GIB):
            observed = devices()
            observed[0]["size"] = size
            self.assertIn(
                "error", self.request("layout-calculate", config=host(), devices=observed, release=release())
            )
        observed = devices()
        observed[1]["identity"] = observed[0]["identity"]
        self.assertIn(
            "error", self.request("layout-calculate", config=host(), devices=observed, release=release())
        )

    def test_btrfs_native_output_contract_preserves_every_allocated_profile(self):
        source = (
            "Data, RAID1: total=1000, used=10\nMetadata, RAID1: total=500, used=10\n"
            "System, single: total=100, used=0\nGlobalReserve, single: total=50, used=0\n"
        )
        expected = [
            {"kind": "data", "profile": "raid1", "total": 1000, "used": 10},
            {"kind": "metadata", "profile": "raid1", "total": 500, "used": 10},
            {"kind": "system", "profile": "single", "total": 100, "used": 0},
        ]
        self.assertEqual(self.evaluate("storage-profiles", text=source), expected)
        for malformed in ("", "Data, single: total=1, used=1\n"):
            self.assertIn("error", self.request("storage-profiles", text=malformed))
        self.assertEqual(
            self.evaluate(
                "storage-members",
                text=(
                    "devid 1 size 100 used 20 path /dev/mapper/state-a\n"
                    "  devid 2 size 0 used 0 path MISSING\n"
                ),
            ),
            [
                {"devid": 1, "size": 100, "used": 20, "path": "/dev/mapper/state-a"},
                {"devid": 2, "size": 0, "used": 0, "path": "MISSING"},
            ],
        )
