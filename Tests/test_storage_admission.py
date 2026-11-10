"""Compiled mirror authority transitions; syscall/failure paths are Rust/native tests."""

import uuid

from Tests.runtime import RustDriverTests


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


class AdmissionTests(RustDriverTests):
    def test_stale_return_cannot_readmit_itself_and_stale_only_fails(self):
        clean = witness()
        degraded = self.evaluate("admission-choose", record=clean, present=["b"])
        self.assertEqual(degraded["allowed"], ["b"])
        degraded["active"] = False
        returned = self.evaluate("admission-choose", record=degraded, present=["a", "b"])
        self.assertEqual(returned["allowed"], ["b"])
        self.assertIn(
            "quarantined", self.request("admission-choose", record=degraded, present=["a"])["error"]
        )

    def test_unclean_session_needs_owner_review_even_if_both_members_return(self):
        for present in (["a", "b"], ["a"], ["b"]):
            active = self.evaluate("admission-choose", record=witness(), present=present)
            self.assertIn(
                "unclean", self.request("admission-choose", record=active, present=["a", "b"])["error"]
            )

    def test_manifest_bindings_preserve_role_partition_and_luks_identity(self):
        record = witness()
        manifest = {
            "devices": [
                {
                    "role": role,
                    "state_luks_uuid": member["luks"],
                    "partitions": [
                        {"role": kind, "uuid": value} for kind, value in member.items() if kind != "luks"
                    ],
                }
                for role, member in record["members"].items()
            ]
        }
        self.assertEqual(self.evaluate("admission-bindings", manifest=manifest), record["members"])

    def test_quarantined_return_may_never_appear_as_an_active_mapper(self):
        manifest = {
            "devices": [
                {
                    "role": "a",
                    "path": "/dev/disposable-returned",
                    "btrfs_devid": 1,
                    "partitions": [{"role": "state", "uuid": "old"}],
                }
            ]
        }
        row = {"devid": 1, "size": 100, "used": 0, "path": "/dev/mapper/particleve-state-a"}
        self.assertIn(
            "quarantined",
            self.request("storage-present-members", manifest=manifest, devices=[row], admitted=["b"])[
                "error"
            ],
        )
