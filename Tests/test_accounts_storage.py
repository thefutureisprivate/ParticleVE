import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from particleve import accounts
from particleve.common import Error
from particleve.storage import members, present_members, profiles


class AccountStorageTests(unittest.TestCase):
    def test_root_does_not_depend_on_homed(self):
        with patch.object(accounts, "run", side_effect=AssertionError("root must retain recovery access")):
            accounts.authorize_login("root")

    def test_nonroot_ssh_account_must_come_from_homed(self):
        with patch.object(
            accounts, "run", return_value=SimpleNamespace(stdout=json.dumps({"userName": "admin"}))
        ) as query:
            accounts.authorize_login("admin")
        self.assertIn("--service=io.systemd.Home", query.call_args.args[0])
        self.assertIn("--with-nss=no", query.call_args.args[0])
        with patch.object(accounts, "run", side_effect=Error("not found")), self.assertRaises(Error):
            accounts.authorize_login("classic-user")

    def test_regular_classic_users_are_reported(self):
        with (
            patch.object(
                accounts.Path, "read_text", return_value="classic:x:1000:1000::/home/classic:/bin/bash"
            ),
            self.assertRaises(Error),
        ):
            accounts.check()

    def test_nonlogin_system_commands_are_not_classic_login_shells(self):
        def contents(path):
            return (
                ("root:x:0:0::/root:/bin/bash\nsync:x:5:0::/sbin:/bin/sync\nhalt:x:7:0::/sbin:/sbin/halt\n")
                if str(path) == "/etc/passwd"
                else "/bin/bash\n"
            )

        with patch.object(accounts.Path, "read_text", contents), patch.object(accounts, "run"):
            self.assertEqual(accounts.check()["non_root_logins"], "homed")

    def test_btrfs_allocation_profiles_include_every_allocated_group(self):
        report = profiles(
            "Data, RAID1: total=1000, used=100\nMetadata, RAID1: total=200, used=20\n"
            "Data, single: total=300, used=30\nGlobalReserve, single: total=100, used=0\n"
        )
        self.assertEqual([r["profile"] for r in report], ["raid1", "raid1", "single"])
        with self.assertRaises(Error):
            profiles("unknown output")

    def test_btrfs_members_resolve_persistent_mapper_paths(self):
        report = members(
            "\tdevid    1 size 10000 used 1000 path /dev/mapper/particleve-state-a\n"
            "\tdevid    2 size 10000 used 1000 path /dev/mapper/particleve-state-b\n"
        )
        self.assertEqual([d["devid"] for d in report], [1, 2])

    def test_degraded_inventory_validates_survivor_and_absent_recorded_member(self):
        manifest = {
            "devices": [
                {
                    "role": role,
                    "path": f"/dev/disk/by-id/test-{role}",
                    "btrfs_devid": number,
                    "state_luks_uuid": f"luks-{role}",
                    "partitions": [{"role": "state", "uuid": f"state-{role}"}],
                }
                for number, role in enumerate(("a", "b"), 1)
            ]
        }
        rows = members(
            "devid 1 size 0 used 0 path  MISSING\n"
            "devid 2 size 10000 used 1000 path /dev/mapper/particleve-state-b\n"
        )
        with (
            patch("particleve.storage.Path.exists", return_value=False),
            patch(
                "particleve.storage.run",
                side_effect=[
                    SimpleNamespace(stdout="luks-b\n"),
                    SimpleNamespace(stdout="  device: /dev/disk/by-partuuid/state-b\n"),
                ],
            ) as commands,
        ):
            self.assertEqual(present_members(manifest, rows), [rows[1]])
            self.assertEqual(commands.call_count, 2)
        with patch("particleve.storage.Path.exists", return_value=True), self.assertRaises(Error):
            present_members(manifest, rows)
        rows[0]["devid"] = 3
        with self.assertRaisesRegex(Error, "unrecorded"):
            present_members(manifest, rows)


if __name__ == "__main__":
    unittest.main()
