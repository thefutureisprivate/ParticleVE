import contextlib
import copy
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import admission, install
from particleve.common import Error, read_json, write_json
from particleve.storage import present_members


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


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(admission, "lock", return_value=contextlib.nullcontext()))

    def test_stale_member_never_readmits_itself_and_stale_only_fails(self):
        clean = witness()
        degraded = admission.choose(clean, ["b"])
        self.assertEqual(degraded["allowed"], ["b"])
        # Model reboot following degraded writes, with the stale peer returning.
        returned = admission.choose({**degraded, "active": False}, ["a", "b"])
        self.assertEqual(returned["allowed"], ["b"])
        with self.assertRaisesRegex(Error, "quarantined"):
            admission.choose({**degraded, "active": False}, ["a"])

    def test_unclean_two_member_session_needs_owner_selection_even_with_both_present(self):
        active = admission.choose(witness(), ["a", "b"])
        for present in (["a", "b"], ["a"], ["b"]):
            with self.subTest(present=present), self.assertRaisesRegex(Error, "unclean"):
                admission.choose(active, present)

    def test_unclean_single_authority_also_requires_owner_review(self):
        active = admission.choose(witness(), ["b"])
        with self.assertRaisesRegex(Error, "unclean"):
            admission.choose(active, ["a", "b"])

    def test_failed_witness_commit_cannot_unlock_or_scan(self):
        with (
            patch.object(admission, "load", return_value=witness()),
            patch.object(admission.Path, "exists", return_value=True),
            patch.object(admission, "disk_sequence", return_value="1"),
            patch.object(admission, "_write_existing", side_effect=OSError("firmware full")),
            patch.object(admission, "write_json") as session,
            patch.object(admission, "run") as commands,
            self.assertRaises(OSError),
        ):
            admission.begin()
        session.assert_not_called()
        commands.assert_not_called()

    def test_missing_or_malformed_witness_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(admission, "VARIABLE", Path(tmp) / "nv"):
            with self.assertRaisesRegex(Error, "owner recovery"):
                admission.load()
            admission.VARIABLE.write_bytes(b"\x07\0\0\0{}")
            with self.assertRaises(Error):
                admission.load()

    def test_shutdown_cannot_mark_clean_while_any_btrfs_subvolume_is_writable(self):
        record = admission.choose(witness(), ["a", "b"])
        with (
            patch.object(admission, "read_json", return_value={"witness": record}),
            patch.object(
                admission,
                "mounts",
                return_value=[{"options": "ro", "target": "/"}, {"options": "rw", "target": "/var"}],
            ),
            patch.object(admission, "load", return_value=record),
            patch.object(
                admission,
                "run",
                return_value=SimpleNamespace(
                    stdout='{"filesystems":[{"options":"ro"},{"options":"rw,subvol=var"}]}'
                ),
            ),
            patch.object(admission, "save") as commit,
            self.assertRaisesRegex(Error, "still writable"),
        ):
            admission.finish()
        commit.assert_not_called()

    def test_shutdown_disk_replug_cannot_mark_clean(self):
        record = admission.choose(witness(), ["a", "b"])
        with (
            patch.object(
                admission, "read_json", return_value={"witness": record, "diskseq": {"a": "1", "b": "2"}}
            ),
            patch.object(admission, "load", return_value=record),
            patch.object(
                admission, "run", return_value=SimpleNamespace(stdout='{"filesystems":[{"options":"ro"}]}')
            ),
            patch.object(admission, "mounts", return_value=[{"options": "ro", "target": "/"}]),
            patch.object(admission, "disk_sequence", return_value="3"),
            patch.object(admission, "save") as commit,
            self.assertRaisesRegex(Error, "disappeared or returned"),
        ):
            admission.finish()
        commit.assert_not_called()

    def test_recovery_can_only_reduce_authority_and_requires_unmounted_storage(self):
        record = admission.choose(witness(), ["b"])
        with (
            patch.object(admission, "load", return_value=record),
            patch.object(admission.Path, "exists", return_value=False),
            patch.object(admission, "disk_sequence", return_value="1"),
            patch.object(admission, "_write_existing") as commit,
        ):
            with self.assertRaisesRegex(Error, "cannot authorize itself"):
                admission.recover("a", record["installation_uuid"])
            admission.recover("b", record["installation_uuid"])
            self.assertEqual(commit.call_args.args[0]["allowed"], ["b"])
            commit.reset_mock()
            with patch.object(admission.Path, "exists", return_value=True), self.assertRaises(Error):
                admission.recover("b", record["installation_uuid"])
            commit.assert_not_called()

    def test_readmission_requires_new_identity_and_preserves_survivor(self):
        record = admission.choose(witness(), ["b"])
        manifest = {
            "installation_uuid": record["installation_uuid"],
            "devices": [
                {
                    "role": r,
                    "state_luks_uuid": m["luks"],
                    "partitions": [{"role": k, "uuid": v} for k, v in m.items() if k != "luks"],
                }
                for r, m in record["members"].items()
            ],
        }
        with patch.object(admission, "load", return_value=record), patch.object(admission, "save") as commit:
            with self.assertRaisesRegex(Error, "erase"):
                admission.readmit(manifest, "a")
            commit.assert_not_called()
            changed = copy.deepcopy(manifest)
            for part in changed["devices"][0]["partitions"]:
                part["uuid"] = str(uuid.uuid4())
            changed["devices"][0]["state_luks_uuid"] = str(uuid.uuid4())
            with (
                patch.object(admission, "disk_sequence", return_value="1"),
                patch.object(admission, "write_json"),
            ):
                admission.readmit(changed, "a")
            self.assertEqual(commit.call_args.args[0]["allowed"], ["a", "b"])

    def test_quarantined_return_may_be_physically_present_but_never_mapped(self):
        manifest = {
            "devices": [
                {
                    "role": "a",
                    "path": "/dev/returned",
                    "btrfs_devid": 1,
                    "partitions": [{"role": "state", "uuid": "old"}],
                }
            ]
        }
        row = {"devid": 1, "size": 0, "used": 0, "path": "MISSING"}
        # No surviving row in this tiny inventory: importantly, the present old
        # physical disk is permitted only as MISSING, never as an active replica.
        with (
            patch("particleve.storage.Path.exists", side_effect=lambda p=None: False),
            self.assertRaisesRegex(Error, "no recorded"),
        ):
            present_members(manifest, [row], admitted=["b"])
        row.update(size=100, path="/dev/mapper/particleve-state-a")
        with self.assertRaisesRegex(Error, "quarantined"):
            present_members(manifest, [row], admitted=["b"])

    def test_mounted_identity_survives_unreadable_media_and_ignores_unselected_storage(self):
        record = witness()
        import json

        table = {
            "filesystems": [
                {"source": "/dev/unselected", "options": "rw", "target": "/other"},
                {"source": "/dev/mapper/particleve-state-b[/var]", "options": "ro", "target": "/var"},
                {"source": "/dev/mapper/particleve-state-b", "options": "ro", "target": "/"},
            ]
        }
        with (
            patch.object(admission, "run", return_value=SimpleNamespace(stdout=json.dumps(table))) as command,
            patch.object(admission, "mounted_uuid", return_value=record["btrfs_uuid"]) as identity,
        ):
            self.assertEqual([m["target"] for m in admission.mounts(record)], ["/", "/var"])
        self.assertNotIn("UUID", command.call_args.args[0][-1])
        self.assertEqual([c.args[0] for c in identity.call_args_list], ["/var", "/"])

    def test_finalization_never_readmits_single_allocations(self):
        backend = SimpleNamespace(directory=Path("/unused"), manifest={}, config={})
        report = {
            "devices": [{}, {}],
            "swap_degraded": 0,
            "swap_sync_action": "idle",
            "allocation": [{"profile": "raid1"}, {"profile": "single"}],
        }
        with (
            patch.object(install, "read_json", return_value={"role": "a"}),
            patch("particleve.storage.status", return_value=report),
            patch.object(admission, "readmit") as commit,
            self.assertRaisesRegex(Error, "RAID1"),
        ):
            install.finalize_replacement(backend)
        commit.assert_not_called()

    def test_state_crypttab_is_noauto(self):
        content = install.crypttab(
            {"devices": [{"role": "a", "state_luks_uuid": "test"}], "swap": {"luks_uuid": "swap"}}
        )
        self.assertIn("noauto,tpm2-device=auto", content)

    def test_hot_error_is_revoked_before_live_mapping_is_fenced(self):
        record = admission.choose(witness(), ["a", "b"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session"
            write_json(path, {"witness": record, "diskseq": {"a": "1", "b": "2"}})
            events = []
            stats = "\n".join(
                f"[/dev/mapper/particleve-state-{r}].{k} {int(r == 'a' and k == 'write_io_errs')}"
                for r in ("a", "b")
                for k in (
                    "write_io_errs",
                    "read_io_errs",
                    "flush_io_errs",
                    "corruption_errs",
                    "generation_errs",
                )
            )

            def command(args, **kwargs):
                events.append(args)
                return SimpleNamespace(
                    returncode=64 if args[0] == "btrfs" else 0, stdout=stats if args[0] == "btrfs" else "1000"
                )

            with (
                patch.object(admission, "SESSION", path),
                patch.object(admission, "lock", return_value=__import__("contextlib").nullcontext()),
                patch.object(admission, "load", return_value=record),
                patch.object(admission, "mounts", return_value=[{"options": "rw", "target": "/"}]),
                patch.object(admission, "disk_sequence", side_effect=["1", "2"]),
                patch.object(
                    admission, "save", side_effect=lambda r: events.append(["commit", r["allowed"]])
                ),
                patch.object(admission, "run", side_effect=command),
                self.assertRaisesRegex(Error, "fenced and quarantined"),
            ):
                admission.watch()
            self.assertLess(
                events.index(["commit", ["b"]]),
                next(i for i, e in enumerate(events) if e[:2] == ["dmsetup", "suspend"]),
            )
            self.assertEqual(read_json(path)["witness"]["allowed"], ["b"])
            self.assertIn(["dmsetup", "reload", "particleve-state-a", "--table", "0 1000 error"], events)

    def test_failed_quarantine_commit_still_fences_and_failed_reload_never_resumes(self):
        for reload_fails in (False, True):
            with self.subTest(reload_fails=reload_fails), tempfile.TemporaryDirectory() as tmp:
                record = admission.choose(witness(), ["b"])
                path = Path(tmp) / "session"
                session = {"witness": record, "diskseq": {"b": "1"}}
                write_json(path, session)
                commands = []

                def command(args, commands=commands, reload_fails=reload_fails, **kwargs):
                    commands.append(args)
                    if args[:2] == ["dmsetup", "reload"] and reload_fails:
                        raise Error("reload failed")
                    return SimpleNamespace(returncode=64 if args[0] == "btrfs" else 0, stdout="1000")

                with (
                    patch.object(admission, "SESSION", path),
                    patch.object(admission, "load", return_value=record),
                    patch.object(admission, "mounts", return_value=[{"target": "/"}]),
                    patch.object(admission, "disk_sequence", side_effect=OSError("disk gone")),
                    patch.object(admission, "save", side_effect=OSError("firmware full")),
                    patch.object(admission, "run", side_effect=command),
                    self.assertRaisesRegex(Error, "reload failed" if reload_fails else "fenced"),
                ):
                    admission.watch()
                self.assertIn(
                    ["dmsetup", "suspend", "--noflush", "--nolockfs", "particleve-state-b"], commands
                )
                self.assertEqual(["dmsetup", "resume", "particleve-state-b"] in commands, not reload_fails)
                self.assertEqual(read_json(path), session)
