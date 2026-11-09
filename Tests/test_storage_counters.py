import errno
import stat
import struct
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import admission
from particleve.common import Error


class MemberCounterTests(unittest.TestCase):
    def setUp(self):
        self.record = {"btrfs_uuid": str(uuid.uuid4())}
        self.fsid = self.record["btrfs_uuid"]
        self.entries = ["0", "1", "2"]
        self.paths = {1: b"/dev/mapper/target", 2: b"/dev/mapper/survivor"}
        self.stats = (0, 0, 0, 0, 0)
        self.stats_header = (2, 5, 0)
        self.queries = []
        self.disappeared = set()
        self.stats_error = None
        self.device_error = None
        self.returned_id = None
        self.block = True

    def ioctl(self, fd, request, data, mutate):
        self.assertEqual(fd, 123)
        self.assertTrue(mutate)
        if request == 0x8400941F:
            self.assertEqual(len(data), 1024)
            data[16:32] = uuid.UUID(self.fsid).bytes
        elif request == 0xD000941E:
            self.assertEqual(len(data), 4096)
            devid = struct.unpack_from("=Q", data)[0]
            self.queries.append(("device", devid))
            if self.device_error:
                raise self.device_error
            if devid in self.disappeared:
                raise OSError(errno.ENODEV, "replacement target disappeared")
            path = self.paths[devid]
            data[3072 : 3072 + len(path)] = path
            if self.returned_id is not None:
                struct.pack_into("=Q", data, 0, self.returned_id)
        else:
            self.assertEqual(request, 0xC4089434)
            self.assertEqual(len(data), 1032)
            header = struct.unpack_from("=QQQ", data)
            self.assertEqual(header, (2, 5, 0))  # Never reset counters or query the target.
            self.queries.append(("stats", header[0]))
            if self.stats_error:
                raise self.stats_error
            struct.pack_into("=QQQ5Q", data, 0, *self.stats_header, *self.stats)
        return 0

    def observe(self):
        def entries(path):
            self.assertEqual(path, Path("/sys/fs/btrfs", self.record["btrfs_uuid"], "devinfo"))
            return iter(Path(path, name) for name in self.entries)

        with (
            patch.object(admission.Path, "resolve", autospec=True, side_effect=lambda path, **_: path),
            patch.object(
                admission.Path,
                "stat",
                return_value=SimpleNamespace(st_mode=stat.S_IFBLK if self.block else stat.S_IFREG),
            ),
            patch.object(admission.Path, "iterdir", autospec=True, side_effect=entries),
            patch.object(admission.os, "open", return_value=123) as opened,
            patch.object(admission.os, "close") as closed,
            patch.object(admission.fcntl, "ioctl", side_effect=self.ioctl),
        ):
            try:
                return admission.member_errors(self.record, "/state", "/dev/mapper/survivor")
            finally:
                if opened.called:
                    self.assertEqual(opened.call_args.args[0], "/state")
                    closed.assert_called_once_with(123)

    def test_selected_survivor_stays_observable_across_replacement_handoff(self):
        for entries, vanished in ((["0", "2"], set()), (["1", "2"], {1}), (["1", "2"], set())):
            with self.subTest(entries=entries, vanished=vanished):
                self.entries, self.disappeared = entries, vanished
                self.queries.clear()
                self.assertEqual(self.observe(), (0,) * 5)
                self.assertEqual([q for q in self.queries if q[0] == "stats"], [("stats", 2)])
                self.assertNotIn(("device", 0), self.queries)

    def test_every_counter_is_preserved_without_reset_or_truncation(self):
        self.stats = (1, 2**64 - 1, 3, 4, 5)
        self.assertEqual(self.observe(), self.stats)

    def test_missing_or_ambiguous_survivor_never_uses_target_as_authority(self):
        for paths, vanished in (
            ({1: b"/dev/mapper/target", 2: b""}, set()),
            (self.paths, {2}),
            ({1: b"/dev/mapper/survivor", 2: b"/dev/mapper/survivor"}, set()),
        ):
            with self.subTest(paths=paths, vanished=vanished):
                self.paths, self.disappeared = paths, vanished
                self.queries.clear()
                with self.assertRaisesRegex(Error, "unavailable or ambiguous"):
                    self.observe()
                self.assertFalse(any(q[0] == "stats" for q in self.queries))

    def test_selected_stats_failure_and_other_ioctl_errors_propagate(self):
        self.stats_error = OSError(errno.ENODEV, "survivor disappeared")
        with self.assertRaises(OSError):
            self.observe()
        self.stats_error = None
        self.device_error = OSError(errno.EIO, "device query failed")
        with self.assertRaises(OSError):
            self.observe()

    def test_wrong_filesystem_or_nonblock_mapping_cannot_supply_counters(self):
        self.fsid = str(uuid.uuid4())
        with self.assertRaisesRegex(Error, "filesystem changed"):
            self.observe()
        self.fsid = self.record["btrfs_uuid"]
        self.block = False
        with self.assertRaisesRegex(Error, "not a block device"):
            self.observe()

    def test_device_inventory_is_bounded_and_canonical(self):
        for entries in ([], ["0", "1", "2", "3"], ["02"], ["-1"], ["x"], [str(2**64)], ["2", "2"]):
            with self.subTest(entries=entries), self.assertRaises(Error):
                self.entries = entries
                self.observe()

    def test_device_identity_and_path_must_be_complete(self):
        for path in (b"relative", b"x" * 1024, b"/dev/\xff"):
            with self.subTest(path=path[:20]), self.assertRaises((Error, UnicodeDecodeError)):
                self.paths[1] = path
                self.observe()
        self.paths[1] = b"/dev/mapper/target"
        self.returned_id = 9
        with self.assertRaisesRegex(Error, "identity changed"):
            self.observe()

    def test_stats_response_cannot_change_identity_count_or_reset_flag(self):
        for header in ((1, 5, 0), (2, 4, 0), (2, 5, 1)):
            with self.subTest(header=header), self.assertRaisesRegex(Error, "incomplete"):
                self.stats_header = header
                self.observe()
