"""Real compiled syscall boundary; counter handoff/faults use the native Btrfs probe."""

import tempfile
import uuid
from pathlib import Path

from Tests.runtime import RustDriverTests


class MemberCounterBoundaryTests(RustDriverTests):
    def test_nonblock_mapping_is_rejected_before_any_filesystem_ioctl(self):
        with tempfile.TemporaryDirectory() as directory:
            mapper = Path(directory) / "ordinary-file"
            mapper.write_bytes(b"not a storage member")
            response = self.request(
                "admission-member-errors",
                record={"btrfs_uuid": str(uuid.uuid4())},
                target=directory,
                mapper=str(mapper),
            )
            self.assertIn("not a block device", response["error"])

    def test_mounted_identity_requires_a_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            ordinary = Path(directory) / "ordinary-file"
            ordinary.write_bytes(b"not a mounted filesystem directory")
            response = self.request("admission-mounted-uuid", target=str(ordinary))
            self.assertIn("error", response)
