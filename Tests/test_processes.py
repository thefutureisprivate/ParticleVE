import errno
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve import processes
from particleve.common import Error
from particleve.confinement import verify_processes
from particleve.security import process_evidence


class ProcessObservationTests(unittest.TestCase):
    def test_replaced_numeric_directory_never_redirects_a_pinned_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            directory = proc / "123"
            directory.mkdir()
            (directory / "status").write_text("Name: original\n")
            (directory / "stat").write_text("123 (spaces and ) parentheses)) S " + "0 " * 18 + "42\n")
            with processes.observe(123, proc=proc, starttime=42) as process:
                descriptor = process.descriptor
                self.assertFalse(os.get_inheritable(descriptor))
                directory.rename(proc / "old")
                directory.mkdir()
                (directory / "status").write_text("Name: replacement\n")
                (directory / "stat").write_text("123 (replacement) S " + "0 " * 18 + "43\n")
                self.assertEqual(process.status(), {"Name": "original"})
                self.assertEqual(process.identity(), {"pid": 123, "starttime": 42})
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            for inspect in (process_evidence, lambda identity, **kw: verify_processes([identity], **kw)):
                with self.subTest(inspect=inspect), self.assertRaisesRegex(Error, "identity changed"):
                    inspect({"pid": 123, "starttime": 42}, proc=proc)

    def test_native_child_exit_cannot_become_a_successful_observation(self):
        # Observe only our inert child; closing its stdin ends it without a
        # signal. The native proc FD remains tied to that reaped task.
        with (
            subprocess.Popen(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"], stdin=subprocess.PIPE
            ) as child,
            processes.observe(child.pid) as process,
        ):
            self.assertEqual(process.identity()["pid"], child.pid)
            self.assertEqual(process.status()["Pid"], str(child.pid))
            self.assertEqual(process.arguments()[0], sys.executable)
            self.assertIn("pid", process.entries("ns", processes.MAX_NAMESPACES))
            child.stdin.close()
            child.wait(timeout=10)
            with self.assertRaises((FileNotFoundError, ProcessLookupError)):
                process.status()

    def test_byte_and_directory_bounds_reject_excess_instead_of_truncating(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            directory = proc / "123"
            directory.mkdir()
            (directory / "status").write_bytes(b"Name: ab")
            (directory / "cmdline").write_bytes(b"qemu\0abc")
            (directory / "fd").mkdir()
            for name in ("1", "2", "3"):
                (directory / "fd" / name).touch()
            with processes.observe(123, proc=proc) as process:
                self.assertEqual(process.read_bytes("status", 8), b"Name: ab")
                self.assertEqual(len(process.entries("fd", 3)), 3)
                with self.assertRaisesRegex(Error, "bound"):
                    process.read_bytes("status", 7)
                with self.assertRaisesRegex(Error, "bound"):
                    process.entries("fd", 2)
                with patch.object(processes, "MAX_STATUS", 7), self.assertRaisesRegex(Error, "bound"):
                    process.status()
                with patch.object(processes, "MAX_CMDLINE", 7), self.assertRaisesRegex(Error, "bound"):
                    process.arguments()
                # A refused directory observation also releases its descriptors.
                self.assertEqual(process.status()["Name"], "ab")

    def test_malformed_kernel_records_and_symlinked_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            directory = proc / "123"
            directory.mkdir()
            with processes.observe(123, proc=proc) as process:
                for content in (b"", b"Seccomp: 0\nSeccomp: 2\n", b"no separator\n", b"Name: \xff\n"):
                    (directory / "status").write_bytes(content)
                    with self.subTest(content=content), self.assertRaises(Error):
                        process.status()
                (directory / "cmdline").write_bytes(b"qemu\0\xff")
                with self.assertRaisesRegex(Error, "encoding"):
                    process.arguments()
                (directory / "status").unlink()
                (directory / "status").symlink_to("cmdline")
                with self.assertRaises(OSError) as symbolic:
                    process.status()
                self.assertEqual(symbolic.exception.errno, errno.ELOOP)


if __name__ == "__main__":
    unittest.main()
