import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from particleve.landlock import (
    CLOSE_RANGE,
    CREATE_RULESET,
    FS_WRITES,
    RESTRICT_SELF,
    abi_version,
    confine_filesystem,
)


class SenderFilesystemTests(unittest.TestCase):
    def test_missing_kernel_abi_never_silently_reduces_protection(self):
        for abi in (-1, 0, 1, 4):
            api = SimpleNamespace(syscall=lambda *_args, value=abi: value)
            with patch("particleve.landlock._libc", return_value=api), self.assertRaisesRegex(Error, "ABI 5"):
                abi_version()

    def test_irreversible_handoff_closes_descriptors_and_enforces_every_required_right(self):
        for failure in (None, CLOSE_RANGE, "create", RESTRICT_SELF):
            events = []

            def syscall(number, *args, failure=failure, events=events):
                if number == CREATE_RULESET and args[-1].value == 1:
                    return 10
                events.append(number)
                if number == CLOSE_RANGE:
                    self.assertEqual([a.value for a in args], [3, 0xFFFFFFFF, 0])
                    return -1 if failure == CLOSE_RANGE else 0
                if number == CREATE_RULESET:
                    self.assertEqual(args[0]._obj.value, FS_WRITES)
                    return -1 if failure == "create" else 101
                self.assertEqual(number, RESTRICT_SELF)
                self.assertEqual(args[0].value, 101)
                return -1 if failure == RESTRICT_SELF else 0

            with (
                self.subTest(failure=failure),
                patch("particleve.landlock._libc", return_value=SimpleNamespace(syscall=syscall)),
                patch("particleve.landlock.os.close") as close,
            ):
                if failure:
                    with self.assertRaises(Error):
                        confine_filesystem()
                else:
                    self.assertEqual(confine_filesystem(), 10)
                    self.assertEqual(events, [CLOSE_RANGE, CREATE_RULESET, RESTRICT_SELF])
                if failure in (None, RESTRICT_SELF):
                    close.assert_called_once_with(101)
                else:
                    close.assert_not_called()

    def test_existing_sibling_threads_cannot_escape_the_filesystem_boundary(self):
        with (
            patch.object(Path, "iterdir", return_value=iter([Path("1"), Path("2")])),
            patch("particleve.landlock._libc") as kernel,
            self.assertRaisesRegex(Error, "single-threaded"),
        ):
            confine_filesystem()
        kernel.assert_not_called()
