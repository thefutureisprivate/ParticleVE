import unittest
from pathlib import Path
from unittest.mock import patch

from particleve import witness
from particleve.admission import VARIABLE
from particleve.common import Error


class WitnessIsolationTests(unittest.TestCase):
    def check(self, *, privileges="1", capability=1 << 9, extra_mount=""):
        status = f"NoNewPrivs:\t{privileges}\n" + "".join(
            f"{field}:\t{capability:016x}\n" for field in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
        mountinfo = (
            "1 0 0:1 / /sys/firmware/efi/efivars ro - efivarfs efivarfs rw\n"
            f"2 1 0:1 /{VARIABLE.name} {VARIABLE} rw - efivarfs efivarfs rw\n" + extra_mount
        )

        def contents(path):
            return status if str(path).endswith("/status") else mountinfo

        with patch.object(witness.os, "geteuid", return_value=0), patch.object(Path, "read_text", contents):
            witness.check_sandbox(VARIABLE)

    def test_only_witness_writable_and_no_privilege_gain_is_accepted(self):
        self.check()

    def test_no_new_privileges_and_no_mount_capability_are_mandatory(self):
        with self.assertRaisesRegex(Error, "isolated launcher"):
            self.check(privileges="0")
        with self.assertRaisesRegex(Error, "CAP_LINUX_IMMUTABLE"):
            self.check(capability=(1 << 9) | (1 << 21))

    def test_writable_firmware_directory_is_rejected(self):
        with self.assertRaisesRegex(Error, "only the existing witness"):
            self.check(extra_mount="3 1 0:1 / /other-efi rw - efivarfs efivarfs rw\n")

    def test_launcher_exposes_one_writable_file_and_drops_other_capabilities(self):
        arguments = witness.command(VARIABLE)
        self.assertEqual(arguments.count("--bind"), 1)
        index = arguments.index("--bind")
        self.assertEqual(arguments[index + 1 : index + 3], [str(VARIABLE), str(VARIABLE)])
        self.assertEqual(arguments[arguments.index("--cap-drop") + 1], "ALL")
        self.assertEqual(arguments[arguments.index("--cap-add") + 1], "CAP_LINUX_IMMUTABLE")
