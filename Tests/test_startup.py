import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import startup
from particleve.common import Error, write_json
from particleve.network import render
from Tests.fixtures import host


class StartupPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        (self.root / "etc").mkdir()
        for name in ("bin", "sbin", "lib", "lib64"):
            (self.root / name).symlink_to("usr/" + name)

        # Tests run as the developer. Exercise actual descriptor traversal and
        # inode/mode checks while substituting only the fixture's owning UID.
        def owned(info, path):
            values = list(info)
            values[4] = 0
            return ORIGINAL_METADATA(os.stat_result(values), path)

        self.enterContext(patch("particleve.startup._metadata", side_effect=owned))

    def file(self, name, contents="approved configuration\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def test_reviewed_configuration_changes_are_detected_before_recommissioning(self):
        config = self.file("etc/particleve/host.json", '{"installation":"owned"}\n')
        dropin = self.file("etc/systemd/system/systemd-vmspawn@guest.service.d/80-approved.conf")
        (self.root / "etc/systemd/system/machines.target.wants").mkdir()
        (self.root / "etc/systemd/system/machines.target.wants/systemd-vmspawn@guest.service").symlink_to(
            "/usr/lib/systemd/system/systemd-vmspawn@.service"
        )
        observed = startup.check(self.root)
        receipt = self.root / "var/lib/particleve/commissioned.json"
        write_json(receipt, {"startup_policy_sha256": observed["sha256"]})
        self.assertEqual(startup.check(self.root), observed)
        self.assertNotIn("approved configuration", str(observed))
        for changed in (config, dropin):
            before = changed.read_text()
            changed.write_text(before + "unauthorized change\n")
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(Error, "startup configuration changed"),
            ):
                startup.check(self.root)
            changed.write_text(before)
        write_json(receipt, {"old": "commissioning record"})
        with self.assertRaisesRegex(Error, "lacks approval"):
            startup.check(self.root)
        self.assertEqual(receipt.read_text().count("old"), 1)

    def test_mutable_code_hooks_and_local_host_units_are_rejected(self):
        for name in (
            "etc/ld.so.preload",
            "etc/pam.d/sshd",
            "etc/modprobe.d/execute.conf",
            "etc/polkit-1/rules.d/99-injected.rules",
            "etc/udev/rules.d/99-injected.rules",
            "etc/systemd/system-generators/injected",
            "etc/systemd/system/injected.service",
            "etc/systemd/system.control/sshd.service.d/50-injected.conf",
        ):
            path = self.file(name)
            with self.subTest(name=name), self.assertRaises(Error):
                startup.inventory(self.root)
            path.unlink()

    def test_credentials_and_mode_zero_account_data_are_inspected_without_reading_contents(self):
        shadow = self.file("etc/shadow", "private test account material")
        shadow.chmod(0)
        token = self.file("etc/particleve/report-token", "first-test-token")
        token.chmod(0o400)
        before = startup.inventory(self.root)
        self.assertEqual(
            {
                row["kind"]
                for row in before["inputs"]
                if row["path"] in {"etc/shadow", "etc/particleve/report-token"}
            },
            {"account-or-credential-data"},
        )
        token.chmod(0o600)
        token.write_text("rotated-test-token")
        token.chmod(0o400)
        self.assertEqual(startup.inventory(self.root), before)

    def test_generated_serial_console_settings_remain_allowed_and_other_overrides_fail(self):
        config = host()
        config["console"] = "console=ttyS1,115200n8"
        for name, contents in render(config).items():
            self.file(name, contents)
        observed = startup.inventory(self.root)
        self.assertTrue(
            {
                "etc/systemd/system/getty.target.d/50-particleve-console.conf",
                "etc/systemd/system/serial-getty@ttyS1.service.d/50-particleve.conf",
            }
            <= {row["path"] for row in observed["inputs"]}
        )
        self.file("etc/systemd/system/serial-getty@ttyS1.service.d/90-unapproved.conf")
        with self.assertRaisesRegex(Error, "regular local units"):
            startup.inventory(self.root)

    def test_writable_links_hardlinks_special_files_and_executable_data_are_rejected(self):
        path = self.root / "etc/escape"
        for destination in ("/var/lib/machines/payload", "../../run/code", "/usr/../var/code"):
            path.symlink_to(destination)
            with self.subTest(destination=destination), self.assertRaisesRegex(Error, "escapes verified usr"):
                startup.inventory(self.root)
            path.unlink()
        path.symlink_to("/usr/share/factory/etc/profile")
        startup.inventory(self.root)
        path.unlink()
        original = self.file("etc/host-setting")
        os.link(original, path)
        with self.assertRaisesRegex(Error, "hard-linked"):
            startup.inventory(self.root)
        path.unlink()
        original.chmod(0o755)
        with self.assertRaisesRegex(Error, "executable"):
            startup.inventory(self.root)
        original.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(Error, "special file"):
            startup.inventory(self.root)

    def test_configuration_and_commissioning_parents_cannot_grant_other_writers(self):
        (self.root / "etc").chmod(0o775)
        with self.assertRaisesRegex(Error, "writable by another account"):
            startup.inventory(self.root)
        (self.root / "etc").chmod(0o755)
        receipt = self.root / "var/lib/particleve/commissioned.json"
        write_json(receipt, {"startup_policy_sha256": startup.inventory(self.root)["sha256"]})
        receipt.parent.chmod(0o777)
        with self.assertRaisesRegex(Error, "writable by another account"):
            startup.check(self.root)
        receipt.parent.chmod(0o700)
        receipt.unlink()
        receipt.symlink_to("/usr/share/factory/etc/os-release")
        with self.assertRaises(OSError):
            startup.check(self.root)

    def test_library_cache_can_only_reference_verified_library_directories(self):
        self.file("etc/ld.so.cache", "inert mocked native cache")
        for library, allowed in (
            ("/lib64/libc.so.6", True),
            ("/usr/lib64/libc.so.6", True),
            ("/var/lib/machines/libc.so.6", False),
            ("/lib64/../../var/libc.so.6", False),
        ):
            result = SimpleNamespace(
                stdout=f"1 libs found in cache `/etc/ld.so.cache'\n\tlibc.so.6 (libc6) => {library}\n",
                stderr="",
            )
            with self.subTest(library=library), patch("particleve.startup.run", return_value=result):
                if allowed:
                    startup.inventory(self.root)
                else:
                    with self.assertRaisesRegex(Error, "writable state"):
                        startup.inventory(self.root)
        alias = self.root / "lib64"
        alias.unlink()
        alias.symlink_to("var/lib")
        with self.assertRaisesRegex(Error, "traditional code path"):
            startup.inventory(self.root)

    def test_ownership_and_acl_policy_is_independent_of_mode_only_checks(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=1000, st_gid=0, st_nlink=1)
        # Invoke the original metadata function without the fixture-UID adapter.
        with (
            patch("particleve.startup.os.getxattr", return_value=b"named-user ACL"),
            self.assertRaisesRegex(Error, "unreviewed ACL"),
        ):
            startup._acl(0, "etc/code")
        with self.assertRaisesRegex(Error, "not owned by root"):
            ORIGINAL_METADATA(info, "etc/code")


ORIGINAL_METADATA = startup._metadata
