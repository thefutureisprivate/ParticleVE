import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from particleve.security import (
    KERNEL_REQUIRED,
    TPM_PROFILE,
    apply_image_privileges,
    capabilities,
    check_privileges,
    kernel_baseline,
    privilege_inventory,
    write_tpm_profile,
)
from Tests.runtime import RustDriverTests


class SecurityBaselineTests(RustDriverTests):
    def native(self, operation, executable, stdout, *, code=0, stderr=""):
        with tempfile.TemporaryDirectory() as temporary:
            command = Path(temporary) / executable
            command.write_text(
                f"#!{sys.executable}\nimport sys\nsys.stdout.write({stdout!r})\n"
                f"sys.stderr.write({stderr!r})\nsys.exit({code})\n"
            )
            command.chmod(0o700)
            return self.request(
                operation, environment=os.environ | {"PATH": temporary + os.pathsep + os.environ["PATH"]}
            )

    def test_unknown_missing_enabled_or_ambiguous_virtualization_booleans_cannot_pass(self):
        good = "virt_use_nfs --> off\nvirt_use_samba --> off\nvirt_use_execmem --> off\n"
        self.assertFalse(any(self.native("security-selinux-baseline", "getsebool", good)["ok"].values()))
        for output in (
            good.replace("virt_use_nfs --> off", "virt_use_nfs --> on"),
            good.replace("virt_use_samba --> off\n", ""),
            good + "virt_use_nfs --> off\n",
            good + "unexpected --> off\n",
        ):
            with self.subTest(output=output):
                self.assertIn("error", self.native("security-selinux-baseline", "getsebool", output))
        self.assertIn(
            "diagnostics",
            self.native("security-selinux-baseline", "getsebool", good, stderr="warning")["error"],
        )

    def test_usr_evidence_identifies_mixed_physical_members_and_rejects_unexpected_backing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mapper = root / "class/block/dm-0"
            (mapper / "dm").mkdir(parents=True)
            (mapper / "dm/uuid").write_text("CRYPT-VERITY-test-usr\n")
            (mapper / "slaves").mkdir()
            for disk, number in (("diskA", 3), ("diskB", 4)):
                part = root / "devices/block" / disk / (disk + str(number))
                part.mkdir(parents=True)
                (part / "partition").write_text(str(number))
                (mapper / "slaves" / part.name).symlink_to(part, target_is_directory=True)
            self.assertEqual(
                set(self.evaluate("security-usr-backing-disks", mapper="dm-0", sysfs=str(root))),
                {"diskA", "diskB"},
            )
            (mapper / "dm/uuid").write_text("CRYPT-LUKS2-test-usr\n")
            self.assertIn(
                "not dm-verity",
                self.request("security-usr-backing-disks", mapper="dm-0", sysfs=str(root))["error"],
            )

    def test_creation_profile_is_explicit_without_overriding_vendor_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "etc/swtpm_setup.conf"
            path.parent.mkdir()
            original = 'create_certs_tool = /usr/bin/swtpm_localca\nprofile = {"Name":"default-v1"}\n'
            path.write_text(original)
            target = Path(tmp) / "usr/lib/particleve"
            target.mkdir(parents=True)
            write_tpm_profile(tmp)
            self.assertEqual(json.loads((target / "tpm-profile.json").read_text()), TPM_PROFILE)
            self.assertEqual(path.read_text(), original)

    def test_firmware_evidence_preserves_attributes_and_unavailable_is_not_pass(self):
        error = {"Error": {"Code": 10, "Message": "HSI unavailable in fixture"}}
        self.assertEqual(
            self.native("security-firmware-evidence", "fwupdmgr", json.dumps(error), code=1)["ok"],
            {"available": False, "reason": error["Error"], "attributes": []},
        )
        attrs = [
            {"AppstreamId": "org.fwupd.hsi.Mtd.Locked", "HsiResult": "locked", "Guid": "fixture-a"},
            {"AppstreamId": "org.fwupd.hsi.Mtd.Locked", "HsiResult": "not-locked", "Guid": "fixture-b"},
        ]
        response = json.dumps({"SecurityAttributes": attrs})
        self.assertEqual(
            self.native("security-firmware-evidence", "fwupdmgr", response)["ok"],
            {"available": True, "attributes": attrs},
        )
        self.assertIn(
            "diagnostics",
            self.native("security-firmware-evidence", "fwupdmgr", response, stderr="warning")["error"],
        )

    def test_malformed_firmware_observations_fail_without_partial_evidence(self):
        for content in (
            "{",
            "null",
            "[]",
            '{"SecurityAttributes":[]}',
            '{"SecurityAttributes":[null]}',
            '{"HostSecurityAttributes":[{}]}',
            "[" * 2000,
        ):
            with self.subTest(content=content[:40]):
                self.assertIn("error", self.native("security-firmware-evidence", "fwupdmgr", content))

    def test_firmware_child_output_and_diagnostics_are_bounded_before_json_parsing(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as temporary:
                command = Path(temporary) / "fwupdmgr"
                command.write_text(
                    f"#!{sys.executable}\nimport os\nos.write({descriptor}, b'x' * (256 * 1024 + 1))\n"
                )
                command.chmod(0o700)
                result = self.request(
                    "security-firmware-evidence",
                    environment=os.environ | {"PATH": temporary + os.pathsep + os.environ["PATH"]},
                )
                self.assertIn("size limit", result["error"])

    def test_missing_kernel_facility_fails_without_requiring_force_mode_in_stock_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root / "usr/lib/modules/test-kernel"
            tree.mkdir(parents=True)
            config = tree / "config"
            config.write_text(
                "\n".join("CONFIG_" + key + "=y" for key in KERNEL_REQUIRED)
                + "\nCONFIG_RFKILL=m\nCONFIG_SECURITY_YAMA=y\n"
                + "CONFIG_ARCH_MMAP_RND_BITS_MAX=32\nCONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16\n"
                + "CONFIG_SERIAL_8250_NR_UARTS=32\nCONFIG_SERIAL_8250_RUNTIME_UARTS=4\n"
            )
            self.assertFalse(kernel_baseline(root)["module_sig_force"])
            self.assertEqual(kernel_baseline(root)["rfkill"], {"core": "m", "deprecated_input": False})
            original = config.read_text()
            for value in ("CONFIG_SERIAL_8250_CONSOLE=y", "CONFIG_SERIAL_8250_RUNTIME_UARTS=4"):
                config.write_text(original.replace(value, value.replace("=y", "=m").replace("=4", "=3")))
                with self.subTest(value=value), self.assertRaisesRegex(Error, "serial|SERIAL"):
                    kernel_baseline(root)
            config.write_text(original)
            config.write_text(original.replace("CONFIG_RFKILL=m", "CONFIG_RFKILL=y\nCONFIG_RFKILL_INPUT=y"))
            self.assertEqual(kernel_baseline(root)["rfkill"], {"core": "y", "deprecated_input": True})
            config.write_text(original.replace("CONFIG_RFKILL=m", "# CONFIG_RFKILL is not set"))
            with self.assertRaisesRegex(Error, "RFKill"):
                kernel_baseline(root)
            config.write_text(original)
            config.write_text(config.read_text().replace("CONFIG_SECCOMP=y", "# CONFIG_SECCOMP is not set"))
            with self.assertRaisesRegex(Error, "SECCOMP"):
                kernel_baseline(root)

    def test_file_capabilities_preserve_both_words_and_namespace_root(self):
        data = struct.pack("<IIIIII", 0x03000001, 1, 2, 4, 8, 100000)
        self.assertEqual(
            capabilities(data),
            {"effective": True, "permitted": 1 | 4 << 32, "inheritable": 2 | 8 << 32, "rootid": 100000},
        )
        for bad in (data[:-1], data + b"\0", struct.pack("<IIIII", 0x02000004, 0, 0, 0, 0)):
            with self.subTest(data=bad), self.assertRaises(Error):
                capabilities(bad)

    def test_privilege_inventory_does_not_follow_symlinks_outside_verified_usr(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "usr/bin").mkdir(parents=True)
            foreign = root / "writable-helper"
            foreign.write_text("untrusted")
            foreign.chmod(0o4755)
            (root / "usr/bin/link").symlink_to(foreign)
            helper = root / "usr/bin/helper"
            helper.write_text("verified")
            helper.chmod(0o2755)
            inventory = privilege_inventory(root)
            self.assertEqual(set(inventory), {"/usr/bin/helper"})
            self.assertEqual(inventory["/usr/bin/helper"]["mode"], "2755")

    def test_unreviewed_privilege_or_changed_capability_fails_policy(self):
        record = {"mode": "4755", "uid": 0, "gid": 0, "capabilities": None}
        policy = {
            "schema": 1,
            "privileged_files": {"/usr/bin/helper": {**record, "purpose": "tested elevation"}},
        }
        for actual in (
            {"/usr/bin/helper": record},
            {"/usr/bin/helper": record, "/usr/bin/unexpected": record},
            {
                "/usr/bin/helper": {
                    **record,
                    "capabilities": {"effective": True, "permitted": 1, "inheritable": 0, "rootid": 0},
                }
            },
        ):
            with (
                patch("particleve.security.read_json", return_value=policy),
                patch("particleve.security.privilege_inventory", return_value=actual),
            ):
                if actual == {"/usr/bin/helper": record}:
                    check_privileges("/")
                else:
                    with self.assertRaisesRegex(Error, "reviewed policy"):
                        check_privileges("/")

    def test_original_erofs_owner_is_not_replaced_by_the_extractor_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "usr/bin/helper"
            helper.parent.mkdir(parents=True)
            helper.write_text("inert")
            helper.chmod(0o4755)
            with patch(
                "particleve.security.run",
                return_value=SimpleNamespace(stdout="Uid: 1234   Gid: 4321  Access: 0755/rwxr-xr-x\n"),
            ) as command:
                item = privilege_inventory(root, image="source.erofs")["/usr/bin/helper"]
            self.assertEqual((item["uid"], item["gid"]), (1234, 4321))
            command.assert_called_once_with(["dump.erofs", "--path=/bin/helper", "source.erofs"])
            with (
                patch(
                    "particleve.security.run", return_value=SimpleNamespace(stdout="unrecognized metadata")
                ),
                self.assertRaisesRegex(Error, "original"),
            ):
                privilege_inventory(root, image="source.erofs")

    def test_privilege_expansion_fails_before_any_revocation_and_vendor_reductions_are_allowed(self):
        record = {"mode": "4755", "uid": 0, "gid": 0, "capabilities": None, "purpose": "reviewed"}
        policy = {
            "schema": 1,
            "privileged_files": {"/usr/bin/required": record},
            "revoked_privileges": {"/usr/bin/revoked": record},
        }
        required = {"/usr/bin/required": {k: v for k, v in record.items() if k != "purpose"}}
        with (
            patch("particleve.security.read_json", return_value=policy),
            patch("particleve.security.privilege_inventory", return_value=required),
            patch.object(Path, "chmod") as chmod,
            patch("particleve.security.os.removexattr") as revoke,
        ):
            self.assertEqual(apply_image_privileges("/"), required)
            chmod.assert_not_called()
            revoke.assert_not_called()
        with (
            patch("particleve.security.read_json", return_value=policy),
            patch(
                "particleve.security.privilege_inventory",
                return_value=required | {"/usr/bin/new": required["/usr/bin/required"]},
            ),
            patch.object(Path, "chmod") as chmod,
            patch("particleve.security.os.removexattr") as revoke,
            self.assertRaisesRegex(Error, "expanded"),
        ):
            apply_image_privileges("/")
        chmod.assert_not_called()
        revoke.assert_not_called()
