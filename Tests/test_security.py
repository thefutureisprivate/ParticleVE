import json
import os
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from particleve.linux import Linux
from particleve.security import (
    KERNEL_REQUIRED,
    TPM_PROFILE,
    apply_image_privileges,
    capabilities,
    check_privileges,
    firmware_evidence,
    kernel_baseline,
    privilege_inventory,
    process_evidence,
    selinux_access,
    selinux_baseline,
    ssh_baseline,
    usr_backing_disks,
    verified_usr_mount,
    write_tpm_profile,
)


class SecurityBaselineTests(unittest.TestCase):
    def test_effective_kernel_policy_checks_include_permissive_flags_and_consistent_sequence(self):
        classes = {
            name: i
            for i, name in enumerate(
                ("user_namespace", "alg_socket", "key_socket", "netlink_xfrm_socket", "process2"), start=1
            )
        }
        mode = "pass"
        queries = 0

        def query(context, target, cls, permission, decision):
            nonlocal queries
            if cls == classes["process2"]:
                self.assertIn(context.split(":")[2], ("unconfined_t", "unconfined_service_t"))
                self.assertEqual(target.split(":")[2], "chronyc_t")
            else:
                self.assertEqual(context, target)
            queries += 1
            domain = context.split(":")[2]
            decision.allowed = (
                permission
                if (
                    (domain == "particleve_vmspawn_t" and cls == 1)
                    or (domain in ("unconfined_t", "unconfined_service_t") and cls == 2)
                    or cls == classes["process2"]
                )
                else 0
            )
            decision.decided = permission
            decision.flags = 0
            decision.seqno = 70
            if mode == "grant-unneeded":
                decision.allowed = permission
            elif mode == "remove-required":
                decision.allowed = 0
            elif mode == "permissive":
                decision.flags = 1
            elif mode == "incomplete":
                decision.decided = 0
            elif mode == "reload":
                decision.seqno += queries
            elif mode == "deny-chrony-transition" and cls == classes["process2"]:
                decision.allowed = 0
            return -1 if mode == "query-failed" else 0

        api = SimpleNamespace(
            security_getenforce=lambda: 1,
            string_to_security_class=lambda name: 0 if mode == "unknown-class" else classes[name],
            string_to_av_perm=lambda cls, name: 8,
            av_decision=SimpleNamespace,
            security_compute_av_flags_raw=query,
        )
        with patch.dict(sys.modules, {"selinux": api}):
            observed = selinux_access()
            self.assertFalse(observed["permissive_domains"])
            self.assertEqual(
                observed["chrony_query_transitions"],
                {"unconfined_t": "chronyc_t", "unconfined_service_t": "chronyc_t"},
            )
            for mode in (
                "grant-unneeded",
                "remove-required",
                "permissive",
                "incomplete",
                "reload",
                "query-failed",
                "unknown-class",
                "deny-chrony-transition",
            ):
                with self.subTest(mode=mode), self.assertRaises(Error):
                    selinux_access()

    def test_unknown_missing_enabled_or_ambiguous_virtualization_booleans_cannot_pass(self):
        good = "virt_use_nfs --> off\nvirt_use_samba --> off\nvirt_use_execmem --> off\n"
        with patch("particleve.security.run") as native:
            native.return_value = SimpleNamespace(stdout=good, stderr="")
            self.assertFalse(any(selinux_baseline().values()))
            for output in (
                good.replace("virt_use_nfs --> off", "virt_use_nfs --> on"),
                good.replace("virt_use_samba --> off\n", ""),
                good + "virt_use_nfs --> off\n",
                good + "unexpected --> off\n",
            ):
                native.return_value.stdout = output
                with self.subTest(output=output), self.assertRaises(Error):
                    selinux_baseline()
            native.return_value.stdout = good
            native.return_value.stderr = "inspection warning"
            with self.assertRaisesRegex(Error, "diagnostics"):
                selinux_baseline()

    def test_verity_mapper_does_not_hide_an_overlaid_or_writable_usr_mount(self):
        good = {
            "target": "/usr",
            "source": "/dev/mapper/usr",
            "fstype": "erofs",
            "maj:min": "253:1",
            "fsroot": "/",
            "vfs-options": "ro,nodev,relatime",
        }
        device = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(253, 1))
        with patch.object(Path, "stat", return_value=device), patch("particleve.security.run") as native:
            native.return_value = SimpleNamespace(stdout=json.dumps({"filesystems": [good]}), stderr="")
            self.assertTrue(verified_usr_mount()["readonly"])
            for changed in (
                {"fstype": "overlay"},
                {"vfs-options": "rw,nodev"},
                {"fsroot": "/untrusted"},
                {"maj:min": "253:9"},
                {"target": "/"},
            ):
                native.return_value.stdout = json.dumps({"filesystems": [{**good, **changed}]})
                with self.subTest(changed=changed), self.assertRaises(Error):
                    verified_usr_mount()
            native.return_value.stdout = json.dumps({"filesystems": [good]})
            native.return_value.stderr = "inspection warning"
            with self.assertRaisesRegex(Error, "diagnostics"):
                verified_usr_mount()

    def test_matching_usr_does_not_hide_a_lost_boot_disk_selection_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            disk = Path(tmp) / "disk-b"
            disk.touch()
            backend = Linux.__new__(Linux)
            backend.current_esp_role = lambda: "b"
            backend.disk = lambda _: {"path": str(disk)}
            resolve = Path.resolve

            def selected(path, *, strict=False):
                return Path("/dev/dm-0") if str(path) == "/dev/mapper/usr" else resolve(path, strict=strict)

            with (
                patch.object(Path, "resolve", selected),
                patch("particleve.security.verified_usr_mount"),
                patch("particleve.security.usr_backing_disks", return_value={"disk-b"}),
                patch(
                    "particleve.linux.run",
                    return_value=SimpleNamespace(stdout="DEVNAME=/dev/disk-b\n", stderr=""),
                ) as native,
            ):
                with self.assertRaisesRegex(Error, "did not survive"):
                    backend.check_usr_boot_disk()
                native.return_value.stdout += "PARTICLEVE_BOOT_DISK=1\n"
                backend.check_usr_boot_disk()
                native.return_value.stderr = "unexpected diagnostic"
                with self.assertRaisesRegex(Error, "inspection diagnostics"):
                    backend.check_usr_boot_disk()

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
            self.assertEqual(usr_backing_disks("dm-0", sysfs=root), {"diskA", "diskB"})
            (mapper / "dm/uuid").write_text("CRYPT-LUKS2-test-usr\n")
            with self.assertRaisesRegex(Error, "not dm-verity"):
                usr_backing_disks("dm-0", sysfs=root)

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

    def test_effective_ssh_policy_requires_native_homed_authentication_and_rejects_drift(self):
        common = """UsePAM yes
PubkeyAuthentication yes
PubkeyAuthOptions touch-required verify-required
AuthorizedKeysCommand /usr/bin/userdbctl ssh-authorized-keys %u
AuthorizedKeysCommandUser root
PermitRootLogin prohibit-password
PermitEmptyPasswords no
KbdInteractiveAuthentication no
DisableForwarding yes
PermitTunnel no
X11Forwarding no
AllowAgentForwarding no
PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com
"""

        def native(command):
            root = "user=root," in command[-1]
            return SimpleNamespace(
                stderr="",
                stdout=common
                + (
                    "PasswordAuthentication no\nAuthenticationMethods publickey\n"
                    if root
                    else "PasswordAuthentication yes\nAuthenticationMethods publickey,password\n"
                ),
            )

        with patch("particleve.security.run", side_effect=native):
            self.assertEqual(ssh_baseline()["homed"]["authenticationmethods"], "publickey,password")
        for old, new in (
            ("DisableForwarding yes", "DisableForwarding no"),
            ("publickey,password", "publickey"),
            ("sk-ssh-ed25519@openssh.com,", ""),
            ("touch-required verify-required", "touch-required"),
            ("touch-required verify-required", "verify-required"),
        ):

            def changed(command, old=old, new=new):
                result = native(command)
                result.stdout = result.stdout.replace(old, new)
                return result

            with (
                self.subTest(change=new),
                patch("particleve.security.run", side_effect=changed),
                self.assertRaises(Error),
            ):
                ssh_baseline()

    def test_firmware_evidence_keeps_individual_attributes_and_does_not_turn_unavailable_into_pass(self):
        error = {"Error": {"Code": 10, "Message": "HSI unavailable for unprivileged hypervisor"}}
        with patch(
            "particleve.security.capture_bounded",
            return_value=SimpleNamespace(returncode=1, stdout=json.dumps(error), stderr=""),
        ):
            self.assertEqual(
                firmware_evidence(), {"available": False, "reason": error["Error"], "attributes": []}
            )
        # Native firmware can report the same attribute for several devices.
        # Preserve the individual records rather than collapsing by identifier.
        attrs = [
            {"AppstreamId": "org.fwupd.hsi.Mtd.Locked", "HsiResult": "locked", "Guid": "fixture-a"},
            {"AppstreamId": "org.fwupd.hsi.Mtd.Locked", "HsiResult": "not-locked", "Guid": "fixture-b"},
        ]
        with patch(
            "particleve.security.capture_bounded",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"SecurityAttributes": attrs, "SecurityEvents": []}),
                stderr="",
            ),
        ):
            self.assertEqual(firmware_evidence(), {"available": True, "attributes": attrs})
        with (
            patch(
                "particleve.security.capture_bounded",
                return_value=SimpleNamespace(returncode=0, stdout='{"SecurityAttributes":[]}', stderr=""),
            ),
            self.assertRaisesRegex(Error, "empty"),
        ):
            firmware_evidence()

    def test_malformed_firmware_observations_fail_without_partial_evidence(self):
        for content in (
            "{",
            "null",
            "[]",
            '{"SecurityAttributes":[null]}',
            '{"HostSecurityAttributes":[{}]}',
            "[" * 2000,
        ):
            with (
                self.subTest(content=content[:40]),
                patch(
                    "particleve.security.capture_bounded",
                    return_value=SimpleNamespace(returncode=0, stdout=content, stderr=""),
                ),
                self.assertRaises(Error),
            ):
                firmware_evidence()

    def test_firmware_child_output_and_diagnostics_are_bounded_before_json_parsing(self):
        attributes = [{"AppstreamId": "org.fwupd.hsi.Kernel.Lockdown", "HsiResult": "locked"}]
        response = json.dumps({"SecurityAttributes": attributes})
        with tempfile.TemporaryDirectory() as name:
            command = Path(name) / "fwupdmgr"
            command.touch(mode=0o700)
            with patch.dict(os.environ, {"PATH": name + os.pathsep + os.environ["PATH"]}):
                command.write_text(f"#!{sys.executable}\nprint({response!r})\n")
                self.assertEqual(firmware_evidence(), {"available": True, "attributes": attributes})
                for descriptor in (1, 2):
                    command.write_text(
                        f"#!{sys.executable}\nimport os\nos.write({descriptor}, b'x' * (256 * 1024 + 1))\n"
                    )
                    with self.subTest(descriptor=descriptor), self.assertRaisesRegex(Error, "size limit"):
                        firmware_evidence()
                command.write_text(
                    f"#!{sys.executable}\nimport sys\nprint({response!r})\n"
                    "print('warning', file=sys.stderr)\n"
                )
                with self.assertRaisesRegex(Error, "diagnostics"):
                    firmware_evidence()

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

    def test_process_evidence_does_not_export_native_guest_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            process = proc / "123"
            (process / "attr").mkdir(parents=True)
            (process / "fd").mkdir()
            (process / "ns").mkdir()
            (process / "ns/user").symlink_to("user:[12345]")
            fields = (
                "Uid",
                "Gid",
                "Groups",
                "CapInh",
                "CapPrm",
                "CapEff",
                "CapBnd",
                "CapAmb",
                "NoNewPrivs",
                "Seccomp",
                "Seccomp_filters",
            )
            (process / "status").write_text("\n".join(f"{field}: 0" for field in fields))
            (process / "attr/current").write_text("system_u:system_r:svirt_t:s0:c10,c20\0")
            (process / "stat").write_text("123 (qemu) S " + "0 " * 18 + "1\n")
            (process / "cmdline").write_bytes(
                b"qemu\0-fw_cfg\0name=opt/io.systemd.credentials,string=DO-NOT-EXPORT\0-sandbox\0on\0"
            )
            result = process_evidence({"pid": 123, "starttime": 1}, proc=proc)
            self.assertNotIn("DO-NOT-EXPORT", json.dumps(result))
            self.assertEqual(result["security_options"]["-sandbox"], ["on"])
            self.assertEqual(result["namespaces"]["user"], "user:[12345]")
            with patch("particleve.security.MAX_NAMESPACES", 0), self.assertRaisesRegex(Error, "bound"):
                process_evidence({"pid": 123, "starttime": 1}, proc=proc)
            (process / "fd/0").symlink_to("/dev/null")
            with patch("particleve.security.MAX_FDS", 0), self.assertRaisesRegex(Error, "bound"):
                process_evidence({"pid": 123, "starttime": 1}, proc=proc)
            (process / "cmdline").write_bytes(b"qemu\0-cpu\0" + b"x" * 65537 + b"\0")
            with self.assertRaisesRegex(Error, "evidence bound"):
                process_evidence({"pid": 123, "starttime": 1}, proc=proc)
