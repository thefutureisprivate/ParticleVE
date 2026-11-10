"""Image admission must reject NSS layouts that hide homed administrator membership."""

import tempfile
import unittest
from pathlib import Path

from particleve.buildcheck import check_homed_nss
from particleve.common import Error


class HomedNSSChecks(unittest.TestCase):
    def test_unmerged_ambiguous_and_foreign_group_providers_fail_image_admission(self):
        for groups in (
            "group: files systemd\n",
            "group: systemd files\n",
            "group: files [SUCCESS=merge] ldap systemd\n",
            "group: files [SUCCESS=merge] systemd\ngroup: files systemd\n",
            "passwd: files systemd\n",
        ):
            with self.subTest(groups=groups), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                factory = root / "usr/share/factory/etc"
                (factory / "authselect").mkdir(parents=True)
                (factory / "nsswitch.conf").symlink_to("/etc/authselect/nsswitch.conf")
                (factory / "authselect/nsswitch.conf").write_text(groups)
                with self.assertRaisesRegex(Error, "merge local and homed"):
                    check_homed_nss(root)

    def test_selected_regular_factory_profile_accepts_native_group_merging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            factory = root / "usr/share/factory/etc"
            (factory / "authselect").mkdir(parents=True)
            (factory / "nsswitch.conf").symlink_to("/etc/authselect/nsswitch.conf")
            (factory / "authselect/nsswitch.conf").write_text(
                "# Selected native profile\npasswd: files systemd\n"
                "group:  files [SUCCESS=merge] systemd # shared group membership\n"
            )
            check_homed_nss(root)

    def test_foreign_factory_authority_is_not_read_through(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            factory = root / "usr/share/factory/etc"
            (factory / "authselect").mkdir(parents=True)
            source = factory / "authselect/nsswitch.conf"
            source.write_text("group: files [SUCCESS=merge] systemd\n")
            authority = factory / "nsswitch.conf"
            authority.symlink_to("/etc/nsswitch.conf")
            with self.assertRaisesRegex(Error, "selected authselect"):
                check_homed_nss(root)
            authority.unlink()
            authority.symlink_to("/etc/authselect/nsswitch.conf")
            source.unlink()
            source.symlink_to("/etc/nsswitch.conf")
            with self.assertRaisesRegex(Error, "image-owned regular file"):
                check_homed_nss(root)
