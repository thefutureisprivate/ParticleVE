import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from particleve.buildcheck import check_radio_rules, check_resolver_defaults
from particleve.common import Error


class DaemonDefaultsTests(unittest.TestCase):
    def test_resolver_defaults_require_readable_directories_and_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path("usr/lib/systemd/resolved.conf.d/50-particleve.conf")
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_text("[Resolve]\n")
            target.chmod(0o644)
            directories = [root / parent for parent in relative.parents[:-1]]
            for directory in directories:
                directory.chmod(0o755)
            check_resolver_defaults(root)
            for directory in directories:
                with self.subTest(directory=directory.relative_to(root)):
                    directory.chmod(0o700)
                    with self.assertRaisesRegex(Error, "not publicly readable/searchable"):
                        check_resolver_defaults(root)
                    directory.chmod(0o755)
            target.chmod(0o600)
            with self.assertRaisesRegex(Error, "not publicly readable"):
                check_resolver_defaults(root)

    def test_masked_radio_activation_is_rejected_before_native_rule_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = root / "usr/lib/udev/rules.d"
            rules.mkdir(parents=True)
            path = rules / "99-systemd.rules"
            for activation in ('ENV{SYSTEMD_WANTS}="', 'ENV{SYSTEMD_WANTS}+="'):
                path.write_text('SUBSYSTEM=="misc", ' + activation + 'systemd-rfkill.socket"\n')
                with (
                    self.subTest(activation=activation),
                    patch("particleve.buildcheck.run") as verify,
                    self.assertRaisesRegex(Error, "masked native radio-state owner"),
                ):
                    check_radio_rules(root)
                verify.assert_not_called()
