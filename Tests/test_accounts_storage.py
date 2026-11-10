"""Exercise the compiled host's upstream-homed account boundary."""

import json
import tempfile

from Tests.runtime import RustDriverTests, native_environment


class AccountStorageTests(RustDriverTests):
    def test_root_does_not_depend_on_homed(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = native_environment(directory, {})
            self.assertIsNone(self.evaluate("accounts-authorize", username="root", environment=environment))

    def test_nonroot_ssh_account_must_come_from_homed(self):
        arguments = (
            "userdbctl",
            "--service=io.systemd.Home",
            "--with-nss=no",
            "--output=json",
            "user",
            "admin",
        )
        with tempfile.TemporaryDirectory() as directory:
            environment = native_environment(
                directory, {arguments: {"stdout": json.dumps({"userName": "admin"})}}
            )
            self.assertIsNone(self.evaluate("accounts-authorize", username="admin", environment=environment))
        for record in ({"userName": "other"}, {"userName": "admin", "disposition": "system"}):
            with self.subTest(record=record), tempfile.TemporaryDirectory() as directory:
                environment = native_environment(directory, {arguments: {"stdout": json.dumps(record)}})
                self.assertIn(
                    "error", self.request("accounts-authorize", username="admin", environment=environment)
                )
        with tempfile.TemporaryDirectory() as directory:
            environment = native_environment(directory, {"userdbctl": {"code": 1, "stderr": "not found"}})
            self.assertIn(
                "error", self.request("accounts-authorize", username="classic-user", environment=environment)
            )

    def test_classic_human_and_system_login_accounts_are_rejected(self):
        for uid in (42, 1000):
            with self.subTest(uid=uid):
                result = self.request(
                    "accounts-audit",
                    passwd=f"classic:x:{uid}:{uid}::/home/classic:/bin/bash\n",
                    shells="/bin/bash\n",
                )
                self.assertIn("homectl", result["error"])

    def test_nonlogin_system_commands_do_not_become_classic_logins(self):
        passwd = (
            "root:x:0:0::/root:/bin/bash\nsync:x:5:0::/sbin:/bin/sync\n"
            "halt:x:7:0::/sbin:/sbin/halt\nsshd:x:74:74::/:/sbin/nologin\n"
        )
        self.assertIsNone(self.evaluate("accounts-audit", passwd=passwd, shells="/bin/bash\n"))

    def test_malformed_accounts_and_option_like_names_fail_closed(self):
        for passwd in ("too:few:fields", "alice:x:not-an-id:1::/:/bin/bash"):
            self.assertIn("error", self.request("accounts-audit", passwd=passwd, shells="/bin/bash\n"))
        with tempfile.TemporaryDirectory() as directory:
            environment = native_environment(directory, {})
            for name in ("", "--service=other", "alice\nroot", "alice\0root"):
                self.assertIn(
                    "error", self.request("accounts-authorize", username=name, environment=environment)
                )
