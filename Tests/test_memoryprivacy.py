"""Verify compiled memory policy against explicit native configuration and mapping fixtures."""

import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests, native_environment

CORE = "[Coredump]\nStorage=none\nProcessSizeMax=0\nEnterNamespace=no\n"
LIMITS = "DefaultLimitCORE=0\nDefaultLimitCORESoft=0\n"
PATTERN = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F %I"


class MemoryPrivacyTests(RustDriverTests):
    def test_effective_native_coredump_keys_are_case_sensitive_and_last_dropin_wins(self):
        for config, allowed in (
            (CORE, True),
            ("[Coredump]\nStorage=external\n" + CORE, True),
            (CORE + "[Coredump]\nStorage=external\n", False),
            (CORE.replace("ProcessSizeMax=0", "ProcessSizeMax=32G"), False),
            (CORE.replace("EnterNamespace=no", "EnterNamespace=yes"), False),
            (CORE.replace("ProcessSizeMax=0", ""), False),
            ("# defaults only\n", False),
            ("[invalid\nStorage=none\n", False),
            (CORE.replace("Storage=none", "storage=none"), False),
            (CORE.replace("[Coredump]", "[DEFAULT]") + "[Coredump]\n", False),
        ):
            with self.subTest(config=config):
                observed = self.request("memory-core-config", data=config)
                self.assertEqual("ok" in observed, allowed, observed)
                if allowed:
                    self.assertEqual(
                        observed["ok"], {"storage": "none", "processsizemax": "0", "enternamespace": "no"}
                    )

    def test_baseline_checks_actual_files_and_native_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc, sysfs = root / "proc", root / "sys"
            (proc / "sys/fs").mkdir(parents=True)
            (proc / "sys/kernel").mkdir()
            (proc / "sys/fs/suid_dumpable").write_text("0\n")
            (proc / "sys/kernel/core_pattern").write_text(PATTERN)
            ksm = sysfs / "kernel/mm/ksm"
            ksm.mkdir(parents=True)
            zero = {"run": "0", "pages_shared": "0", "pages_sharing": "0", "ksm_zero_pages": "0"}
            native = {
                ("systemd-analyze", "cat-config", "--tldr", "systemd/coredump.conf"): {"stdout": CORE},
                ("systemctl", "show", "--property=DefaultLimitCORE", "--property=DefaultLimitCORESoft"): {
                    "stdout": LIMITS
                },
                ("systemctl", "is-enabled", "ksm.service", "ksmtuned.service"): {
                    "stdout": "masked\nmasked\n",
                    "code": 1,
                },
            }
            identifiers = iter(range(100))

            def environment_for(responses):
                return native_environment(root / f"commands-{next(identifiers)}", responses)

            environment = environment_for(native)
            for mutation in (
                {},
                {"run": "1"},
                {"run": "2"},
                {"pages_shared": "1"},
                {"pages_sharing": "1"},
                {"ksm_zero_pages": "1"},
            ):
                for name, value in (zero | mutation).items():
                    (ksm / name).write_text(value + "\n")
                with self.subTest(mutation=mutation):
                    observed = self.request(
                        "memory-baseline", proc=str(proc), sysfs=str(sysfs), environment=environment
                    )
                    self.assertEqual("ok" in observed, not mutation, observed)
            for name, value in zero.items():
                (ksm / name).write_text(value + "\n")
            command = ("systemctl", "show", "--property=DefaultLimitCORE", "--property=DefaultLimitCORESoft")
            for response in (
                {"stdout": LIMITS.replace("Soft=0", "Soft=infinity")},
                {"stdout": ""},
                {"stdout": LIMITS, "stderr": "warning\n"},
                {"code": 1},
            ):
                environment = environment_for(native | {command: response})
                self.assertIn(
                    "error",
                    self.request(
                        "memory-baseline", proc=str(proc), sysfs=str(sysfs), environment=environment
                    ),
                )
            command = ("systemctl", "is-enabled", "ksm.service", "ksmtuned.service")
            environment = environment_for(native | {command: {"stdout": "disabled\nmasked\n", "code": 1}})
            self.assertIn(
                "error",
                self.request("memory-baseline", proc=str(proc), sysfs=str(sysfs), environment=environment),
            )
            environment = environment_for(
                native | {command: {"stdout": "masked-runtime\nmasked-runtime\n", "code": 1}}
            )
            report = self.evaluate(
                "memory-baseline", proc=str(proc), sysfs=str(root / "absent"), environment=environment
            )
            self.assertEqual(report["ksm"], {"available": False})
            command = ("systemd-analyze", "cat-config", "--tldr", "systemd/coredump.conf")
            for response in ({"code": 1}, {"stdout": CORE, "stderr": "warning\n"}):
                environment = environment_for(native | {command: response})
                self.assertIn(
                    "error",
                    self.request(
                        "memory-baseline", proc=str(proc), sysfs=str(sysfs), environment=environment
                    ),
                )
            environment = environment_for(native)
            (proc / "sys/fs/suid_dumpable").write_text("2")
            self.assertIn(
                "error",
                self.request("memory-baseline", proc=str(proc), sysfs=str(sysfs), environment=environment),
            )
            (proc / "sys/fs/suid_dumpable").write_text("0")
            (proc / "sys/kernel/core_pattern").write_text("core")
            self.assertIn(
                "error",
                self.request("memory-baseline", proc=str(proc), sysfs=str(sysfs), environment=environment),
            )
