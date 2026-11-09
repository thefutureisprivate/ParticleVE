import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import memoryprivacy
from particleve.common import Error
from particleve.processes import observe

CORE = "[Coredump]\nStorage=none\nProcessSizeMax=0\nEnterNamespace=no\n"
LIMITS = "DefaultLimitCORE=0\nDefaultLimitCORESoft=0\n"
SMAPS = "1000-2000 rw-p 00000000 00:00 0\nKSM: 0 kB\nVmFlags: rd wr dd\n"


def response(stdout, *, returncode=0, stderr=""):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


class MemoryPrivacyTests(unittest.TestCase):
    def test_effective_core_configuration_uses_last_dropin_and_requires_both_controls(self):
        for config, allowed in (
            (CORE, True),
            ("[Coredump]\nStorage=external\n" + CORE, True),
            (CORE + "[Coredump]\nStorage=external\n", False),
            (CORE.replace("ProcessSizeMax=0", "ProcessSizeMax=32G"), False),
            (CORE.replace("EnterNamespace=no", "EnterNamespace=yes"), False),
            (CORE.replace("ProcessSizeMax=0", ""), False),
            ("# compile-time defaults only\n", False),
            ("[invalid\nStorage=none\n", False),
            (CORE.replace("Storage=none", "storage=none"), False),
            (CORE.replace("[Coredump]", "[DEFAULT]") + "[Coredump]\n", False),
        ):
            with (
                self.subTest(config=config),
                patch.object(memoryprivacy, "capture_bounded", return_value=response(config)),
            ):
                if allowed:
                    self.assertEqual(memoryprivacy.core_handling()["storage"], "none")
                else:
                    with self.assertRaises(Error):
                        memoryprivacy.core_handling()

    def test_manager_limits_and_native_diagnostics_fail_closed(self):
        for result in (response("", returncode=1), response(CORE, stderr="warning\n")):
            with (
                patch.object(memoryprivacy, "capture_bounded", return_value=result),
                self.assertRaises(Error),
            ):
                memoryprivacy.core_handling()
        for limits, allowed in (
            (LIMITS, True),
            (LIMITS.replace("Soft=0", "Soft=infinity"), False),
            ("", False),
        ):
            with (
                self.subTest(limits=limits),
                patch.object(
                    memoryprivacy, "capture_bounded", side_effect=[response(CORE), response(limits)]
                ),
            ):
                if allowed:
                    self.assertEqual(memoryprivacy.configuration()["manager_core_limit"], 0)
                else:
                    with self.assertRaises(Error):
                        memoryprivacy.configuration()

    def test_stopped_ksm_with_retained_shared_pages_is_not_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "proc/sys/fs").mkdir(parents=True)
            (root / "proc/sys/fs/suid_dumpable").write_text("0\n")
            (root / "proc/sys/kernel").mkdir()
            (root / "proc/sys/kernel/core_pattern").write_text(memoryprivacy.CORE_PATTERN)
            ksm = root / "sys/kernel/mm/ksm"
            ksm.mkdir(parents=True)
            values = {"run": "0", "pages_shared": "0", "pages_sharing": "0", "ksm_zero_pages": "0"}
            for mutation in (
                {},
                {"run": "1"},
                {"run": "2"},
                {"pages_shared": "1"},
                {"pages_sharing": "1"},
                {"ksm_zero_pages": "1"},
            ):
                for name, value in (values | mutation).items():
                    (ksm / name).write_text(value + "\n")
                with (
                    self.subTest(mutation=mutation),
                    patch.object(
                        memoryprivacy,
                        "capture_bounded",
                        return_value=response("masked\nmasked\n", returncode=1),
                    ),
                    patch.object(memoryprivacy, "configuration", return_value={}),
                ):
                    if mutation:
                        with self.assertRaisesRegex(Error, "KSM"):
                            memoryprivacy.baseline(proc=root / "proc", sysfs=root / "sys")
                    else:
                        self.assertEqual(
                            memoryprivacy.baseline(proc=root / "proc", sysfs=root / "sys")["ksm"]["run"], 0
                        )

    def test_ksm_effective_activation_and_privileged_dumps_cannot_escape_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sys/fs").mkdir(parents=True)
            (root / "sys/kernel").mkdir()
            pattern = root / "sys/kernel/core_pattern"
            pattern.write_text(memoryprivacy.CORE_PATTERN)
            path = root / "sys/fs/suid_dumpable"
            for value, status in (
                ("0", "masked\nmasked\n"),
                ("0", "masked-runtime\nmasked-runtime\n"),
                ("2", "masked\nmasked\n"),
                ("0", "disabled\nmasked\n"),
            ):
                path.write_text(value)
                with (
                    self.subTest(value=value, status=status),
                    patch.object(
                        memoryprivacy, "capture_bounded", return_value=response(status, returncode=1)
                    ),
                    patch.object(memoryprivacy, "configuration", return_value={}),
                ):
                    if value == "0" and status.splitlines() in (
                        ["masked", "masked"],
                        ["masked-runtime", "masked-runtime"],
                    ):
                        self.assertFalse(
                            memoryprivacy.baseline(proc=root, sysfs=root / "absent")["ksm"]["available"]
                        )
                    else:
                        with self.assertRaises(Error):
                            memoryprivacy.baseline(proc=root, sysfs=root / "absent")
            path.write_text("0")
            pattern.write_text("core")
            with self.assertRaisesRegex(Error, "handler"):
                memoryprivacy.baseline(proc=root, sysfs=root / "absent")

    def test_process_limits_filter_and_each_mapping_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            directory = proc / "123"
            directory.mkdir()
            stats = directory / "ksm_stat"
            stats.write_text("ksm_zero_pages 0\nksm_merging_pages 0\n")
            for soft, hard, mask, maps, allowed in (
                ("0", "0", "00000000", SMAPS, True),
                ("0", "unlimited", "00000000", SMAPS, False),
                ("1", "0", "00000000", SMAPS, False),
                ("0", "0", "00000033", SMAPS, False),
                ("0", "0", "", SMAPS, False),
                ("0", "0", "00000000", SMAPS + SMAPS.replace("rd wr", "rd wr mg"), False),
                ("0", "0", "00000000", SMAPS.replace("KSM: 0", "KSM: 4"), False),
                ("0", "0", "00000000", SMAPS.replace("KSM: 0 kB\n", ""), False),
                ("0", "0", "00000000", SMAPS.replace("VmFlags: rd wr dd\n", ""), False),
                ("0", "0", "00000000", "", False),
            ):
                (directory / "limits").write_text(f"Max core file size {soft} {hard} bytes\n")
                (directory / "coredump_filter").write_text(mask)
                (directory / "smaps").write_text(maps)
                with (
                    self.subTest(soft=soft, hard=hard, mask=mask, maps=maps),
                    observe(123, proc=proc) as process,
                ):
                    if allowed:
                        memoryprivacy.process_policy(process, qemu=True)
                    else:
                        with self.assertRaises(Error):
                            memoryprivacy.process_policy(process, qemu=True)
            (directory / "limits").write_text("Max core file size 0 0 bytes\n")
            (directory / "coredump_filter").write_text("00000000")
            (directory / "smaps").write_text(SMAPS)
            with (
                observe(123, proc=proc) as process,
                patch.object(memoryprivacy, "MAX_SMAPS", 10),
                self.assertRaisesRegex(Error, "bound"),
            ):
                memoryprivacy.process_policy(process, qemu=True)
            for contents in (
                "",
                "ksm_zero_pages 1\nksm_merging_pages 0\n",
                "ksm_zero_pages 0\nksm_merging_pages 1\n",
            ):
                stats.write_text(contents)
                with (
                    self.subTest(contents=contents),
                    observe(123, proc=proc) as process,
                    self.assertRaisesRegex(Error, "KSM"),
                ):
                    memoryprivacy.process_policy(process, qemu=True)
            # A kernel deliberately built without KSM has neither interface.
            stats.unlink()
            (directory / "smaps").write_text(SMAPS.replace("KSM: 0 kB\n", ""))
            with observe(123, proc=proc) as process:
                memoryprivacy.process_policy(process, qemu=True)


if __name__ == "__main__":
    unittest.main()
