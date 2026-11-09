import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import resourceusage
from particleve.common import Error

PSI = (
    "some avg10=2.00 avg60=1.50 avg300=0.50 total=10000\nfull avg10=1.00 avg60=0.20 avg300=0.10 total=1000\n"
)
UNIT = "systemd-vmspawn@test.service"


def properties(**changes):
    values = {
        "Id": UNIT,
        "ActiveState": "active",
        "Result": "success",
        "ControlGroup": "/machine.slice/" + UNIT,
        "MemoryHigh": "1610612736",
        "MemoryMax": "2147483648",
        "MemorySwapMax": "infinity",
        "TasksMax": "256",
        "IOAccounting": "yes",
        "MemoryAccounting": "yes",
        "TasksAccounting": "yes",
        "OOMPolicy": "kill",
    } | changes
    return "\n".join(name + "=" + value for name, value in values.items())


class ResourceUsageTests(unittest.TestCase):
    def test_pressure_rejects_missing_duplicate_nonfinite_and_impossible_percentages(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pressure"
            path.write_text(PSI)
            self.assertEqual(resourceusage.pressure(path)["some"]["avg60"], 1.5)
            for invalid in (
                "",
                PSI.splitlines()[0],
                PSI + PSI,
                PSI.replace("1.50", "NaN"),
                PSI.replace("1.50", "101.00"),
                PSI.replace("total=10000", "total=-1"),
            ):
                path.write_text(invalid)
                with self.subTest(invalid=invalid), self.assertRaises(Error):
                    resourceusage.pressure(path)
            path.write_bytes(b"a" * 65537)
            with self.assertRaisesRegex(Error, "bound"):
                resourceusage.pressure(path)

    def test_counters_and_io_devices_keep_layers_separate_and_reject_duplicates(self):
        observed = resourceusage.devices("253:16 rbytes=100 wbytes=200\n252:1 rbytes=100 wbytes=200\n")
        self.assertEqual(set(observed), {"253:16", "252:1"})
        self.assertIsNone(resourceusage.devices("253:16 rbps=max wbps=8388608\n")["253:16"]["rbps"])
        for value in ("high 1\nhigh 2\n", "oom_kill -1\n", "not a counter\n", ""):
            with self.subTest(value=value), self.assertRaises(Error):
                resourceusage.numbers(value)
        for value in (
            "253:16 rbytes=1 rbytes=2\n",
            "253:16 rbps=NaN\n",
            "253:16 rbytes=1\n253:16 rbytes=2\n",
        ):
            with self.subTest(value=value), self.assertRaises(Error):
                resourceusage.devices(value)

    def test_unavailable_required_controller_is_not_a_healthy_empty_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "cgroup.controllers"
            path.write_text("cpu memory pids\n")
            with self.assertRaisesRegex(Error, "controllers"):
                resourceusage.controllers(root)
            path.write_text("cpu io memory pids\n")
            self.assertEqual(resourceusage.controllers(root), ["cpu", "io", "memory", "pids"])

    def test_whole_vm_cgroup_includes_auxiliary_charges_without_reading_process_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "machine.slice" / UNIT
            directory.mkdir(parents=True)
            for name, content in {
                "memory.current": "1073741824\n",
                "memory.peak": "1200000000\n",
                "memory.stat": "anon 700000000\nfile 350000000\nkernel 23741824\n",
                "memory.events": "high 12\noom 0\noom_kill 0\n",
                "pids.current": "10\n",
                "pids.events": "max 0\n",
                "memory.oom.group": "1\n",
                "cpu.stat": "usage_usec 1000\nnr_throttled 2\n",
                "cpu.max": "25000 100000\n",
                "io.stat": "253:16 rbytes=100 wbytes=200\n252:1 rbytes=100 wbytes=200\n",
                "io.max": "253:16 rbps=8388608 wbps=8388608 riops=max wiops=max\n",
                **{kind + ".pressure": PSI for kind in ("cpu", "memory", "io")},
            }.items():
                (directory / name).write_text(content)
            with patch.object(
                resourceusage, "command", side_effect=[json.dumps([{"unit": UNIT}]), properties()]
            ):
                observed = resourceusage.virtual_machines(root)[0]
            self.assertEqual(observed["memory_current_bytes"], 1024**3)
            self.assertEqual(observed["tasks_current"], 10)
            self.assertEqual(observed["cpu_max"]["quota_usec"], 25000)
            self.assertEqual(len(observed["io_stat"]), 2)
            self.assertIsNone(observed["limits"]["MemorySwapMax"])

    def test_failed_vm_survives_cgroup_removal_and_paths_cannot_escape_sysfs(self):
        with (
            patch.object(
                resourceusage,
                "command",
                side_effect=[
                    json.dumps([{"unit": UNIT}]),
                    properties(ActiveState="failed", Result="oom-kill"),
                ],
            ),
            patch.object(
                resourceusage, "text", side_effect=AssertionError("failed cgroup is already removed")
            ),
        ):
            observed = resourceusage.virtual_machines()[0]
            self.assertEqual(observed["result"], "oom-kill")
            self.assertNotIn("memory_current_bytes", observed)
        for path in ("/machine.slice/../" + UNIT, "/root/foreign.service", "relative/" + UNIT):
            with (
                self.subTest(path=path),
                patch.object(
                    resourceusage,
                    "command",
                    side_effect=[json.dumps([{"unit": UNIT}]), properties(ControlGroup=path)],
                ),
                self.assertRaisesRegex(Error, "cgroup"),
            ):
                resourceusage.virtual_machines()

    def test_native_inventory_diagnostics_and_truncation_fail_closed(self):
        for response in (
            SimpleNamespace(returncode=0, stderr="deprecated setting\n", stdout="[]"),
            SimpleNamespace(returncode=1, stderr="", stdout="[]"),
        ):
            with (
                patch.object(resourceusage, "capture_bounded", return_value=response),
                self.assertRaises(Error),
            ):
                resourceusage.virtual_machines()
        for units in (
            [{"unit": UNIT}] * 2,
            [{"unit": UNIT}] * (resourceusage.MAX_VMS + 1),
            [{"unit": "sshd.service"}],
        ):
            with (
                patch.object(resourceusage, "command", return_value=json.dumps(units)),
                self.assertRaises(Error),
            ):
                resourceusage.virtual_machines()

    def test_oom_receipts_are_bounded_and_do_not_export_raw_kernel_messages(self):
        rows = [
            {
                "__CURSOR": str(i),
                "MESSAGE": UNIT + ": Failed with result 'oom-kill'. private-argv-canary",
                "_TRANSPORT": "journal",
            }
            for i in range(65)
        ]
        response = SimpleNamespace(returncode=0, stderr="", stdout="\n".join(map(json.dumps, rows)))
        with patch.object(resourceusage, "capture_bounded", return_value=response):
            observed = resourceusage.oom_events()
        self.assertTrue(observed["limited"])
        self.assertEqual(len(observed["events"]), 64)
        self.assertEqual(observed["events"][0]["unit"], UNIT)
        self.assertNotIn("private-argv-canary", json.dumps(observed))


if __name__ == "__main__":
    unittest.main()
