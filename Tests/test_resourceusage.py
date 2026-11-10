"""Exercise compiled cgroup accounting against inert native-command fixtures."""

import json
import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests, native_environment

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


FIELDS = (
    "Id",
    "ActiveState",
    "Result",
    "ControlGroup",
    "MemoryHigh",
    "MemoryMax",
    "MemorySwapMax",
    "TasksMax",
    "IOAccounting",
    "MemoryAccounting",
    "TasksAccounting",
    "OOMPolicy",
)
LIST = ("systemctl", "list-units", "--all", "--type=service", "--output=json", "systemd-vmspawn@*.service")
SHOW = ("systemctl", "show", UNIT, *("--property=" + name for name in FIELDS))


class ResourceUsageTests(RustDriverTests):
    def test_pressure_rejects_missing_duplicate_nonfinite_and_impossible_percentages(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pressure"
            path.write_text(PSI)
            self.assertEqual(self.evaluate("resource-pressure", path=str(path))["some"]["avg60"], 1.5)
            for invalid in (
                "",
                PSI.splitlines()[0],
                PSI + PSI,
                PSI.replace("1.50", "NaN"),
                PSI.replace("1.50", "101.00"),
                PSI.replace("total=10000", "total=-1"),
                "a" * 65537,
            ):
                path.write_text(invalid)
                self.assertIn("error", self.request("resource-pressure", path=str(path)))

    def test_counters_and_io_devices_keep_layers_separate_and_reject_duplicates(self):
        observed = self.evaluate(
            "resource-devices", text="253:16 rbytes=100 wbytes=200\n252:1 rbytes=100 wbytes=200\n"
        )
        self.assertEqual(set(observed), {"253:16", "252:1"})
        self.assertIsNone(
            self.evaluate("resource-devices", text="253:16 rbps=max wbps=8388608\n")["253:16"]["rbps"]
        )
        for value in ("high 1\nhigh 2\n", "oom_kill -1\n", "not a counter\n", ""):
            self.assertIn("error", self.request("resource-counters", text=value))
        for value in (
            "253:16 rbytes=1 rbytes=2\n",
            "253:16 rbps=NaN\n",
            "253:16 rbytes=1\n253:16 rbytes=2\n",
        ):
            self.assertIn("error", self.request("resource-devices", text=value))

    def test_unavailable_required_controller_is_not_healthy_empty_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "cgroup.controllers"
            path.write_text("cpu memory pids\n")
            self.assertIn("controllers", self.request("resource-controllers", root=str(root))["error"])
            path.write_text("cpu io memory pids\n")
            self.assertEqual(
                self.evaluate("resource-controllers", root=str(root)), ["cpu", "io", "memory", "pids"]
            )

    def test_whole_vm_cgroup_includes_auxiliary_charges_without_process_memory(self):
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
            environment = native_environment(
                root / "commands",
                {LIST: {"stdout": json.dumps([{"unit": UNIT}])}, SHOW: {"stdout": properties()}},
            )
            observed = self.evaluate("resource-virtual-machines", root=str(root), environment=environment)[0]
            self.assertEqual(observed["memory_current_bytes"], 1024**3)
            self.assertEqual(observed["tasks_current"], 10)
            self.assertEqual(observed["cpu_max"]["quota_usec"], 25000)
            self.assertEqual(len(observed["io_stat"]), 2)
            self.assertIsNone(observed["limits"]["MemorySwapMax"])

    def test_failed_vm_survives_removed_cgroup_and_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            environment = native_environment(
                root / "failed",
                {
                    LIST: {"stdout": json.dumps([{"unit": UNIT}])},
                    SHOW: {"stdout": properties(ActiveState="failed", Result="oom-kill")},
                },
            )
            observed = self.evaluate("resource-virtual-machines", root=str(root), environment=environment)[0]
            self.assertEqual(observed["result"], "oom-kill")
            self.assertNotIn("memory_current_bytes", observed)
            for index, path in enumerate(
                ("/machine.slice/../" + UNIT, "/root/foreign.service", "relative/" + UNIT)
            ):
                environment = native_environment(
                    root / str(index),
                    {
                        LIST: {"stdout": json.dumps([{"unit": UNIT}])},
                        SHOW: {"stdout": properties(ControlGroup=path)},
                    },
                )
                self.assertIn(
                    "cgroup",
                    self.request("resource-virtual-machines", root=str(root), environment=environment)[
                        "error"
                    ],
                )

    def test_native_inventory_diagnostics_bounds_and_unknown_units_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            responses = [{"stdout": "[]", "stderr": "deprecated setting\n"}, {"stdout": "[]", "code": 1}]
            responses.extend(
                {"stdout": json.dumps(units)}
                for units in ([{"unit": UNIT}] * 2, [{"unit": UNIT}] * 129, [{"unit": "sshd.service"}])
            )
            responses.append({"stdout": "x" * (512 * 1024 + 1)})
            for index, response in enumerate(responses):
                environment = native_environment(root / str(index), {LIST: response})
                self.assertIn(
                    "error",
                    self.request("resource-virtual-machines", root=str(root), environment=environment),
                )

    def test_oom_receipts_are_bounded_and_do_not_export_raw_kernel_messages(self):
        rows = [
            {
                "__CURSOR": str(index),
                "MESSAGE": UNIT + ": Failed with result 'oom-kill'. private-argv-canary",
                "_TRANSPORT": "journal",
            }
            for index in range(65)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            environment = native_environment(
                Path(tmp), {"journalctl": {"stdout": "\n".join(map(json.dumps, rows))}}
            )
            observed = self.evaluate("resource-oom-events", environment=environment)
        self.assertTrue(observed["limited"])
        self.assertEqual(len(observed["events"]), 64)
        self.assertEqual(observed["events"][0]["unit"], UNIT)
        self.assertNotIn("private-argv-canary", json.dumps(observed))
