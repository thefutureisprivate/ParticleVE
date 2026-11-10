"""Validate compiled capacity inputs; resource decisions are covered in Rust tests."""

import copy

from particleve.common import digest
from Tests.fixtures import host
from Tests.runtime import RustDriverTests


class ResourceTests(RustDriverTests):
    def test_reserves_are_explicit_and_validation_preserves_identity(self):
        settings = host()
        before = digest(settings)
        self.assertEqual(self.evaluate("config-validate", config=settings), settings)
        self.assertEqual(digest(settings), before)
        for field in ("maintenance", "resources"):
            candidate = copy.deepcopy(settings)
            if field == "maintenance":
                del candidate[field]["minimum_available_ram_mib"]
            else:
                del candidate[field]
            self.assertIn("error", self.request("config-validate", config=candidate))

    def test_memory_reserve_uses_physical_availability_and_rejects_missing_measurements(self):
        report = self.evaluate(
            "resource-memory", text="MemTotal: 4194304 kB\nMemAvailable: 524288 kB\nSwapFree: 999999999 kB\n"
        )
        self.assertEqual(report, {"total_bytes": 4 * 1024**3, "available_bytes": 512 * 1024**2})
        for value in (
            "MemTotal: 4194304 kB\n",
            "MemTotal: 1 MB\nMemAvailable: 0 kB\n",
            "MemTotal: 1 kB\nMemAvailable: 2 kB\n",
        ):
            self.assertIn("error", self.request("resource-memory", text=value))

    def test_pressure_policy_rejects_incomplete_or_unbounded_thresholds(self):
        for value in (
            None,
            {},
            {"cpu": 50, "memory": 10, "io": 101},
            {"cpu": 50, "memory": 0, "io": 20},
            {"cpu": 50, "memory": True, "io": 20},
        ):
            settings = host()
            settings["resources"]["pressure_avg60_percent"] = value
            self.assertIn("error", self.request("config-validate", config=settings))
