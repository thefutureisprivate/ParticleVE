import tempfile
import unittest
from datetime import UTC, datetime

from particleve.common import Deferred, Error, lock
from particleve.coordinator import Coordinator, reboot_window
from Tests.fixtures import Backend


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backend = Backend()
        self.coordinator = Coordinator(self.temporary.name, self.backend)
        self.window = datetime(2026, 11, 6, 3, 30, tzinfo=UTC)

    def test_full_transaction_assessment_and_no_second_reboot(self):
        self.assertEqual(self.coordinator.prepare()["action"], "ready")
        self.assertNotIn("reboot", self.backend.calls)
        self.assertEqual(self.coordinator.reboot(now=self.window)["action"], "activation-requested")
        self.assertEqual(self.coordinator.reboot(now=self.window)["action"], "deferred")
        self.backend.current, self.backend.boot = "45.0.1.2-1.1", "second-boot"
        self.coordinator.assess()
        self.assertIsNotNone(self.coordinator.load()["pending"])
        self.coordinator.bless()
        self.assertIsNone(self.coordinator.load()["pending"])
        self.assertEqual(self.coordinator.prepare()["reason"], "no newer OS release")
        self.assertEqual(self.backend.calls.count("reboot"), 1)

    def test_failed_native_blessing_keeps_activation_for_fallback_quarantine(self):
        self.coordinator.prepare()
        self.coordinator.reboot(now=self.window)
        self.backend.current, self.backend.boot = "45.0.1.2-1.1", "candidate-boot"
        self.coordinator.assess()
        self.backend.fail_at = "bless"
        with self.assertRaises(OSError):
            self.coordinator.bless()
        self.assertEqual(self.coordinator.load()["pending"]["phase"], "booting")
        self.backend.current, self.backend.boot, self.backend.fail_at = "45.0.1.1-1.1", "fallback-boot", None
        self.coordinator.runtime_guard()
        self.assertIn("45.0.1.2-1.1", self.coordinator.load()["rejected"])
        self.assertIsNone(self.coordinator.load()["pending"])

    def test_unassessed_boot_cannot_clear_its_counter(self):
        with self.assertRaisesRegex(Error, "boot assessment"):
            self.coordinator.bless()
        self.assertNotIn("bless", self.backend.calls)

    def test_interruptions_at_every_resource_boundary_resume_same_version(self):
        boundaries = [
            "protect",
            "transfer-a",
            "transferred-a",
            "transfer-b",
            "transferred-b",
            "expose-a",
            "exposed-a",
            "expose-b",
            "exposed-b",
        ]
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                backend = Backend()
                coordinator = Coordinator(directory, backend)
                backend.fail_at = boundary
                with self.assertRaises(OSError):
                    coordinator.prepare()
                self.assertNotIn("reboot", backend.calls)
                backend.latest, backend.fail_at = "45.0.1.3-1.1", None
                result = Coordinator(directory, backend).prepare()
                self.assertEqual(result, {"action": "ready", "version": "45.0.1.2-1.1"})
                self.assertEqual(backend.disks, {"a": "45.0.1.2-1.1", "b": "45.0.1.2-1.1"})

    def test_readiness_is_rechecked_against_actual_disk(self):
        self.coordinator.prepare()
        del self.backend.disks["b"]
        with self.assertRaises(Error):
            self.coordinator.reboot(now=self.window)
        self.assertNotIn("reboot", self.backend.calls)

    def test_firmware_missing_disk_schema_and_commissioning_block(self):
        for blocker in ("firmware", "disk", "schema", "memory"):
            with self.subTest(blocker=blocker):
                self.backend.blocked = blocker
                self.assertEqual(self.coordinator.prepare()["action"], "deferred")
                self.assertNotIn("transfer-a", self.backend.calls)
        self.backend.blocked = None
        self.backend.commissioned = False
        self.assertEqual(self.coordinator.prepare()["reason"], "not commissioned")

    def test_degradation_after_prepare_blocks_activation(self):
        self.coordinator.prepare()
        self.backend.blocked = "disk"
        self.assertEqual(self.coordinator.reboot(now=self.window)["action"], "deferred")
        self.assertNotIn("select", self.backend.calls)

    def test_maintenance_persists_and_serializes(self):
        self.coordinator.maintenance("supervised firmware")
        reopened = Coordinator(self.temporary.name, self.backend)
        self.assertIn("manual maintenance", reopened.prepare()["reason"])
        with self.assertRaises(Error):
            reopened.maintenance(reviewed=False)
        reopened.maintenance(reviewed=True)
        with lock(self.temporary.name), self.assertRaises(Deferred):
            reopened.prepare()

    def test_fallback_quarantines_before_old_daemon_is_started(self):
        self.coordinator.prepare()
        self.coordinator.reboot(now=self.window)
        self.backend.boot = "after-fallback"
        self.coordinator.runtime_guard()
        self.assertIn("45.0.1.2-1.1", self.coordinator.load()["rejected"])
        self.assertLess(
            self.backend.calls.index("reject-45.0.1.2-1.1"), self.backend.calls.index("daemon-state")
        )
        self.assertIn("quarantined", self.coordinator.prepare()["reason"])
        self.assertEqual(self.backend.calls.count("reboot"), 1)

    def test_no_boot_change_does_not_imply_fallback(self):
        self.coordinator.prepare()
        self.coordinator.reboot(now=self.window)
        self.coordinator.runtime_guard()
        self.assertNotIn("45.0.1.2-1.1", self.coordinator.load()["rejected"])

    def test_changed_release_cannot_resume(self):
        self.backend.fail_at = "transferred-a"
        with self.assertRaises(OSError):
            self.coordinator.prepare()
        self.backend.releases["45.0.1.2-1.1"]["artifacts"]["usr"]["sha256"] = "b" * 64
        self.backend.fail_at = None
        with self.assertRaises(Error):
            self.coordinator.prepare()

    def test_no_update_and_missed_window_do_not_reboot(self):
        self.backend.latest = "45.0.1.1-1.1"
        self.coordinator.prepare()
        self.assertEqual(self.coordinator.reboot(now=self.window)["action"], "deferred")
        self.backend.latest = "45.0.1.2-1.1"
        self.coordinator.prepare()
        daytime = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
        self.assertEqual(self.coordinator.reboot(now=daytime)["action"], "deferred")
        self.assertNotIn("reboot", self.backend.calls)
        self.assertNotIn("freeze-vms", self.backend.calls)

    def test_shutdown_failure_cancels_activation_and_restores_vms(self):
        self.coordinator.prepare()

        def refuse():
            raise Deferred("VM refused poweroff")

        self.backend.stop_vms = refuse
        result = self.coordinator.reboot(now=self.window)
        self.assertEqual(result["action"], "deferred")
        self.assertIn("restore-vms", self.backend.calls)
        self.assertNotIn("reboot", self.backend.calls)
        self.assertEqual(self.coordinator.load()["pending"]["phase"], "ready")

    def test_supervised_activation_before_commissioning_requires_manual_flag(self):
        self.backend.commissioned = False
        self.coordinator.prepare(automatic=False)
        self.assertEqual(self.coordinator.reboot(now=self.window)["reason"], "not commissioned")
        self.assertNotIn("freeze-vms", self.backend.calls)
        daytime = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)
        result = self.coordinator.reboot(now=daytime, automatic=False)
        self.assertEqual(result["action"], "activation-requested")
        self.assertLess(self.backend.calls.index("stop-vms"), self.backend.calls.index("reboot"))

    def test_manual_activation_retains_firmware_storage_and_shutdown_guards(self):
        self.backend.commissioned = False
        self.coordinator.prepare(automatic=False)
        for blocker in ("firmware", "disk", "memory"):
            with self.subTest(blocker=blocker):
                self.backend.blocked = blocker
                self.assertEqual(self.coordinator.reboot(automatic=False)["action"], "deferred")
                self.assertNotIn("freeze-vms", self.backend.calls)
        self.backend.blocked = None

        def firmware_appears_during_shutdown():
            self.backend.event("stop-vms")
            self.backend.blocked = "firmware"

        self.backend.stop_vms = firmware_appears_during_shutdown
        result = self.coordinator.reboot(automatic=False)
        self.assertEqual(result["reason"], "staged firmware")
        self.assertIn("restore-vms", self.backend.calls)
        self.assertNotIn("reboot", self.backend.calls)
        self.assertEqual(self.coordinator.load()["pending"]["phase"], "ready")

    def test_failed_reboot_queue_restores_the_running_set(self):
        self.coordinator.prepare()
        self.backend.conditional_reboot = lambda version: False
        with self.assertRaises(Error):
            self.coordinator.reboot(now=self.window)
        self.assertIn("restore-vms", self.backend.calls)
        self.assertEqual(self.coordinator.load()["pending"]["phase"], "ready")

    def test_untrusted_time_defers_before_vm_shutdown_including_manual_activation(self):
        self.coordinator.prepare()
        self.backend.blocked = "time"
        for automatic in (True, False):
            with self.subTest(automatic=automatic):
                result = self.coordinator.reboot(now=self.window, automatic=automatic)
                self.assertEqual(result["action"], "deferred")
                self.assertIn("authenticated time", result["reason"])
                self.assertNotIn("freeze-vms", self.backend.calls)
                self.assertNotIn("stop-vms", self.backend.calls)
                self.assertNotIn("reboot", self.backend.calls)

    def test_time_loss_or_step_during_shutdown_restores_vms_and_current_os(self):
        self.coordinator.prepare()

        def check_time(*, anchor=None):
            self.backend.event("time-recheck" if anchor else "time-check")
            if anchor is not None:
                raise Deferred("clock stepped during activation")
            return {"wall": self.window.timestamp(), "boottime": 100.0}

        self.backend.check_time = check_time
        result = self.coordinator.reboot(now=self.window)
        self.assertEqual(result["action"], "deferred")
        self.assertIn("clock stepped", result["reason"])
        self.assertIn("stop-vms", self.backend.calls)
        self.assertIn("restore-vms", self.backend.calls)
        self.assertNotIn("reboot", self.backend.calls)
        self.assertLess(self.backend.calls.index("time-check"), self.backend.calls.index("freeze-vms"))
        self.assertLess(self.backend.calls.index("select"), self.backend.calls.index("time-recheck"))
        self.assertEqual(self.coordinator.load()["pending"]["phase"], "ready")

    def test_corrected_clock_does_not_create_daytime_catch_up(self):
        self.coordinator.prepare()
        self.backend.check_time = lambda: {"wall": self.window.timestamp() + 3600, "boottime": 100.0}
        result = self.coordinator.reboot(now=self.window)
        self.assertEqual(result["action"], "deferred")
        self.assertIn("after authenticated time inspection", result["reason"])
        self.assertNotIn("freeze-vms", self.backend.calls)
        self.assertNotIn("reboot", self.backend.calls)

    def test_both_dst_transitions_and_adjacent_minutes(self):
        for day, utc_hour in (("2026-03-29", 2), ("2026-10-25", 3)):
            self.assertTrue(reboot_window(datetime.fromisoformat(f"{day}T{utc_hour:02}:30:00+00:00")))
            for minute in (29, 31):
                self.assertFalse(
                    reboot_window(datetime.fromisoformat(f"{day}T{utc_hour:02}:{minute}:00+00:00"))
                )


if __name__ == "__main__":
    unittest.main()
