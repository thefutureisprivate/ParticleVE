import fcntl
import http.client
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from particleve.commission import requirements_digest
from particleve.common import Error, canonical, digest, read_json, write_json
from particleve.linux import Linux
from particleve.reporting import HANDOFF_SEALS, MAX_REPORT, deliver, journal, send, sender_main, snapshot
from Tools.heartbeat import freshness


class ReportingTests(unittest.TestCase):
    def test_native_handoff_is_sealed_and_replaces_the_inspector_with_no_capabilities(self):
        saved_stdin = os.dup(0)
        config = {
            "endpoint": "https://receiver.example.org",
            "maximum_update_check_age_seconds": 172800,
            "private_ca": False,
        }
        try:
            with (
                patch("particleve.reporting.settings", return_value=config),
                patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/run/credentials/owned.service"}),
                patch("particleve.reporting.os.geteuid", return_value=0),
                patch("particleve.reporting.run", return_value=Mock(stdout="u 62300\n", stderr="")),
                patch("particleve.reporting.snapshot", return_value={"result": "pass"}),
                patch("particleve.reporting.os.execv") as execute,
                self.assertRaisesRegex(Error, "unexpectedly returned"),
            ):
                send(Mock())
            seals = fcntl.fcntl(0, fcntl.F_GET_SEALS)
            self.assertEqual(seals & HANDOFF_SEALS, HANDOFF_SEALS)
            self.assertFalse(os.fstat(0).st_mode & 0o111)
            with self.assertRaises(PermissionError):
                os.write(0, b"cannot alter report")
            args = execute.call_args.args[1]
            for option in [
                "--reuid=62300",
                "--regid=62300",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
            ]:
                self.assertIn(option, args)
            self.assertEqual(args[-3:], ["/usr/bin/python3", "-I", "/usr/libexec/particleve-health-sender"])
        finally:
            os.dup2(saved_stdin, 0)
            os.close(saved_stdin)

    def test_sender_rejects_root_before_reading_input_or_credentials(self):
        with (
            patch("particleve.reporting.os.geteuid", return_value=0),
            patch("particleve.reporting.os.fstat") as read,
            self.assertRaisesRegex(Error, "private dynamic user"),
        ):
            sender_main()
        read.assert_not_called()

    def test_old_or_changed_reporting_policy_requires_review_before_automatic_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = object.__new__(Linux)
            backend.directory = Path(temporary)
            backend.manifest = {"owned": "installation"}
            backend.config = {"owned": "configuration"}
            record = {
                "installation_sha256": digest(backend.manifest),
                "config_sha256": digest(backend.config),
                "startup_policy_sha256": "approved-startup",
                "acceptance_requirements_sha256": requirements_digest(),
            }
            path = backend.directory / "commissioned.json"
            write_json(path, record)
            with (
                patch("particleve.reporting.policy_binding", return_value="current") as binding,
                patch("particleve.linux.require_active_services") as active,
                patch.object(Linux, "startup_policy", return_value="approved-startup"),
            ):
                with self.assertRaisesRegex(Error, "lacks external reporting evidence"):
                    backend.check_commissioned()
                binding.assert_not_called()
                write_json(path, {**record, "reporting_policy_sha256": "current"})
                backend.check_commissioned()
                active.assert_called_once_with("particleve-report.timer")
                write_json(path, {**record, "reporting_policy_sha256": "changed"})
                with self.assertRaisesRegex(Error, "reporting policy changed"):
                    backend.check_commissioned()

    def test_journal_no_match_sanitization_and_output_bound(self):
        real_popen = subprocess.Popen
        message = (
            "avc: denied { read write } scontext=system_u:system_r:svirt_t:s0:c1,c2 "
            'tcontext=system_u:object_r:virt_var_lib_t:s0:c3,c4 tclass=file name="PRIVATE-PATH"'
        )
        line = json.dumps({"__CURSOR": "owned-cursor", "MESSAGE": message}) + "\n"
        for program, expected in (
            ("raise SystemExit(1)", "empty"),
            ("print(" + repr(line) + ',end="")', "event"),
            ('print("x"*300000)', "oversized"),
        ):

            def launch(_command, script=program, **kwargs):
                return real_popen([sys.executable, "-I", "-c", script], **kwargs)

            with patch("particleve.common.subprocess.Popen", side_effect=launch):
                if expected == "oversized":
                    with self.assertRaisesRegex(Error, "size limit"):
                        journal()
                else:
                    result = journal()
                    if expected == "empty":
                        self.assertEqual(result["events"], [])
                    else:
                        self.assertEqual(result["events"][0]["permissions"], ["read", "write"])
                        self.assertNotIn("PRIVATE-PATH", json.dumps(result))

    def test_delivery_never_redirects_or_exports_receiver_text(self):
        token = b"a" * 48
        for status in (200, 202, 204, 301, 302, 307, 403, 500):
            with patch("particleve.reporting.http.client.HTTPSConnection") as constructor:
                connection = constructor.return_value
                response = connection.getresponse.return_value
                response.status = status
                response.read.return_value = b""
                if status in (200, 202, 204):
                    self.assertTrue(
                        deliver({"result": "pass"}, "https://receiver.example.org/report", token)["delivered"]
                    )
                else:
                    with self.assertRaises(Error):
                        deliver({"result": "pass"}, "https://receiver.example.org/report", token)
                constructor.assert_called_once()
                connection.request.assert_called_once()
                connection.close.assert_called_once()

    def test_delivery_rejects_credentials_in_urls_headers_and_oversized_reports(self):
        with patch("particleve.reporting.http.client.HTTPSConnection") as constructor:
            for endpoint, token, report in (
                ("http://receiver.example.org", b"a" * 48, {"result": "pass"}),
                ("https://user:secret@receiver.example.org", b"a" * 48, {"result": "pass"}),
                ("https://receiver.example.org", b"a" * 48 + b"\r\nInjected: value", {"result": "pass"}),
                ("https://receiver.example.org", b"a" * 48, {"result": "x" * MAX_REPORT}),
            ):
                with self.assertRaises(Error):
                    deliver(report, endpoint, token)
            constructor.assert_not_called()

    def test_transport_failure_is_bounded_and_closes_only_its_connection(self):
        with patch("particleve.reporting.http.client.HTTPSConnection") as constructor:
            connection = constructor.return_value
            connection.getresponse.side_effect = http.client.BadStatusLine("do not export receiver bytes")
            with self.assertRaisesRegex(Error, "BadStatusLine") as result:
                deliver({"result": "pass"}, "https://receiver.example.org", b"a" * 48)
            self.assertNotIn("receiver bytes", str(result.exception))
            connection.close.assert_called_once()

    def test_receiver_uses_its_own_receipt_time_even_if_sender_claims_the_future(self):
        now = datetime(2026, 11, 8, tzinfo=UTC)
        receipt = {
            "schema": 1,
            "received_at": now.isoformat(),
            "report": {
                "schema": 1,
                "installation_uuid": "owned",
                "result": "pass",
                "observed_at": "2099-01-01T00:00:00+00:00",
            },
        }
        self.assertTrue(freshness(receipt, "owned", now=now)["fresh"])
        for age in (901, -1):
            with self.assertRaises(Error):
                freshness(receipt, "owned", now=now + timedelta(seconds=age))
        with self.assertRaises(Error):
            freshness(receipt, "foreign", now=now)
        receipt["report"]["result"] = "attention"
        with self.assertRaises(Error):
            freshness(receipt, "owned", now=now)

    def test_failed_authenticated_fetch_retains_previous_success_and_cache_does_not_refresh_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            backend = object.__new__(Linux)
            backend.directory = Path(temporary)
            backend.cache = Path(temporary) / "releases"
            backend.config = {"feed": "https://receiver.example.org/feed"}
            backend.keyring = "public-keyring"
            backend.certificate = "public-certificate"
            receipt = backend.directory / "release-check.json"
            with patch("particleve.linux.fetch", return_value=(backend.cache, {"version": "45.0.1.1-63.1"})):
                backend.release()
            success = read_json(receipt)
            with (
                patch("particleve.linux.fetch", side_effect=Error("signature rejected")),
                self.assertRaises(Error),
            ):
                backend.release()
            failed = read_json(receipt)
            self.assertEqual(failed["last_success_at"], success["last_success_at"])
            self.assertEqual(failed["result"], "fail")
            (backend.cache / "45.0.1.1-63.1").mkdir(parents=True)
            with (
                patch("particleve.linux.verify_directory", return_value={"version": "45.0.1.1-63.1"}),
                patch("particleve.linux.fetch") as fetch,
            ):
                backend.release("45.0.1.1-63.1")
            fetch.assert_not_called()
            self.assertEqual(read_json(receipt), failed)

    def test_observation_failure_stale_checks_and_unknown_disk_health_cannot_pass(self):
        now = datetime(2026, 11, 8, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as temporary:
            backend = Mock()
            backend.directory = Path(temporary)
            backend.manifest = {"installation_uuid": "owned"}
            backend.current_version.return_value = "45.0.1.1-63.1"
            backend.boot_id.return_value = "owned-boot"
            backend.health.return_value = None
            backend.check_time.return_value = {"operators": ["a", "b"], "maximum_error_seconds": 0.01}
            backend.check_storage.return_value = {
                "free_bytes": 100,
                "reserve_bytes": 10,
                "swap_degraded": 0,
                "swap_sync_action": "idle",
            }
            backend.check_resources.return_value = {
                "memory": {"available_bytes": 100},
                "physical_disks": [{"role": "a", "status": "passed"}],
                "pressure": {},
                "oom_events": {"events": [], "limited": False},
                "alerts": [],
                "alerts_limited": False,
                "virtual_machines": [],
            }
            with (
                patch("particleve.reporting.journal", return_value={"events": [], "limited": False}),
                patch("particleve.vms.LinuxVMs.inventory", return_value=[]),
                patch("particleve.bootloaders.Loaders.load", return_value={"rejected": []}),
            ):
                self.assertEqual(snapshot(backend, now=now)["result"], "pass")
                backend.check_resources.return_value["alerts"] = ["sustained memory pressure"]
                resource_attention = snapshot(backend, now=now)
                self.assertEqual(resource_attention["result"], "attention")
                self.assertEqual(
                    resource_attention["details"]["resources"]["alerts"], ["sustained memory pressure"]
                )
                backend.check_resources.assert_called_with(healthy=False)
                backend.check_resources.return_value["alerts"] = []
                backend.health.side_effect = Error("unexpected effective security policy")
                self.assertEqual(snapshot(backend, now=now)["result"], "attention")
                backend.health.side_effect = None
                (backend.directory / "commissioned.json").touch()
                self.assertEqual(snapshot(backend, now=now)["result"], "attention")
                write_json(
                    backend.directory / "release-check.json",
                    {
                        "schema": 1,
                        "result": "pass",
                        "last_success_at": now.isoformat(),
                        "version": "45.0.1.1-63.1",
                    },
                )
                self.assertEqual(snapshot(backend, now=now)["result"], "pass")
                self.assertEqual(snapshot(backend, now=now + timedelta(days=3))["result"], "attention")
                backend.check_resources.return_value["physical_disks"][0]["status"] = "unavailable"
                self.assertEqual(snapshot(backend, now=now)["result"], "attention")
                # Simultaneous pressure, OOM and maximum AVC summaries must
                # remain deliverable; detail caps cannot hide attention state.
                units = [r"systemd-vmspawn@" + r"\x2d" * 55 + f"{i:02x}.service" for i in range(128)]
                psi = {
                    kind: {
                        scope: {"avg10": 100.0, "avg60": 100.0, "avg300": 100.0, "total_usec": 2**64 - 1}
                        for scope in ("some", "full")
                    }
                    for kind in ("cpu", "memory", "io")
                }
                resource = backend.check_resources.return_value
                resource["virtual_machines"] = [
                    {
                        "unit": unit,
                        "state": "failed",
                        "result": "oom-kill",
                        "limits": {
                            key: 2**64 - 1 for key in ("MemoryHigh", "MemoryMax", "MemorySwapMax", "TasksMax")
                        },
                        "memory_current_bytes": 2**64 - 1,
                        "memory_peak_bytes": 2**64 - 1,
                        "memory_events": {"high": 2**64 - 1, "oom_kill": 1},
                        "tasks_current": 256,
                        "task_events": {"max": 1},
                        "pressure": psi,
                    }
                    for unit in units
                ]
                resource["alerts"] = [
                    "sustained memory pressure exceeds policy: " + unit for unit in units[:32]
                ]
                resource["oom_events"]["events"] = [
                    {"id": "f" * 64, "source": "kernel", "unit": unit} for unit in units[:64]
                ]
                avcs = [
                    {
                        "id": "f" * 64,
                        "scontext": "a" * 128,
                        "tcontext": "b" * 128,
                        "tclass": "c" * 128,
                        "permissions": ["d" * 128],
                    }
                ] * 64
                with patch("particleve.reporting.journal", return_value={"events": avcs, "limited": True}):
                    bounded = snapshot(backend, now=now)
                self.assertEqual(bounded["result"], "attention")
                self.assertLessEqual(len(canonical(bounded)), MAX_REPORT)
                details = bounded["details"]["resources"]
                self.assertTrue(
                    details["vm_details_limited"]
                    and details["alerts_limited"]
                    and details["oom_events"]["limited"]
                )
