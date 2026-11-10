"""Exercise compiled sanitized reporting and the external receipt-time checker."""

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from particleve.common import Error, read_json, write_json
from Tests.runtime import RustDriverTests, native_environment
from Tools.heartbeat import freshness


class ReportingTests(RustDriverTests):
    def test_sender_rejects_non_service_identity_before_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            credential = Path(temporary) / "report-token"
            credential.write_text("must not be read")
            credential.chmod(0)
            self.assertIn(
                "TLS sender",
                self.request("reporting-sender", environment={"CREDENTIALS_DIRECTORY": temporary})["error"],
            )

    def test_journal_no_match_sanitization_and_actual_output_bound(self):
        message = (
            "avc: denied { read write } scontext=system_u:system_r:svirt_t:s0:c1,c2 "
            "tcontext=system_u:object_r:virt_var_lib_t:s0:c3,c4 tclass=file name=PRIVATE-PATH"
        )
        line = json.dumps({"__CURSOR": "owned-cursor", "MESSAGE": message}) + "\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = native_environment(root / "empty", {"journalctl": {"code": 1}})
            self.assertEqual(self.evaluate("reporting-journal", environment=empty)["events"], [])
            event = native_environment(root / "event", {"journalctl": {"stdout": line}})
            result = self.evaluate("reporting-journal", environment=event)
            self.assertEqual(result["events"][0]["permissions"], ["read", "write"])
            self.assertNotIn("PRIVATE-PATH", json.dumps(result))
            oversized = native_environment(root / "large", {"journalctl": {"stdout": "x" * 300000}})
            self.assertIn("size limit", self.request("reporting-journal", environment=oversized)["error"])

    def test_delivery_rejects_unsafe_origin_headers_and_oversized_report_before_tls(self):
        for endpoint, token, report in (
            ("http://receiver.example.org", "a" * 48, {"result": "pass"}),
            ("https://user:secret@receiver.example.org", "a" * 48, {"result": "pass"}),
            ("https://receiver.example.org", "a" * 48 + "\r\nInjected: value", {"result": "pass"}),
            ("https://receiver.example.org", "a" * 48, {"result": "x" * 65536}),
        ):
            self.assertIn(
                "error", self.request("reporting-deliver", endpoint=endpoint, token=token, report=report)
            )

    def test_receiver_uses_its_own_receipt_time_even_if_sender_claims_future(self):
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

    def test_failed_fetch_keeps_previous_success_and_cache_attempt_cannot_refresh_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt = directory / "release-check.json"
            success = {
                "schema": 1,
                "result": "pass",
                "attempted_at": "2026-11-08T00:00:00+00:00",
                "last_success_at": "2026-11-08T00:00:00+00:00",
                "version": "45.0.1.1-63.1",
            }
            write_json(receipt, success)
            config = {"feed": "http://invalid-before-any-network-request"}
            self.assertIn("error", self.request("linux-release", directory=temporary, config=config))
            failed = read_json(receipt)
            self.assertEqual(failed["last_success_at"], success["last_success_at"])
            self.assertEqual(failed["result"], "fail")
            (directory / "releases/45.0.1.1-63.1").mkdir(parents=True)
            environment = native_environment(directory / "commands", {"gpgv": {"code": 1}})
            self.assertIn(
                "error",
                self.request(
                    "linux-release",
                    directory=temporary,
                    config=config,
                    version="45.0.1.1-63.1",
                    environment=environment,
                ),
            )
            self.assertEqual(read_json(receipt), failed)
