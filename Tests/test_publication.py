import contextlib
import io
import json
import runpy
import tempfile
import unittest
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from particleve.common import Error, read_json
from Tools.publication import (
    PACKAGES,
    HTTPSRedirects,
    assess,
    collect,
    read_source,
    request,
    source_revision,
    source_workflow,
)


class PublicationTests(unittest.TestCase):
    def test_source_selection_failure_is_visible_before_the_build_ref_moves(self):
        now = datetime(2026, 11, 13, tzinfo=UTC)
        args = (
            "a" * 40,
            dict.fromkeys(PACKAGES, "a" * 40),
            dict.fromkeys(PACKAGES, "succeeded"),
            {"sources": {"particleve": "a" * 40}, "version": "45.0.3.4-1.4"},
        )
        selection = {"revision": "b" * 40, "system_changes": 1, "workflow": "fail"}
        self.assertEqual(assess(*args, now=now, grace_seconds=7200, selection=selection)["result"], "fail")
        selection["workflow"] = "pending"
        pending = assess(*args, now=now, grace_seconds=7200, selection=selection)
        self.assertEqual(pending["result"], "pending")
        expired = assess(
            *args,
            now=now + timedelta(seconds=7201),
            grace_seconds=7200,
            selection=selection,
            previous=pending,
        )
        self.assertEqual(expired["result"], "fail")
        selection.update(system_changes=0, workflow="fail")
        self.assertEqual(assess(*args, now=now, grace_seconds=7200, selection=selection)["result"], "pass")

    def test_source_workflow_observation_is_bound_to_the_exact_push(self):
        run = {
            "head_sha": "a" * 40,
            "head_branch": "main",
            "event": "push",
            "path": ".github/workflows/check.yml",
            "status": "completed",
            "conclusion": "failure",
        }
        self.assertEqual(source_workflow({"total_count": 1, "workflow_runs": [run]}, "a" * 40), "fail")
        self.assertEqual(source_workflow({"total_count": 0, "workflow_runs": []}, "a" * 40), "pending")
        for key, value in (
            ("head_sha", "b" * 40),
            ("path", ".github/workflows/another.yml"),
            ("event", "pull_request"),
        ):
            with self.subTest(key=key), self.assertRaises(Error):
                source_workflow({"total_count": 1, "workflow_runs": [run | {key: value}]}, "a" * 40)

    def observe_builds(self, worker_statuses=(), *, previous=None):
        site = read_json(Path(__file__).resolve().parent.parent / ".obs/site.json")
        owner = '<person userid="' + site["obs_user"] + '" role="maintainer"/>'
        builds = (
            "<resultlist>"
            + "".join(
                f'<result repository="{repository}" arch="x86_64">'
                f'<status package="{package}" code="succeeded"/></result>'
                for repository, package, _ in PACKAGES.values()
            )
            + '<result repository="Fedora_45" arch="x86_64">'
            '<status package="particleve" code="excluded"/>'
            + "".join(f'<status package="kernel:build-policy" code="{code}"/>' for code in worker_statuses)
            + "</result></resultlist>"
        )
        manifest = {"sources": {"particleve": "a" * 40}, "version": "45.0.1.1-87.2", "artifacts": {}}

        def fetch(url, **_kwargs):
            if url.endswith(site["obs_project"] + "/_meta"):
                return ("<project>" + owner + "</project>").encode()
            if url.endswith("/_meta"):
                return b"<package/>"
            if "/_result?" in url:
                return builds.encode()
            if "/repos/" in url:
                return json.dumps({"sha": "a" * 40}).encode()
            return b"commit: " + b"a" * 40 + b"\n"

        with (
            patch("Tools.publication.request", side_effect=fetch) as requests,
            patch("Tools.publication.signed_manifest", return_value=manifest),
            patch("Tools.publication.kernel_freshness.collect", return_value=self.upstreams()),
        ):
            result = collect(site, "unused", "unused", previous=previous)
        return result, requests

    def test_one_source_package_can_publish_rpms_and_the_image_independently(self):
        result, requests = self.observe_builds()
        self.assertEqual(result["result"], "pass")
        self.assertIn("kernel:source", {check["name"] for check in result["checks"]})
        self.assertTrue(
            any(
                "/kernel/_service:obs_scm:particleve-kernel-inputs.obsinfo?" in call.args[0]
                for call in requests.call_args_list
            )
        )
        self.assertFalse(any("/image/" in call.args[0] for call in requests.call_args_list))
        self.assertFalse(any("/particleve:rpm/" in call.args[0] for call in requests.call_args_list))

    def test_kernel_worker_policy_failure_is_not_hidden_by_other_successful_builds(self):
        for code, expected in (("succeeded", "pass"), ("failed", "fail"), ("building", "pending")):
            with self.subTest(code=code):
                result, _ = self.observe_builds((code,))
                self.assertEqual(result["result"], expected)
                worker = next(c for c in result["checks"] if c["name"] == "kernel-build-policy:build")
                self.assertEqual(worker["code"], code)
        with self.assertRaisesRegex(Error, "ambiguous build observation: kernel:build-policy"):
            self.observe_builds(("succeeded", "failed"))
        observed, _ = self.observe_builds(("succeeded",))
        with self.assertRaisesRegex(Error, "missing or ambiguous build observation: kernel:build-policy"):
            self.observe_builds(previous=observed)

    def test_kernel_worker_policy_deadline_survives_build_to_signing_transition(self):
        now = datetime(2026, 11, 13, tzinfo=UTC)
        arguments = (
            "a" * 40,
            dict.fromkeys(PACKAGES, "a" * 40),
            dict.fromkeys(PACKAGES, "succeeded"),
            {"sources": {"particleve": "a" * 40}, "version": "45.0.3.5-1.1"},
        )
        initial = assess(*arguments, now=now, grace_seconds=7200, kernel_build_policy="building")
        self.assertEqual(initial["result"], "pending")
        expired = assess(
            *arguments,
            now=now + timedelta(seconds=7201),
            grace_seconds=7200,
            kernel_build_policy="signing",
            previous=initial,
        )
        self.assertEqual(expired["result"], "fail")
        recovered = assess(
            *arguments,
            now=now + timedelta(seconds=7202),
            grace_seconds=7200,
            kernel_build_policy="succeeded",
            previous=expired,
        )
        self.assertEqual(recovered["result"], "pass")

    def upstreams(self):
        return {
            "fedora-kernel:upstream": dict.fromkeys(("selected", "available"), "7.3.3-300.fc45@" + "a" * 40),
            "secureblue-kernel:upstream": dict.fromkeys(("selected", "available"), "b" * 40),
        }

    def test_updater_lag_expires_even_when_newer_upstream_updates_keep_arriving(self):
        now = datetime(2026, 11, 12, tzinfo=UTC)
        arguments = (
            "a" * 40,
            dict.fromkeys(PACKAGES, "a" * 40),
            dict.fromkeys(PACKAGES, "succeeded"),
            {"sources": {"particleve": "a" * 40}, "version": "45.0.3.0-1.1"},
        )
        for upstream in self.upstreams():
            with self.subTest(upstream=upstream):
                observed = self.upstreams()
                observed[upstream]["available"] = (
                    "7.3.3-300.fc45@" if upstream == "fedora-kernel:upstream" else ""
                ) + "c" * 40
                initial = assess(*arguments, now=now, grace_seconds=7200, upstreams=observed)
                self.assertEqual(initial["result"], "pending")
                observed[upstream]["available"] = (
                    "7.4.0-301.fc45@" if upstream == "fedora-kernel:upstream" else ""
                ) + "d" * 40
                expired = assess(
                    *arguments,
                    now=now + timedelta(seconds=7201),
                    grace_seconds=7200,
                    upstreams=observed,
                    previous=json.loads(json.dumps(initial)),
                )
                self.assertEqual(expired["result"], "fail")
                self.assertEqual(expired["checks"][-1]["result"], "pass")
                observed[upstream]["selected"] = observed[upstream]["available"]
                recovered = assess(
                    *arguments,
                    now=now + timedelta(seconds=7202),
                    grace_seconds=7200,
                    upstreams=observed,
                    previous=expired,
                )
                self.assertEqual(recovered["result"], "pass")
                self.assertFalse(any("pending_since" in item for item in recovered["checks"]))

    def test_missing_or_invalid_kernel_upstream_cannot_pass(self):
        arguments = (
            "a" * 40,
            dict.fromkeys(PACKAGES, "a" * 40),
            dict.fromkeys(PACKAGES, "succeeded"),
            {"sources": {"particleve": "a" * 40}, "version": "45.0.3.0-1.1"},
        )
        for value in ({}, {"unknown": {}}, self.upstreams() | {"fedora-kernel:upstream": {}}):
            with self.subTest(value=value), self.assertRaises(Error):
                assess(
                    *arguments,
                    now=datetime(2026, 11, 12, tzinfo=UTC),
                    grace_seconds=7200,
                    upstreams=value,
                )

    def report(self, *, age=60, sources=None, statuses=None, published=None):
        now = datetime(2026, 11, 8, tzinfo=UTC)
        first = assess(
            "a" * 40,
            sources or dict.fromkeys(PACKAGES, "a" * 40),
            statuses or dict.fromkeys(PACKAGES, "succeeded"),
            {"sources": {"particleve": published or "a" * 40}, "version": "45.0.1.1-63.1"},
            now=now - timedelta(seconds=age),
            grace_seconds=7200,
        )
        return assess(
            "a" * 40,
            sources or dict.fromkeys(PACKAGES, "a" * 40),
            statuses or dict.fromkeys(PACKAGES, "succeeded"),
            {"sources": {"particleve": published or "a" * 40}, "version": "45.0.1.1-63.1"},
            now=now,
            grace_seconds=7200,
            previous=first,
        )

    def test_complete_publication_passes(self):
        self.assertEqual(self.report()["result"], "pass")

    def test_delayed_source_and_feed_expire_without_terminal_build_failure(self):
        for age, expected in ((60, "pending"), (7201, "fail")):
            report = self.report(age=age, sources=dict.fromkeys(PACKAGES, "b" * 40), published="b" * 40)
            self.assertEqual(report["result"], expected)

    def test_terminal_failure_is_immediate_even_with_a_usable_current_feed(self):
        statuses = dict.fromkeys(PACKAGES, "succeeded")
        for code in ("failed", "unresolvable", "disabled", "broken", "new_unknown_state"):
            statuses["image"] = code
            report = self.report(statuses=statuses)
            self.assertEqual(report["result"], "fail")
            self.assertEqual(report["checks"][-1]["result"], "pass")

    def test_stalled_dependency_rebuild_does_not_claim_last_release_is_broken(self):
        statuses = dict.fromkeys(PACKAGES, "succeeded")
        for package in ("image", "kernel"):
            with self.subTest(package=package):
                pending = statuses | {package: "building"}
                report = self.report(age=100000, statuses=pending)
                self.assertEqual(report["result"], "fail")
                self.assertEqual(report["checks"][-1]["result"], "pass")
                check = next(c for c in report["checks"] if c["name"] == package + ":build")
                self.assertEqual(check["result"], "fail")

    def test_missing_observation_or_future_clock_cannot_pass(self):
        sources = dict.fromkeys(PACKAGES, "a" * 40)
        sources.pop("mkosi")
        with self.assertRaises(Error):
            self.report(sources=sources)
        with self.assertRaises(Error):
            self.report(age=-301)

    def test_stalled_dependency_build_expires_across_fresh_observer_processes(self):
        now = datetime(2026, 11, 8, tzinfo=UTC)
        statuses = dict.fromkeys(PACKAGES, "succeeded")
        statuses["image"] = "building"
        initial = self.report(statuses=statuses)
        statuses["image"] = "signing"
        report = assess(
            "a" * 40,
            dict.fromkeys(PACKAGES, "a" * 40),
            statuses,
            {"sources": {"particleve": "a" * 40}, "version": "45.0.1.1-63.1"},
            now=now + timedelta(seconds=7201),
            grace_seconds=7200,
            previous=json.loads(json.dumps(initial)),
        )
        self.assertEqual(report["result"], "fail")
        self.assertEqual(report["checks"][-1]["result"], "pass")
        statuses["image"] = "succeeded"
        recovered = assess(
            "a" * 40,
            dict.fromkeys(PACKAGES, "a" * 40),
            statuses,
            {"sources": {"particleve": "a" * 40}, "version": "45.0.1.1-63.1"},
            now=now + timedelta(seconds=7202),
            grace_seconds=7200,
            previous=report,
        )
        self.assertEqual(recovered["result"], "pass")

    def test_corrupt_observer_state_and_clock_rollback_cannot_reset_grace(self):
        now = datetime(2026, 11, 8, tzinfo=UTC)
        for previous in (
            {"schema": 2},
            {**self.report(), "observed_at": (now + timedelta(seconds=1)).isoformat()},
        ):
            with self.assertRaises(Error):
                assess(
                    "a" * 40,
                    dict.fromkeys(PACKAGES, "a" * 40),
                    dict.fromkeys(PACKAGES, "building"),
                    {"sources": {"particleve": "a" * 40}, "version": "45.0.1.1-63.1"},
                    now=now,
                    grace_seconds=7200,
                    previous=previous,
                )

    def test_obs_source_identity_rejects_ambiguous_or_missing_commit(self):
        line = b"commit: " + b"a" * 40 + b"\n"
        self.assertEqual(source_revision(line), "a" * 40)
        for data in (b"", line + line, b"commit: main\n"):
            with self.assertRaises(Error):
                source_revision(data)

    def test_https_cannot_downgrade_or_include_credentials(self):
        with self.assertRaises(Error):
            HTTPSRedirects().redirect_request(None, None, 302, "Found", {}, "http://example.org/file")
        for url in ("http://example.org", "https://owner:secret@example.org"):
            with self.assertRaises(Error), patch("urllib.request.build_opener") as opener:
                request(url)
            opener.assert_not_called()

    def test_bounded_reads_and_head_size_are_required(self):
        with patch("urllib.request.build_opener") as opener:
            response = opener.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b"x" * 5
            with self.assertRaises(Error):
                request("https://example.org/file", size_limit=4)
            response.read.assert_called_once_with(5)
            response.read.reset_mock()
            response.headers = {"Content-Length": "123"}
            self.assertEqual(request("https://example.org/file", method="HEAD"), 123)
            response.read.assert_not_called()
            for length in ("", "unknown", "-1"):
                response.headers = {"Content-Length": length}
                with self.assertRaises(Error):
                    request("https://example.org/file", method="HEAD")

    def test_http_failures_identify_the_endpoint_without_exporting_query_parameters(self):
        target = "https://example.org/path?private=hidden"
        error = urllib.error.HTTPError(target, 404, "Not Found", {}, None)
        with patch("urllib.request.build_opener") as opener:
            opener.return_value.open.side_effect = error
            with self.assertRaisesRegex(Error, r"publication HTTP 404: example\.org/path$") as result:
                request(target)
        self.assertNotIn("hidden", str(result.exception))
        self.assertNotIn("private", str(result.exception))

    def test_native_source_refresh_response_retains_its_pending_contract(self):
        error = urllib.error.HTTPError(
            "https://api.opensuse.org/source", 400, "service in progress", {}, None
        )
        with patch("urllib.request.build_opener") as opener:
            opener.return_value.open.side_effect = error
            self.assertIsNone(read_source("https://api.opensuse.org/source"))

    def test_observer_rejects_shared_state_before_any_network_request(self):
        script = Path(__file__).resolve().parent.parent / "Tools/check-publication.py"
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            state.chmod(0o755)
            output = io.StringIO()
            with (
                patch("sys.argv", [str(script), "--state-dir", str(state)]),
                patch("Tools.publication.collect") as collect,
                contextlib.redirect_stdout(output),
                self.assertRaises(SystemExit) as result,
            ):
                runpy.run_path(str(script), run_name="__main__")
            self.assertEqual(result.exception.code, 1)
            self.assertEqual(json.loads(output.getvalue())["result"], "unavailable")
            collect.assert_not_called()

    def test_package_access_expansion_is_rejected_before_feed_observation(self):
        site = read_json(Path(__file__).resolve().parent.parent / ".obs/site.json")
        owner = '<person userid="' + site["obs_user"] + '" role="maintainer"/>'
        for _, package, _ in PACKAGES.values():
            source_package = package.split(":", 1)[0]

            def fetch(url, selected=source_package, **_kwargs):
                if url.endswith("/" + selected + "/_meta"):
                    return b'<package><person userid="unexpected" role="maintainer"/></package>'
                if url.endswith("/_meta"):
                    return (
                        "<project>"
                        + (owner if url.endswith(site["obs_project"] + "/_meta") else "")
                        + "</project>"
                    ).encode()
                if "/repos/" in url:
                    return json.dumps(
                        {"sha": "a" * 40, "commit": {"committer": {"date": "2026-11-08T00:00:00Z"}}}
                    ).encode()
                if "/_result?" in url:
                    return b"<resultlist/>"
                return b"commit: " + b"a" * 40 + b"\n"

            with (
                patch("Tools.publication.request", side_effect=fetch),
                patch("Tools.publication.signed_manifest") as manifest,
                self.assertRaisesRegex(Error, "OBS package access"),
            ):
                collect(site, "unused", "unused")
            manifest.assert_not_called()

    def test_observer_policy_binding_is_checked_before_network_access(self):
        with patch("Tools.publication.request") as fetch, self.assertRaises(Error):
            collect({}, "unused", "unused", previous={"site_sha256": "unrelated"})
        fetch.assert_not_called()

    def test_finished_is_pending_until_obs_decides_success_or_failure(self):
        statuses = dict.fromkeys(PACKAGES, "succeeded")
        statuses["image"] = "finished"
        self.assertEqual(self.report(statuses=statuses)["result"], "pending")

    def test_source_service_refresh_is_pending_and_expires_without_claiming_a_revision(self):
        for age, expected in ((60, "pending"), (7201, "fail")):
            self.assertEqual(self.report(age=age, sources=dict.fromkeys(PACKAGES, None))["result"], expected)
        for code, reason, transitional in (
            (400, "service in progress", True),
            (400, "bad request", False),
            (403, "Forbidden", False),
        ):
            error = urllib.error.HTTPError("https://api.opensuse.org/source", code, reason, {}, None)
            with patch("Tools.publication.request", side_effect=error):
                if transitional:
                    self.assertIsNone(read_source("unused"))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        read_source("unused")
