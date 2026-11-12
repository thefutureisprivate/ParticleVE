import base64
import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from Tools.kernel_updates import (
    KERNEL_INPUTS,
    OUTPUTS,
    blob,
    build_metadata,
    candidate,
    context,
    locked_update,
    prepare,
    publish,
    report_check,
    validate_plan,
)
from Tools.sourcegit import git as native_git


class KernelUpdateTests(unittest.TestCase):
    repository = "fixture/ParticleVE"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-q", "--initial-branch=main")
        self.lock = json.loads(Path("sources.lock.json").read_text())
        self.write("sources.lock.json", json.dumps(self.lock))
        for path in OUTPUTS:
            self.write(path, "trusted generated input\n")
        self.write(
            KERNEL_INPUTS, json.dumps({"fedora_version": {"specrpmversion": "7.3.3", "pkgrelease": "300"}})
        )
        self.write(
            "mkosi.extra/usr/lib/particleve/build.json",
            json.dumps(
                {
                    "schema": 1,
                    "sources": {name: pin["revision"] for name, pin in self.lock["sources"].items()},
                }
            ),
        )
        self.write("Tools/generator.py", "trusted base implementation\n")
        self.base = self.commit("Trusted base")
        self.updated = copy.deepcopy(self.lock)
        self.updated["sources"]["fedora_kernel"]["revision"] = "a" * 40
        self.write("sources.lock.json", json.dumps(self.updated))
        self.head = self.commit("Renovate source pin")
        self.git("checkout", "-q", "--detach", self.base)
        bot = {"login": "renovate[bot]", "type": "Bot"}
        self.event = {
            "action": "synchronize",
            "sender": bot,
            "repository": {"full_name": self.repository},
            "pull_request": {
                "number": 17,
                "state": "open",
                "user": bot,
                "changed_files": 1,
                "base": {"sha": self.base, "ref": "main", "repo": {"full_name": self.repository}},
                "head": {
                    "sha": self.head,
                    "ref": "renovate/kernel-source-pins",
                    "repo": {"full_name": self.repository},
                },
            },
        }

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=self.env,
        ).stdout.strip()

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def commit(self, subject):
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            subject,
        )
        return self.git("rev-parse", "HEAD")

    def offline_git(self, root, *arguments, **options):
        if arguments[0] == "fetch":
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        return native_git(root, *arguments, **options)

    def plan(self):
        return {
            **context(self.event, self.repository),
            "files": {
                OUTPUTS[0]: base64.b64encode(b"regenerated recipe\n").decode(),
            },
        }

    def test_candidate_blob_preserves_exact_line_endings(self):
        path = self.root / OUTPUTS[0]
        path.write_bytes(b"candidate generated input\r\n")
        commit = self.commit("Candidate output with CRLF")
        self.assertEqual(blob(self.root, commit, OUTPUTS[0]), "candidate generated input\r\n")

    def test_only_reviewed_immutable_revisions_may_change(self):
        self.assertEqual(locked_update(self.lock, self.updated), self.updated)
        variants = []
        for key, value in (
            ("url", "https://unrelated.invalid/source.git"),
            ("branch", "f46"),
            ("revision", "main"),
        ):
            candidate = copy.deepcopy(self.updated)
            candidate["sources"]["fedora_kernel"][key] = value
            variants.append(candidate)
        for key, value in (("fedora", "46"), ("compatibility", "different policy")):
            candidate = copy.deepcopy(self.updated)
            candidate[key] = value
            variants.append(candidate)
        candidate = copy.deepcopy(self.updated)
        candidate["sources"]["mkosi"]["revision"] = "b" * 40
        variants.append(candidate)
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(Error):
                locked_update(self.lock, candidate)
        with self.assertRaisesRegex(Error, "did not change"):
            locked_update(self.lock, self.lock)

    def test_published_version_request_does_not_need_an_unbuilt_git_tip(self):
        self.write(
            KERNEL_INPUTS, json.dumps({"fedora_version": {"specrpmversion": "7.4.1", "pkgrelease": "301"}})
        )
        head = self.commit("Renovate published kernel version")
        self.git("checkout", "-q", "--detach", self.base)
        selected = context(self.event, self.repository) | {"head": head}
        with patch("Tools.kernel_updates.git", self.offline_git):
            self.assertEqual(candidate(self.root, selected), self.lock)

    def test_generated_fedora_pin_cannot_replace_other_lock_policy(self):
        selected = context(self.event, self.repository)
        plan = {
            **selected,
            "files": {"sources.lock.json": base64.b64encode(json.dumps(self.updated).encode()).decode()},
        }
        self.assertEqual(validate_plan(plan, selected, self.lock), plan["files"])
        with self.assertRaisesRegex(Error, "trusted base lock"):
            validate_plan(plan, selected)
        changed = copy.deepcopy(self.updated)
        changed["sources"]["fedora_kernel"]["url"] = "https://unrelated.invalid/kernel.git"
        plan["files"]["sources.lock.json"] = base64.b64encode(json.dumps(changed).encode()).decode()
        with self.assertRaises(Error):
            validate_plan(plan, selected, self.lock)

    def test_published_version_preparation_resolves_verifies_and_generates_the_pin(self):
        self.write(
            KERNEL_INPUTS, json.dumps({"fedora_version": {"specrpmversion": "7.4.1", "pkgrelease": "301"}})
        )
        head = self.commit("Renovate RPM coordinate")
        self.git("checkout", "-q", "--detach", self.base)
        event = copy.deepcopy(self.event)
        event["pull_request"]["head"]["sha"] = head
        published = {"version": "7.4.1", "release": "301.fc45", "revision": "c" * 40}

        def local_git(root, *arguments, **options):
            if arguments[0] in ("fetch", "checkout"):
                return SimpleNamespace(stdout="", stderr="", returncode=0)
            return native_git(root, *arguments, **options)

        with (
            patch("Tools.kernel_updates.git", local_git),
            patch("Tools.kernel_updates.fetch"),
            patch("Tools.kernel_updates.fedora_kernel.resolve", return_value=published) as resolve,
            patch("Tools.kernel_updates.fedora_kernel.verify_published") as verified,
            patch(
                "Tools.kernel_updates.generate",
                return_value={
                    path.removeprefix(".obs/kernel/"): "regenerated\n"
                    for path in OUTPUTS
                    if path.startswith(".obs/kernel/")
                },
            ),
        ):
            plan = prepare(self.root, event, self.repository, self.root / "prepared")
        resolve.assert_called_once_with("7.4.1-301.fc45", "45")
        self.assertEqual(verified.call_count, 1)
        self.assertEqual(verified.call_args.args[:2], (published, "45"))
        generated = json.loads(base64.b64decode(plan["files"]["sources.lock.json"]))
        expected = copy.deepcopy(self.lock)
        expected["sources"]["fedora_kernel"]["revision"] = published["revision"]
        self.assertEqual(generated, expected)
        self.assertEqual(json.loads((self.root / "sources.lock.json").read_text()), self.lock)

    def test_an_unbuilt_fedora_revision_cannot_override_the_published_source(self):
        with (
            patch("Tools.kernel_updates.git", self.offline_git),
            patch("Tools.kernel_updates.fedora_kernel.resolve", return_value={"revision": "b" * 40}),
            patch("Tools.kernel_updates.fedora_kernel.verify_published") as verified,
            self.assertRaisesRegex(Error, "published source"),
        ):
            prepare(self.root, self.event, self.repository, self.root / "not-prepared")
        verified.assert_not_called()

    def test_forks_nonbot_events_and_unapproved_refs_are_rejected(self):
        variants = []
        for side, field, value in (
            ("head", "ref", "main"),
            ("head", "ref", "renovate/../main"),
            ("head", "sha", "HEAD"),
            ("base", "ref", "build"),
        ):
            event = copy.deepcopy(self.event)
            event["pull_request"][side][field] = value
            variants.append(event)
        for key, value in (("state", "closed"), ("changed_files", len(OUTPUTS) + 2)):
            event = copy.deepcopy(self.event)
            event["pull_request"][key] = value
            variants.append(event)
        event = copy.deepcopy(self.event)
        event["pull_request"]["head"]["repo"]["full_name"] = "foreign/ParticleVE"
        variants.append(event)
        event = copy.deepcopy(self.event)
        event["sender"] = {"login": "ordinary-user", "type": "User"}
        variants.append(event)
        for event in variants:
            with self.subTest(event=event), self.assertRaises(Error):
                context(event, self.repository)

    def test_kernel_update_refreshes_image_source_claims_without_changing_other_metadata(self):
        original = {
            "schema": 1,
            "sources": {name: pin["revision"] for name, pin in self.lock["sources"].items()},
            "feed": "https://feed.example.invalid/particleve",
            "cpu_baseline": "x86-64-v2",
        }
        updated = json.loads(build_metadata(self.lock, self.updated, original))
        self.assertEqual(updated["sources"]["fedora_kernel"], "a" * 40)
        self.assertEqual(updated | {"sources": original["sources"]}, original)
        self.assertEqual(
            original["sources"]["fedora_kernel"], self.lock["sources"]["fedora_kernel"]["revision"]
        )
        original["sources"]["mkosi"] = "0" * 40
        with self.assertRaisesRegex(Error, "metadata differs"):
            build_metadata(self.lock, self.updated, original)

    def test_candidate_is_read_as_data_without_executing_or_checking_out_head(self):
        self.git("checkout", "-q", "--detach", self.head)
        self.write(OUTPUTS[0], "$(touch compromised)\n")
        head = self.commit("Untrusted generated text")
        self.git("checkout", "-q", "--detach", self.base)
        selected = {**context(self.event, self.repository), "head": head}
        with patch("Tools.kernel_updates.git", side_effect=self.offline_git):
            self.assertEqual(candidate(self.root, selected), self.updated)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.assertEqual((self.root / OUTPUTS[0]).read_text(), "trusted generated input\n")
        self.assertFalse((self.root / "compromised").exists())

    def test_code_changes_and_generated_symlinks_are_rejected(self):
        for name in ("Tools/generator.py", OUTPUTS[0]):
            self.git("checkout", "-q", "--detach", self.head)
            if name == OUTPUTS[0]:
                (self.root / name).unlink()
                (self.root / name).symlink_to("/etc/passwd")
            else:
                self.write(name, "different implementation\n")
            head = self.commit("Unapproved candidate input")
            self.git("checkout", "-q", "--detach", self.base)
            selected = {**context(self.event, self.repository), "head": head}
            with patch("Tools.kernel_updates.git", side_effect=self.offline_git), self.assertRaises(Error):
                candidate(self.root, selected)

    def test_publication_uses_expected_head_and_dispatches_exact_verified_commit(self):
        new = "f" * 40
        responses = [
            self.event["pull_request"],
            {"data": {"createCommitOnBranch": {"commit": {"oid": new, "signature": {"isValid": True}}}}},
            None,
        ]
        with patch("Tools.kernel_updates.api", side_effect=responses) as api:
            self.assertEqual(publish(self.root, self.event, self.repository, self.plan()), new)
        mutation = api.call_args_list[1].args[1]["variables"]["input"]
        self.assertEqual(mutation["expectedHeadOid"], self.head)
        self.assertEqual(
            mutation["branch"],
            {"repositoryNameWithOwner": self.repository, "refName": "renovate/kernel-source-pins"},
        )
        self.assertEqual({item["path"] for item in mutation["fileChanges"]["additions"]}, {OUTPUTS[0]})
        self.assertEqual(api.call_args_list[-1].args[1], {"ref": "main", "inputs": {"source_commit": new}})

    def test_unapproved_plan_or_changed_pr_ownership_cannot_write(self):
        plan = self.plan()
        plan["files"][".github/workflows/check.yml"] = base64.b64encode(b"unapproved").decode()
        with patch("Tools.kernel_updates.api") as api, self.assertRaises(Error):
            publish(self.root, self.event, self.repository, plan)
        api.assert_not_called()
        pr = copy.deepcopy(self.event["pull_request"])
        pr["head"]["repo"]["full_name"] = "foreign/ParticleVE"
        with patch("Tools.kernel_updates.api", return_value=pr) as api, self.assertRaises(Error):
            publish(self.root, self.event, self.repository, self.plan())
        self.assertEqual(api.call_count, 1)

    def test_unverified_generated_commit_does_not_dispatch_source_checks(self):
        responses = [
            self.event["pull_request"],
            {
                "data": {
                    "createCommitOnBranch": {"commit": {"oid": "e" * 40, "signature": {"isValid": False}}}
                }
            },
        ]
        with (
            patch("Tools.kernel_updates.api", side_effect=responses) as api,
            self.assertRaisesRegex(Error, "verify"),
        ):
            publish(self.root, self.event, self.repository, self.plan())
        self.assertEqual(api.call_count, 2)

    def test_late_completed_append_is_reconciled_without_a_second_commit(self):
        self.git("checkout", "-q", "--detach", self.head)
        self.write(OUTPUTS[0], "regenerated recipe\n")
        appended = self.commit("Completed generated append")
        self.git("checkout", "-q", "--detach", self.base)
        pr = copy.deepcopy(self.event["pull_request"])
        pr["head"]["sha"] = appended
        with (
            patch("Tools.kernel_updates.git", side_effect=self.offline_git),
            patch(
                "Tools.kernel_updates.api", side_effect=[pr, {"verification": {"verified": True}}, None]
            ) as api,
        ):
            self.assertEqual(publish(self.root, self.event, self.repository, self.plan()), appended)
        self.assertFalse(any(call.args[0] == "graphql" for call in api.call_args_list))
        self.assertEqual(api.call_args_list[-1].args[1]["inputs"]["source_commit"], appended)
        self.git("checkout", "-q", "--detach", appended)
        self.write("unrelated", "concurrent work\n")
        independent = self.commit("Independent later change")
        self.git("checkout", "-q", "--detach", self.base)
        pr["head"]["sha"] = independent
        with (
            patch("Tools.kernel_updates.git", side_effect=self.offline_git),
            patch("Tools.kernel_updates.api", return_value=pr) as api,
            self.assertRaisesRegex(Error, "advanced independently"),
        ):
            publish(self.root, self.event, self.repository, self.plan())
        self.assertEqual(api.call_count, 1)

    def test_candidate_reporting_cannot_change_repository_url_or_result(self):
        url = "https://github.com/" + self.repository + "/actions/runs/123"
        with patch("Tools.kernel_updates.api") as api:
            report_check(self.repository, self.head, "success", url)
        self.assertEqual(api.call_args.args[1]["head_sha"], self.head)
        self.assertEqual(api.call_args.args[1]["conclusion"], "success")
        for sha, result, link in (
            ("main", "success", url),
            (self.head, "passed", url),
            (self.head, "success", "https://unrelated.invalid/run"),
        ):
            with patch("Tools.kernel_updates.api") as api, self.assertRaises(Error):
                report_check(self.repository, sha, result, link)
            api.assert_not_called()
