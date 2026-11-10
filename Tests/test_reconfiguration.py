"""Exercise durable configuration transactions through the compiled implementation."""

import copy
import json
import tempfile
from pathlib import Path

from particleve.common import digest, read_json, write_json
from Tests.fixtures import host
from Tests.runtime import RustDriverTests, native_environment


class ReconfigurationTests(RustDriverTests):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.config_file = self.directory / "host.json"
        self.previous = host()
        self.proposed = copy.deepcopy(self.previous)
        self.proposed["maintenance"]["minimum_available_ram_mib"] = 1280
        self.manifest = {"schema": 1, "config_sha256": digest(self.previous), "devices": ["unchanged"]}
        write_json(self.directory / "installation.json", self.manifest)
        write_json(
            self.directory / "state.json", {"schema": 1, "maintenance": {"reason": "policy"}, "pending": None}
        )
        write_json(self.directory / "commissioned.json", {"old": "approval"})
        write_json(self.config_file, self.previous)
        self.log = self.directory / "native.jsonl"
        self.environment = native_environment(self.directory / "commands", {"systemctl": {}}) | {
            "PVE_NATIVE_COMMAND_LOG": str(self.log)
        }

    def fields(self):
        return {"directory": str(self.directory), "destination": str(self.config_file)}

    def preview(self):
        return self.evaluate(
            "reconfigure-preview", **self.fields(), previous=self.previous, proposed=self.proposed
        )

    def apply(self, confirmation, **extra):
        return self.evaluate(
            "reconfigure-apply",
            **self.fields(),
            previous=self.previous,
            proposed=self.proposed,
            confirm=confirmation,
            environment=self.environment,
            **extra,
        )

    def transaction(self, plan):
        return {
            "plan": plan,
            "previous_manifest": self.manifest,
            "proposed_manifest": self.manifest | {"config_sha256": digest(self.proposed)},
            "previous_config": self.previous,
            "proposed_config": self.proposed,
        }

    def test_reviewed_policy_rebinds_and_invalidates_automation(self):
        plan = self.preview()
        self.assertTrue((self.directory / "commissioned.json").exists())
        result = self.apply(plan["confirmation"])
        self.assertEqual(result["action"], "reconfigured")
        self.assertEqual(read_json(self.config_file), self.proposed)
        self.assertEqual(
            read_json(self.directory / "installation.json"),
            self.manifest | {"config_sha256": digest(self.proposed)},
        )
        self.assertFalse((self.directory / "commissioned.json").exists())
        self.assertFalse((self.directory / "reconfiguration.json").exists())
        self.assertTrue(read_json(self.directory / "state.json")["maintenance"])
        self.assertEqual(
            [json.loads(line) for line in self.log.read_text().splitlines()],
            [
                [
                    "systemctl",
                    "disable",
                    "--now",
                    "systemd-sysupdate-update.timer",
                    "particleve-maintenance.timer",
                ]
            ],
        )

    def test_interrupted_invalidation_keeps_exact_journal_and_resumes(self):
        plan = self.preview()
        failure = native_environment(self.directory / "interrupted", {"systemctl": {"code": 1}})
        self.assertIn(
            "error",
            self.request(
                "reconfigure-apply",
                **self.fields(),
                previous=self.previous,
                proposed=self.proposed,
                confirm=plan["confirmation"],
                environment=failure,
            ),
        )
        self.assertEqual(read_json(self.directory / "reconfiguration.json"), self.transaction(plan["plan"]))
        self.assertFalse((self.directory / "commissioned.json").exists())
        result = self.apply(plan["confirmation"])
        self.assertEqual(result["action"], "reconfigured")
        self.assertFalse((self.directory / "reconfiguration.json").exists())

    def test_fixed_disk_layout_identity_network_and_trust_changes_never_mutate(self):
        for path, value in (
            (["disks", 0, "serial"], "another"),
            (["storage", "esp_mib"], 4096),
            (["hostname"], "foreign"),
            (["time", "sources", 0, "server"], "other.example.org"),
        ):
            candidate = copy.deepcopy(self.proposed)
            target = candidate
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            self.assertIn(
                "error",
                self.request(
                    "reconfigure-apply",
                    **self.fields(),
                    previous=self.previous,
                    proposed=candidate,
                    confirm="bad",
                    environment=self.environment,
                ),
            )
            self.assertFalse(self.log.exists())
            self.assertFalse((self.directory / "reconfiguration.json").exists())
            self.assertEqual(read_json(self.config_file), self.previous)

    def test_fresh_process_resumes_without_either_original_input_file(self):
        plan = self.preview()
        write_json(self.directory / "reconfiguration.json", self.transaction(plan["plan"]))
        write_json(self.config_file, self.proposed)
        for installed in (self.manifest, self.transaction(plan["plan"])["proposed_manifest"]):
            write_json(self.directory / "installation.json", installed)
            result = self.evaluate("reconfigure-preview", **self.fields(), resume=True)
            self.assertEqual(result["confirmation"], plan["confirmation"])
            self.assertTrue(result["resume"])
        result = self.evaluate(
            "reconfigure-apply",
            **self.fields(),
            resume=True,
            confirm=plan["confirmation"],
            environment=self.environment,
        )
        self.assertEqual(result["action"], "reconfigured")
        self.assertEqual(
            read_json(self.directory / "installation.json")["config_sha256"], digest(self.proposed)
        )
        self.assertFalse((self.directory / "reconfiguration.json").exists())

    def test_resume_rejects_changed_confirmation_active_binding_and_journal(self):
        plan = self.preview()
        journal = self.transaction(plan["plan"])
        write_json(self.directory / "reconfiguration.json", journal)
        self.assertIn(
            "error",
            self.request(
                "reconfigure-apply",
                **self.fields(),
                resume=True,
                confirm="wrong",
                environment=self.environment,
            ),
        )
        active = copy.deepcopy(self.previous)
        active["maintenance"]["minimum_available_ram_mib"] = 1536
        write_json(self.config_file, active)
        self.assertIn(
            "error",
            self.request(
                "reconfigure-apply",
                **self.fields(),
                resume=True,
                confirm=plan["confirmation"],
                environment=self.environment,
            ),
        )
        write_json(self.config_file, self.previous)
        journal["previous_config"]["maintenance"]["minimum_available_ram_mib"] = 2048
        write_json(self.directory / "reconfiguration.json", journal)
        self.assertIn(
            "previous configuration",
            self.request(
                "reconfigure-apply",
                **self.fields(),
                resume=True,
                confirm=plan["confirmation"],
                environment=self.environment,
            )["error"],
        )
        self.assertFalse(self.log.exists())
        self.assertTrue((self.directory / "commissioned.json").exists())

    def test_status_and_disable_do_not_need_valid_configuration_binding(self):
        write_json(self.config_file, self.proposed)
        status = self.evaluate(
            "reconfigure-status", config_path=str(self.config_file), directory=str(self.directory)
        )
        self.assertFalse(status["config_binding"]["valid"])
        self.config_file.write_text("invalid JSON")
        status = self.evaluate(
            "reconfigure-status", config_path=str(self.config_file), directory=str(self.directory)
        )
        self.assertFalse(status["config_binding"]["valid"])
        self.assertEqual(
            self.evaluate("disable-automation", directory=str(self.directory), environment=self.environment),
            {"automation_enabled": False},
        )
        self.assertFalse((self.directory / "commissioned.json").exists())
