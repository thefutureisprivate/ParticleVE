"""Check compiled host contracts against build inputs and explicit regression fixtures."""

import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import consoles, contracts, release
from particleve.common import Error, digest, read_json, write_json
from Tests import test_consoles
from Tests.fixtures import host
from Tests.fixtures import release as release_fixture
from Tests.runtime import RustDriverTests


class RustOrchestrationTests(RustDriverTests):
    def compare(self, operation, expected, **fields):
        actual = self.request(operation, **fields)
        try:
            value = expected()
        except Error, OSError, ValueError, KeyError, TypeError:
            self.assertIn("error", actual, fields)
        else:
            self.assertEqual(actual, {"ok": value}, fields)

    def test_bound_legacy_time_trust_only_enters_reviewed_system_store_transition(self):
        previous = host()
        previous["time"]["sources"][0]["trust"] = "installation"
        previous["time"]["certificates"] = (
            Path(__file__).resolve().parent.parent / "mkosi.extra/usr/lib/particleve/trust/secure-boot.crt"
        ).read_text()
        proposed = copy.deepcopy(previous)
        proposed["time"]["sources"][0]["trust"] = "system"
        proposed["time"]["certificates"] = ""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            destination = directory / "host.json"
            manifest = {"schema": 1, "config_sha256": digest(previous), "devices": ["unchanged"]}
            write_json(directory / "installation.json", manifest)
            write_json(
                directory / "state.json", {"schema": 1, "maintenance": {"reason": "trust"}, "pending": None}
            )
            write_json(destination, previous)
            fields = {
                "directory": str(directory),
                "destination": str(destination),
                "previous": previous,
                "proposed": proposed,
            }
            result = self.request("reconfigure-preview", **fields)["ok"]
            self.assertEqual(result["confirmation"], digest(result["plan"]))
            self.assertEqual(
                result["plan"]["system_trust_transition"],
                {
                    "previous_time_policy_sha256": digest(previous["time"]),
                    "proposed_time_policy_sha256": digest(proposed["time"]),
                },
            )
            self.assertEqual(
                self.request("maintenance-input", config=previous, directory=str(directory)), {"ok": previous}
            )
            self.assertIn("error", self.request("config-validate", config=previous, publication=True))
            self.assertEqual(read_json(destination), previous)
            self.assertFalse((directory / "reconfiguration.json").exists())
            for mutation in ("previous", "source", "disk", "reverse"):
                arguments = copy.deepcopy(fields)
                if mutation == "previous":
                    arguments["previous"]["hostname"] = "another-host"
                elif mutation == "source":
                    arguments["proposed"]["time"]["sources"][0]["server"] = "other.example.org"
                elif mutation == "disk":
                    arguments["proposed"]["disks"][0]["serial"] = "another-disk"
                else:
                    arguments["proposed"] = previous
                self.assertIn("error", self.request("reconfigure-preview", **arguments), mutation)
            new_manifest = manifest | {"config_sha256": digest(proposed)}
            write_json(
                directory / "reconfiguration.json",
                {
                    "plan": result["plan"],
                    "previous_manifest": manifest,
                    "proposed_manifest": new_manifest,
                    "previous_config": previous,
                    "proposed_config": proposed,
                },
            )
            write_json(destination, proposed)
            for installed in (manifest, new_manifest):
                write_json(directory / "installation.json", installed)
                resumed = self.request(
                    "reconfigure-preview", directory=str(directory), destination=str(destination), resume=True
                )["ok"]
                self.assertEqual(resumed["confirmation"], result["confirmation"])
                self.assertTrue(resumed["resume"])

    def test_persisted_interfaces_match_build_provenance(self):
        self.assertEqual(self.evaluate("persistent-contracts"), contracts.PERSISTENT_STATE)

    def test_configuration_and_source_identity_contracts(self):
        selected = host()
        self.assertEqual(self.evaluate("config-validate", config=selected, publication=True), selected)
        for feed in (
            "https:updates.example.org",
            "https:/updates.example.org",
            "https:///updates.example.org",
            "https:////updates.example.org",
        ):
            candidate = copy.deepcopy(selected)
            candidate["feed"] = feed
            self.assertIn("error", self.request("config-validate", config=candidate, publication=True))
        candidate = copy.deepcopy(selected)
        candidate["feed"] = "HTTPS://updates.example.org/feed"
        self.assertEqual(self.evaluate("config-validate", config=candidate, publication=True), candidate)
        for mutate in (
            lambda value: value.update(schema=1),
            lambda value: value["disks"][0].update(path="/dev/sda"),
            lambda value: value["storage"].update(discard=True),
            lambda value: value["network"].update(allowed_sources=["0.0.0.0/0"]),
            lambda value: value["network"].update(addresses=["2001:db8::1%eth0/64"]),
            lambda value: value["maintenance"].update(graceful_seconds=1801),
            lambda value: value.update(tpm_policy="pcr7"),
        ):
            candidate = copy.deepcopy(selected)
            mutate(candidate)
            self.assertIn("error", self.request("config-validate", config=candidate))
        for version, key in (
            ("45.0.1.1-1.1", [45, 0, 1, 1, 1, 1]),
            ("45.0.1.13-87.2", [45, 0, 1, 13, 87, 2]),
        ):
            self.assertEqual(self.evaluate("version-key", version=version), key)
        for version in ("45.0.1.1-01.1", "0.0.1.1-1.1", "45.0.1.1"):
            self.assertIn("error", self.request("version-key", version=version))

    def test_every_signed_console_has_native_network_and_getty_configuration(self):
        for console in ("console=tty0", *consoles.SERIAL_CONSOLES.values()):
            selected = host()
            selected["console"] = console
            files = self.evaluate("network-render", config=selected)
            expected = next(
                (name for name, argument in consoles.SERIAL_CONSOLES.items() if argument == console), None
            )
            self.assertEqual(self.evaluate("consoles-profile", config=selected), expected)
            self.assertEqual(files["etc/hostname"], selected["hostname"] + "\n")
            if console != "console=tty0":
                port, baud = console.removeprefix("console=").split(",")
                unit = f"etc/systemd/system/serial-getty@{port}.service.d/50-particleve.conf"
                self.assertIn("--noreset", files[unit])
                self.assertIn(baud.removesuffix("n8") + " vt220", files[unit])
                self.assertEqual(
                    files["etc/systemd/system/getty.target.d/50-particleve-console.conf"],
                    f"[Unit]\nWants=serial-getty@{port}.service\n",
                )
        selected = host()
        selected["network"]["bridges"] = [{"name": "br0"}]
        selected["network"]["vlans"] = [{"name": "vlan7", "id": 7, "parent": "mgmt0", "bridge": "br0"}]
        files = self.evaluate("network-render", config=selected)
        self.assertIn("VLAN=vlan7\n", files["etc/systemd/network/30-particleve-mgmt0.network"])
        self.assertIn("Bridge=br0\n", files["etc/systemd/network/30-particleve-vlan7.network"])
        firewall = self.evaluate("network-firewall", config=selected)
        self.assertTrue(firewall.startswith("destroy table inet particleve_host\n"))
        self.assertIn("policy drop;", firewall)
        for source in selected["network"]["allowed_sources"]:
            self.assertIn(f"saddr {source} tcp dport 22 accept", firewall)

    def test_release_and_transfer_identity_match_build_contracts(self):
        selected = release_fixture()
        self.compare("release-validate", lambda: release.validate(selected), manifest=selected)
        transfers = self.evaluate(
            "release-transfers",
            manifest=selected,
            disk="/dev/disk/by-id/selected",
            source="/var/lib/particleve/releases/45.0.1.2-1.1",
            current="45.0.1.1-1.1",
        )
        self.assertEqual(set(transfers), {"10-verity_sig.transfer", "11-verity.transfer", "12-usr.transfer"})
        for name, content in transfers.items():
            self.assertIn("ProtectVersion=45.0.1.1-1.1\nVerify=yes\n", content)
            self.assertIn("Path=/dev/disk/by-id/selected\n", content)
            self.assertIn("MatchPattern=PVE_@v\n", content)
            self.assertIn("ReadOnly=yes\nInstancesMax=2\n", content)
            kind = name.removesuffix(".transfer").split("-", 1)[1]
            self.assertIn("PartitionUUID=" + selected["artifacts"][kind]["partition_uuid"] + "\n", content)
        for mutate in (
            lambda value: value.update(architecture="arm64"),
            lambda value: value["artifacts"]["uki"].update(file="../unreviewed.efi"),
            lambda value: value["artifacts"]["usr"].update(
                partition_uuid="11111111-2222-3333-4444-555555555555"
            ),
            lambda value: value["artifacts"]["verity_sig"].update(size=1),
        ):
            candidate = copy.deepcopy(selected)
            mutate(candidate)
            self.compare(
                "release-validate",
                lambda candidate=candidate: release.validate(candidate),
                manifest=candidate,
            )

    def test_every_signed_console_profile_is_independently_verified(self):
        source = test_consoles.ConsoleTests().sections()
        for mutate in (
            lambda value: None,
            lambda value: value["_profiles"].pop(),
            lambda value: value["_profiles"][-1].pop(".pcrsig"),
            lambda value: value["_profiles"][-1].update({".linux": {"size": 42}}),
            lambda value: value["_profiles"][-1].update({".pcrsig": value["_profiles"][0][".pcrsig"]}),
        ):
            selected = copy.deepcopy(source)
            mutate(selected)

            def expected(selected=selected):
                with patch(
                    "particleve.release.run",
                    return_value=SimpleNamespace(stdout=json.dumps(selected), stderr=""),
                ):
                    return release.inspect_uki("test-only.efi", release_fixture())

            self.compare("verify-uki-sections", expected, sections=selected, manifest=release_fixture())
