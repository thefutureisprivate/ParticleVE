import copy
import tempfile
import unittest
from pathlib import Path

from particleve import layout, release
from particleve.common import Error, atomic_write, read_json
from Tests.fixtures import ROOT, devices, host
from Tests.fixtures import release as fixture_release
from Tests.runtime import RustDriverTests


class PlatformTests(RustDriverTests):
    def test_layout_uses_smaller_disk_and_explicit_partitions(self):
        result = self.evaluate(
            "layout-calculate", config=host(), devices=devices(), release=fixture_release()
        )
        first, second = result["devices"]
        self.assertEqual(
            [(p["offset"], p["size"]) for p in first["partitions"]],
            [(p["offset"], p["size"]) for p in second["partitions"]],
        )
        self.assertNotEqual(first["partitions"][0]["uuid"], second["partitions"][0]["uuid"])
        for disk in result["devices"]:
            script = self.evaluate("sfdisk-script", device=disk)
            self.assertIn("unit: sectors", script)
            self.assertEqual(len(disk["partitions"]), 9)
            self.assertTrue(
                all(p["offset"] % layout.MIB == 0 and p["size"] % layout.MIB == 0 for p in disk["partitions"])
            )

    def test_four_kn_sector_geometry(self):
        observed = devices()
        for disk in observed:
            disk["logical_sector"] = 4096
        result = self.evaluate("layout-calculate", config=host(), devices=observed, release=fixture_release())
        self.assertIn("start=256,", self.evaluate("sfdisk-script", device=result["devices"][0]))

    def test_signature_slots_have_no_unwritten_growth_tail(self):
        candidate = host()
        candidate["storage"]["usr_growth_percent"] = 90
        result = self.evaluate(
            "layout-calculate", config=candidate, devices=devices(), release=fixture_release()
        )
        for disk in result["devices"]:
            signatures = [p for p in disk["partitions"] if p["role"].endswith("_verity_sig")]
            self.assertEqual([p["size"] for p in signatures], [layout.MIB, layout.MIB])

    def test_too_small_duplicate_disk_and_bad_sectors_rejected(self):
        for mutation in ("small", "alias", "sectors"):
            observed = devices()
            if mutation == "small":
                observed[0]["size"] = 8 * layout.GIB
            elif mutation == "alias":
                observed[1]["identity"] = observed[0]["identity"]
            else:
                observed[0]["logical_sector"] = 520
            with self.subTest(mutation=mutation):
                self.assertIn(
                    "error",
                    self.request(
                        "layout-calculate", config=host(), devices=observed, release=fixture_release()
                    ),
                )

    def test_config_rejects_unsafe_inputs(self):
        for path, value in (
            (["disks", 0, "path"], "/dev/sda"),
            (["network", "allowed_sources"], ["0.0.0.0/0"]),
            (["network", "addresses"], ["2001:db8::10%eth0\nDNSOverTLS=no/64"]),
            (["network", "gateways"], ["2001:db8::1%eth0\nDNSSEC=no"]),
            (["network", "allowed_sources"], ["2001:db8::%eth0\naccept/64"]),
            (["maintenance", "graceful_seconds"], 0),
            (["maintenance", "minimum_available_ram_mib"], 0),
            (["maintenance", "minimum_available_ram_mib"], 4096),
            (["storage", "discard"], True),
            (["storage", "minimum_state_mib"], True),
            (["admin_ssh_keys"], ["REPLACE"]),
        ):
            candidate = host()
            target = candidate
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertIn("error", self.request("config-validate", config=candidate))

    def test_network_single_owner_and_cycles(self):
        candidate = host()
        candidate["network"]["bridges"] = [{"name": "br0"}]
        candidate["network"]["links"][0]["bridge"] = "br0"
        candidate["network"]["management"] = "br0"
        rendered = self.evaluate("network-render", config=self.evaluate("config-validate", config=candidate))
        physical = rendered["etc/systemd/network/30-particleve-mgmt0.network"]
        self.assertIn("Bridge=br0", physical)
        self.assertNotIn("Address=", physical)
        firewall = self.evaluate("network-firewall", config=candidate)
        self.assertIn("ip6 saddr 2001:db8:1::/64", firewall)
        self.assertNotIn("flush ruleset", firewall)
        self.assertNotIn("forward", firewall)
        for prefix in ("vt-*", "ns-*"):
            self.assertIn(f'iifname "{prefix}" meta nfproto ipv4 udp sport 68 udp dport 67 accept', firewall)
        candidate["network"]["vlans"] = [{"name": "v10", "id": 10, "parent": "br0", "bridge": "br0"}]
        self.assertIn("error", self.request("config-validate", config=candidate))

    def test_release_requires_complete_immutable_artifacts(self):
        manifest = fixture_release()
        release.validate(manifest)
        for change in ("traversal", "missing", "state", "uuid", "signature-size", "version"):
            broken = copy.deepcopy(manifest)
            if change == "traversal":
                broken["artifacts"]["uki"]["file"] = "../uki.efi"
            elif change == "missing":
                del broken["artifacts"]["fwupd_efi"]
            elif change == "state":
                broken["persistent_state"] = {}
            elif change == "uuid":
                broken["artifacts"]["usr"]["partition_uuid"] = "00000000-0000-0000-0000-000000000000"
            elif change == "signature-size":
                broken["artifacts"]["verity_sig"]["size"] = 3270
            else:
                broken["version"] = "9999999.9999999"
            with self.subTest(change=change), self.assertRaises(Error):
                release.validate(broken)

    def test_serial_console_is_an_explicit_per_installation_getty(self):
        candidate = host()
        candidate["console"] = "console=ttyS2,38400n8"
        files = self.evaluate("network-render", config=self.evaluate("config-validate", config=candidate))
        self.assertIn(
            "serial-getty@ttyS2.service",
            files["etc/systemd/system/getty.target.d/50-particleve-console.conf"],
        )
        self.assertIn(
            "38400 vt220", files["etc/systemd/system/serial-getty@ttyS2.service.d/50-particleve.conf"]
        )
        self.assertIn(
            r"-o '-p -- \\u'",
            files["etc/systemd/system/serial-getty@ttyS2.service.d/50-particleve.conf"],
        )

    def test_transfers_target_both_explicit_disks_and_preserve_running_release(self):
        manifest = fixture_release()
        for item in manifest["artifacts"].values():
            if "partition_uuid" in item:
                item["file"] = item["file"].replace(
                    item["partition_uuid"], item["partition_uuid"].replace("-", "")
                )
        for disk in host()["disks"]:
            definitions = self.evaluate(
                "release-transfers",
                manifest=manifest,
                disk=disk["path"],
                source="/var/cache/particleve/45.0.1.2-1.1",
                current="45.0.1.1-1.1",
            )
            self.assertEqual(len(definitions), 3)
            for kind, text in zip(("verity_sig", "verity", "usr"), definitions.values(), strict=True):
                self.assertIn("Path=" + disk["path"], text)
                self.assertIn("ProtectVersion=45.0.1.1-1.1", text)
                self.assertIn("PartitionUUID=" + manifest["artifacts"][kind]["partition_uuid"], text)
                self.assertNotIn("PathRelativeTo=explicit", text)
                self.assertNotIn("Path=auto", text)
                self.assertNotIn("--reboot", text)

    def test_atomic_json_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "state.json"
            atomic_write(target, b'{"accepted": ["1"]}')
            self.assertEqual(read_json(target)["accepted"], ["1"])
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            atomic_write(target, b'{"a":1,"a":2}')
            with self.assertRaises(Error):
                read_json(target)

    def test_schedule_no_catchup_and_automatic_work_disabled_by_default(self):
        timer = (ROOT / "mkosi.extra/usr/lib/systemd/system/particleve-maintenance.timer").read_text()
        self.assertIn("04:30:00 Europe/Berlin", timer)
        self.assertIn("Persistent=false", timer)
        preset = (ROOT / "mkosi.extra/usr/lib/systemd/system-preset/00-particleve.preset").read_text()
        self.assertIn("disable systemd-sysupdate*.timer", preset)
        for path in (ROOT / "mkosi.extra/usr/lib/systemd/system").rglob("*"):
            if path.is_file() and path.suffix in (".service", ".timer", ".conf"):
                text = path.read_text()
                self.assertNotIn("fwupdmgr update", text)
                self.assertNotIn("fwupdmgr install", text)


if __name__ == "__main__":
    unittest.main()
