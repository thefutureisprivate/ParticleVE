import json
import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests


class PhysicalTests(RustDriverTests):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "devices").mkdir()

    def node(self, bus, name, parent=None, **fields):
        directory = (parent or self.root / "devices") / name
        directory.mkdir(parents=True)
        for field, value in fields.items():
            (directory / field).write_text(value + "\n")
        link = self.root / bus / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(directory)
        return directory

    def usb(self):
        return self.node(
            "bus/usb/devices",
            "usb1",
            idVendor="1d6b",
            idProduct="0003",
            bDeviceClass="09",
            bDeviceSubClass="00",
            bDeviceProtocol="03",
            authorized="1",
            authorized_default="1",
            interface_authorized_default="1",
            removable="fixed",
        )

    def test_unexposed_buses_and_present_empty_buses_are_distinct(self):
        report = self.evaluate("physical-collect", sysfs=str(self.root))
        self.assertFalse(report["usb"]["sysfs_present"])
        (self.root / "bus/usb/devices").mkdir(parents=True)
        report = self.evaluate("physical-collect", sysfs=str(self.root))
        self.assertTrue(report["usb"]["sysfs_present"])
        self.assertEqual(report["usb"]["devices"], [])
        self.assertFalse(report["thunderbolt"]["sysfs_present"])

    def test_usb_root_interface_and_composite_capabilities_do_not_enroll_or_read_serials(self):
        hub = self.usb()
        self.node(
            "bus/usb/devices",
            "1-0:1.0",
            parent=hub,
            bInterfaceClass="09",
            bInterfaceSubClass="00",
            bInterfaceProtocol="00",
        )
        child = self.node(
            "bus/usb/devices",
            "1-2",
            parent=hub,
            idVendor="abcd",
            idProduct="0123",
            bDeviceClass="00",
            bDeviceSubClass="00",
            bDeviceProtocol="00",
            authorized="0",
            serial="PRIVATE-SERIAL-DO-NOT-READ",
            product="UNTRUSTED-NAME",
        )
        self.node(
            "bus/usb/devices",
            "1-2:1.0",
            parent=child,
            bInterfaceClass="03",
            bInterfaceSubClass="01",
            bInterfaceProtocol="01",
            authorized="0",
        )
        self.node(
            "bus/usb/devices",
            "1-2:1.1",
            parent=child,
            bInterfaceClass="08",
            bInterfaceSubClass="06",
            bInterfaceProtocol="50",
            authorized="0",
        )
        before = {p: p.read_bytes() for p in (self.root / "devices").rglob("*") if p.is_file()}
        report = self.evaluate("physical-collect", sysfs=str(self.root))
        rows = {row["node"]: row for row in report["usb"]["devices"]}
        self.assertEqual(len(rows["usb1"]["interfaces"]), 1)
        self.assertFalse(rows["1-2"]["authorized"])
        self.assertEqual([row["bInterfaceClass"] for row in rows["1-2"]["interfaces"]], ["03", "08"])
        self.assertNotIn("PRIVATE-SERIAL", json.dumps(report))
        self.assertNotIn("UNTRUSTED-NAME", json.dumps(report))
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_radio_blocking_is_an_observation_not_an_assumed_hardware_protection(self):
        self.node("class/rfkill", "rfkill0", type="wlan", soft="0", hard="1")
        row = self.evaluate("physical-collect", sysfs=str(self.root))["radios"]["devices"][0]
        self.assertFalse(row["soft_blocked"])
        self.assertTrue(row["hard_blocked"])
        (self.root / "devices/rfkill0/hard").write_text("unknown\n")
        self.assertIn("boolean", self.request("physical-collect", sysfs=str(self.root))["error"])

    def test_thunderbolt_dma_status_is_separate_from_authorization_and_security_level(self):
        domain = self.node(
            "bus/thunderbolt/devices",
            "domain0",
            security="none",
            iommu_dma_protection="1",
            deauthorization="1",
        )
        self.node(
            "bus/thunderbolt/devices",
            "0-1",
            parent=domain,
            vendor="0x1234",
            device="0x5678",
            authorized="0",
            unique_id="PRIVATE-THUNDERBOLT-UUID",
        )
        rows = self.evaluate("physical-collect", sysfs=str(self.root))["thunderbolt"]["devices"]
        values = {row["node"]: row for row in rows}
        self.assertEqual(values["domain0"]["security"], "none")
        self.assertTrue(values["domain0"]["iommu_dma_protection"])
        self.assertEqual(values["0-1"]["authorized"], "0")
        self.assertNotIn("PRIVATE-THUNDERBOLT", json.dumps(rows))

    def test_pci_network_and_iommu_group_membership_are_linked_without_identity_strings(self):
        device = self.node(
            "bus/pci/devices",
            "0000:01:00.0",
            **{"class": "0x020000", "vendor": "0x1234", "device": "0x5678", "untrusted": "1"},
        )
        group = self.root / "kernel/iommu_groups/7"
        (group / "devices").mkdir(parents=True)
        (group / "type").write_text("DMA\n")
        (group / "devices/0000:01:00.0").symlink_to(device)
        (device / "iommu_group").symlink_to(group)
        driver = self.root / "bus/pci/drivers/test-net"
        driver.mkdir(parents=True)
        (device / "driver").symlink_to(driver)
        net = self.node("class/net", "eth0", address="PRIVATE-MAC-DO-NOT-READ")
        (net / "device").symlink_to(device)
        self.node("class/net", "lo")
        report = self.evaluate("physical-collect", sysfs=str(self.root))
        self.assertEqual(report["pci"]["devices"][0]["iommu_group"], "7")
        self.assertEqual(
            report["iommu"]["devices"][0], {"group": "7", "type": "DMA", "members": ["0000:01:00.0"]}
        )
        values = {row["node"]: row for row in report["network"]["devices"]}
        self.assertEqual(values["eth0"]["driver"], "test-net")
        self.assertEqual(values["eth0"]["device_node"], "0000:01:00.0")
        self.assertIsNone(values["lo"]["device_node"])
        self.assertNotIn("PRIVATE-MAC", json.dumps(report))

    def test_oversized_and_malformed_fields_fail_before_any_enrollment(self):
        hub = self.usb()
        for value in ("x" * (1025), "1d6b\x1b[31m", "1d6b\u2603", "zzzz"):
            (hub / "idVendor").write_text(value)
            with self.subTest(value=value):
                self.assertIn("error", self.request("physical-collect", sysfs=str(self.root)))
        (hub / "idVendor").write_text("1d6b\n")

    def test_sysfs_escapes_and_attribute_symlinks_fail_closed(self):
        hub = self.usb()
        vendor = hub / "idVendor"
        vendor.unlink()
        vendor.symlink_to(hub / "idProduct")
        self.assertIn("error", self.request("physical-collect", sysfs=str(self.root)))
        vendor.unlink()
        vendor.write_text("1d6b\n")
        link = self.root / "bus/usb/devices/usb1"
        link.unlink()
        link.symlink_to(self.root)
        self.assertIn("escapes", self.request("physical-collect", sysfs=str(self.root))["error"])

    def test_device_disappearance_is_not_reported_as_an_empty_inventory(self):
        self.usb()
        link = self.root / "bus/usb/devices/usb1"
        link.unlink()
        link.symlink_to(self.root / "devices/disappeared")
        self.assertIn("error", self.request("physical-collect", sysfs=str(self.root)))
