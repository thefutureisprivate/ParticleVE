import errno
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import config, network, radio
from particleve.common import Error, canonical, digest
from Tests.fixtures import host


class RadioPolicyTests(unittest.TestCase):
    def test_explicit_installation_policy_is_validated_and_rendered_without_host_metadata(self):
        candidate = host()
        policy = candidate["physical"]["radios"]
        self.assertEqual(config.validate(candidate)["physical"]["radios"], {"allowed_types": []})
        for allowed in (None, True, "wlan", ["wlan", "wlan"], ["all"], ["uwb"], [True], ["wlan\n"]):
            with self.subTest(allowed=allowed), self.assertRaises(Error):
                radio.validate({"allowed_types": allowed})
        for bad in (None, {}, {"allowed_types": [], "restore": True}):
            with self.subTest(bad=bad), self.assertRaises(Error):
                radio.validate(bad)
        policy["allowed_types"] = list(radio.TYPES)
        self.assertEqual(
            network.render(config.validate(candidate))["etc/particleve/radio-policy.json"],
            canonical(policy).decode(),
        )
        del candidate["physical"]
        with self.assertRaisesRegex(Error, "physical radio policy"):
            config.validate(candidate)

    def test_kernel_event_protocol_blocks_denied_hotplug_and_drift_without_clearing_allowed_blocks(self):
        service, kernel = socket.socketpair(type=socket.SOCK_SEQPACKET)
        self.addCleanup(service.close)
        self.addCleanup(kernel.close)
        service.setblocking(False)
        kernel.setblocking(False)
        control = radio.Control(service.fileno(), {"allowed_types": ["wlan"]})
        control.initialize()
        for kind in range(2, len(radio.TYPES) + 1):
            self.assertEqual(radio.EVENT.unpack(kernel.recv(8)), (0, kind, 3, 1, 0))
        self.assertEqual(radio.EVENT.unpack(kernel.recv(8)), (0, 1, 3, 0, 0))
        # A persistent denied device may ADD unblocked despite the global
        # default. Its independent hardware block does not replace a soft block.
        kernel.send(radio.EVENT.pack(10, 2, 0, 0, 1))
        kernel.send(radio.EVENT.pack(11, 1, 0, 1, 0))
        self.assertTrue(control.drain())
        self.assertEqual(radio.EVENT.unpack(kernel.recv(8)), (10, 2, 2, 1, 0))
        with self.assertRaises(BlockingIOError):
            kernel.recv(8)
        self.assertEqual(set(control.pending), {10})
        kernel.send(radio.EVENT.pack(10, 2, 2, 1, 1))
        self.assertTrue(control.drain())
        self.assertFalse(control.pending)
        # Driver/button state changes cannot leave a denied device unblocked.
        kernel.send(radio.EVENT.pack(10, 2, 2, 0, 0))
        self.assertTrue(control.drain())
        self.assertEqual(radio.EVENT.unpack(kernel.recv(8)), (10, 2, 2, 1, 0))
        kernel.send(radio.EVENT.pack(10, 2, 1, 0, 0))
        self.assertTrue(control.drain())
        self.assertFalse(control.pending)
        # Removal followed by index reuse has a fresh type and lifetime.
        kernel.send(radio.EVENT.pack(10, 1, 0, 1, 0))
        self.assertTrue(control.drain())
        with self.assertRaises(BlockingIOError):
            kernel.recv(8)

    def test_malformed_events_fail_closed_and_lifecycle_event_loss_is_tolerated(self):
        control = radio.Control(-1, {"allowed_types": []})
        for data in (
            b"short",
            radio.EVENT.pack(0, 0, 0, 1, 0),
            radio.EVENT.pack(0, 9, 0, 1, 0),
            radio.EVENT.pack(0, 1, 3, 1, 0),
            radio.EVENT.pack(0, 1, 0, 2, 0),
            radio.EVENT.pack(0, 1, 0, 1, 2),
        ):
            with self.subTest(data=data), self.assertRaises(Error):
                control.event(data)
        control.event(radio.EVENT.pack(0, 1, 0, 1, 0))
        # The kernel can drop lifecycle events. Repeated ADD, CHANGE without ADD,
        # index reuse and DEL without ADD must not require a duplicate registry.
        for data in (
            radio.EVENT.pack(0, 1, 0, 1, 0),
            radio.EVENT.pack(0, 2, 2, 1, 0),
            radio.EVENT.pack(9, 1, 1, 1, 0),
        ):
            control.event(data)
        with patch.object(radio, "MAX_NODES", 1), patch.object(radio.os, "write", return_value=8):
            control.event(radio.EVENT.pack(1, 1, 0, 0, 0))
            with self.assertRaisesRegex(Error, "too many pending"):
                control.event(radio.EVENT.pack(2, 1, 0, 0, 0))

    def test_independent_reconciliation_recovers_lost_change_acknowledgment_and_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nodes = root / "class/rfkill"
            nodes.mkdir(parents=True)
            for index, kind in ((0, "wlan"), (1, "bluetooth")):
                device = root / "devices" / f"rfkill{index}"
                device.mkdir(parents=True)
                (nodes / device.name).symlink_to(device)
                for name, value in (("type", kind), ("soft", "0"), ("hard", "1")):
                    (device / name).write_text(value + "\n")
            control = radio.Control(3, {"allowed_types": ["wlan"]})
            with patch.object(radio.os, "write", return_value=8) as writes:
                # No RFKill ADD or CHANGE event reached this descriptor.
                control.reconcile(sysfs=root)
                writes.assert_called_once_with(3, radio.EVENT.pack(1, 2, 2, 1, 0))
                self.assertEqual(set(control.pending), {1})
                writes.reset_mock()
                (root / "devices/rfkill1/soft").write_text("1\n")
                control.reconcile(sysfs=root)
                self.assertFalse(control.pending)  # The ACK event was lost too.
                writes.assert_not_called()
                control.pending[1] = 0
                (nodes / "rfkill1").unlink()
                control.reconcile(sysfs=root)
                self.assertFalse(control.pending)  # A lost DEL cannot time out.

    def test_driver_acknowledgment_is_required_and_short_writes_are_errors(self):
        control = radio.Control(-1, {"allowed_types": []})
        with (
            patch.object(radio.os, "write", return_value=8),
            patch.object(radio.time, "monotonic", return_value=20),
        ):
            control.event(radio.EVENT.pack(1, 1, 0, 0, 0))
            control.check_pending()
        with (
            patch.object(radio.time, "monotonic", return_value=25),
            self.assertRaisesRegex(Error, "acknowledge"),
        ):
            control.check_pending()
        with patch.object(radio.os, "write", return_value=7), self.assertRaisesRegex(Error, "incomplete"):
            control.initialize()

    def test_event_flood_cannot_starve_watchdog_or_deadline(self):
        control = radio.Control(-1, {"allowed_types": ["wlan"]})
        with patch.object(
            radio.os, "read", side_effect=[radio.EVENT.pack(i, 1, 0, 0, 0) for i in range(300)]
        ) as reads:
            self.assertFalse(control.drain())
            self.assertEqual(reads.call_count, 256)
        with patch.object(radio.os, "read", return_value=b""), self.assertRaisesRegex(Error, "closed"):
            control.drain()

    def test_input_inhibition_only_accepts_the_explicit_compiled_out_capability(self):
        with patch.object(radio.fcntl, "ioctl") as ioctl:
            radio.inhibit_input(3, Path("/credential/kernel-config"))
            ioctl.assert_called_once_with(3, 0x5201)
        for code, config_text, accepted in (
            (errno.ENOTTY, "# CONFIG_RFKILL_INPUT is not set\n", True),
            (errno.ENOTTY, "CONFIG_RFKILL_INPUT=y\n", False),
            (errno.ENOTTY, "", False),
            (errno.EPERM, "# CONFIG_RFKILL_INPUT is not set\n", False),
        ):
            with (
                self.subTest(code=code, config=config_text),
                patch.object(radio.fcntl, "ioctl", side_effect=OSError(code, "ioctl rejected")),
                patch.object(Path, "read_text", return_value=config_text),
            ):
                if accepted:
                    radio.inhibit_input(3, Path("/credential/kernel-config"))
                else:
                    with self.assertRaises(Error):
                        radio.inhibit_input(3, Path("/credential/kernel-config"))

    def test_inherited_control_requires_zero_capabilities_and_the_named_device(self):
        status = "\n".join(f"{name}:\t0" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        status += "\nNoNewPrivs:\t1\n"
        with (
            patch.object(radio.os, "getuid", return_value=61000),
            patch.object(radio.os, "geteuid", return_value=61000),
            patch.object(Path, "read_text", return_value=status),
            patch.dict(
                os.environ,
                {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": "rfkill-control"},
            ),
            patch.object(
                radio.os,
                "fstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(10, 242)),
            ),
            patch.object(radio.Observation, "attribute", return_value="10:242"),
            patch.object(radio.fcntl, "fcntl", return_value=os.O_RDWR),
            patch.object(radio.os, "set_blocking"),
            patch.object(radio.os, "set_inheritable"),
        ):
            with patch.object(radio.os, "geteuid", return_value=0), self.assertRaises(Error):
                radio.inherited_descriptor()
            with (
                patch.object(Path, "read_text", return_value=status.replace("CapBnd:\t0", "CapBnd:\t1")),
                self.assertRaises(Error),
            ):
                radio.inherited_descriptor()
            with (
                patch.object(radio.Observation, "attribute", return_value="10:241"),
                self.assertRaises(Error),
            ):
                radio.inherited_descriptor()
            with patch.dict(os.environ, {"LISTEN_FDS": "2"}), self.assertRaises(Error):
                radio.inherited_descriptor()
            self.assertEqual(radio.inherited_descriptor(), 3)
            self.assertNotIn("LISTEN_FDS", os.environ)


class RadioBaselineTests(unittest.TestCase):
    def test_effective_policy_detects_released_hard_block_stale_service_and_device_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sysfs = root / "sys"
            node = sysfs / "devices/rfkill0"
            node.mkdir(parents=True)
            nodes = sysfs / "class/rfkill"
            nodes.mkdir(parents=True)
            (nodes / "rfkill0").symlink_to(node)
            for name, value in (("type", "bluetooth"), ("soft", "1"), ("hard", "1")):
                (node / name).write_text(value + "\n")
            parameter = sysfs / "module/rfkill/parameters/default_state"
            parameter.parent.mkdir(parents=True)
            parameter.write_text("0\n")
            (root / "cmdline").write_text("rfkill.default_state=0\n")
            policy = {"allowed_types": []}
            policy_path = root / "policy.json"
            policy_path.write_bytes(canonical(policy))
            device = SimpleNamespace(
                stat=lambda: SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_uid=0, st_gid=0)
            )
            properties = {
                "ActiveState": "active",
                "SubState": "running",
                "StatusText": "RFKill policy " + digest(policy),
            }
            native_mask = "masked"
            diagnostics = ""

            def native(args):
                return SimpleNamespace(
                    stderr=diagnostics,
                    stdout=(
                        "\n".join(k + "=" + v for k, v in properties.items())
                        if args[-1] == radio.UNIT
                        else native_mask
                    ),
                )

            def baseline():
                return radio.baseline(policy, sysfs=sysfs, proc=root, device=device, policy_path=policy_path)

            with patch.object(radio, "run", side_effect=native):
                self.assertTrue(baseline()["devices"][0]["soft_blocked"])
                diagnostics = "warning: incomplete observation"
                with self.assertRaisesRegex(Error, "inspection diagnostics"):
                    baseline()
                diagnostics = ""
                parameter.write_text("1\n")
                with self.assertRaisesRegex(Error, "early default"):
                    baseline()
                parameter.write_text("0\n")
                (node / "soft").write_text("0\n")
                with self.assertRaisesRegex(Error, "software block"):
                    baseline()
                (node / "soft").write_text("1\n")
                properties["StatusText"] += " stale"
                with self.assertRaisesRegex(Error, "different configuration"):
                    baseline()
                properties["StatusText"] = "RFKill policy " + digest(policy)
                native_mask = "loaded"
                with self.assertRaisesRegex(Error, "not masked"):
                    baseline()
                native_mask = "masked"
                device.stat = lambda: SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_uid=0, st_gid=0)
                with self.assertRaisesRegex(Error, "only by root"):
                    baseline()
