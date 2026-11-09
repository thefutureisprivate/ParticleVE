"""Signed-kernel USB loopback fixture, confined to an explicitly pinned VM.

No USB passthrough is used. Configfs gadgets attach only to dummy_hcd's virtual
controllers. The helper is acceptance tooling and is never in the runtime RPM.
"""

import errno
import time
from pathlib import Path

from particleve.common import read_json, require, run

KEYBOARD_REPORT = bytes.fromhex(
    "05010906a101050719e029e715002501750195088102950175088103"
    "95057501050819012905910295017503910395067508150025730507190029738100c0"
)
MODULES = {
    "dummy_hcd",
    "libcomposite",
    "usb_f_acm",
    "usb_f_hid",
    "u_serial",
    "udc_core",
    "usbcore",
    "usb_common",
    "usbhid",
    "hid_generic",
    "hid",
    "cdc_acm",
}


def wait_for(operation, label):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError("USB fixture timeout: " + label)


class Gadget:
    def __init__(self, name, udc, product, serial, functions):
        self.path = Path("/sys/kernel/config/usb_gadget") / name
        self.udc, self.serial = udc, serial
        require(not self.path.exists(), "test gadget already exists")
        self.path.mkdir()
        try:
            for attribute, value in (
                ("idVendor", "0x1209"),
                ("idProduct", f"0x{product:04x}"),
                ("bcdUSB", "0x0200"),
                ("bcdDevice", "0x0100"),
                ("bDeviceClass", "0"),
            ):
                (self.path / attribute).write_text(value + "\n")
            strings = self.path / "strings/0x409"
            strings.mkdir()
            for attribute, value in (
                ("serialnumber", serial),
                ("manufacturer", "ParticleVE disposable test"),
                ("product", name),
            ):
                (strings / attribute).write_text(value + "\n")
            config = self.path / "configs/c.1"
            config.mkdir()
            for function in functions:
                item = self.path / "functions" / (function + ".test")
                item.mkdir()
                if function == "hid":
                    for attribute, value in (("protocol", "1"), ("subclass", "1"), ("report_length", "8")):
                        (item / attribute).write_text(value + "\n")
                    (item / "report_desc").write_bytes(KEYBOARD_REPORT)
                (config / item.name).symlink_to(item)
        except Exception:
            self.close()
            raise

    def connect(self):
        (self.path / "UDC").write_text(self.udc + "\n")
        return wait_for(self.host_device, "gadget enumeration")

    def host_device(self):
        for device in Path("/sys/bus/usb/devices").iterdir():
            if ":" in device.name or device.name.startswith("usb"):
                continue
            try:
                target = device.resolve(strict=True)
                if (device / "serial").read_text().strip() == self.serial:
                    require("dummy_hcd." in str(target), "gadget escaped virtual USB controller")
                    return device
            except OSError as exc:
                # A removed synthetic device can disappear before open (ENOENT)
                # or after open but before its sysfs show callback (ENODEV).
                if exc.errno not in (errno.ENOENT, errno.ENODEV):
                    raise
        return None

    def close(self):
        if not self.path.exists():
            return
        if (self.path / "UDC").read_text().strip():
            (self.path / "UDC").write_text("\n")
            wait_for(lambda: self.host_device() is None, "gadget removal")
        for config in (self.path / "configs").iterdir():
            for child in config.iterdir():
                if child.is_symlink():
                    child.unlink()
            for language in (config / "strings").iterdir():
                language.rmdir()
            config.rmdir()
        for function in (self.path / "functions").iterdir():
            function.rmdir()
        for language in (self.path / "strings").iterdir():
            language.rmdir()
        self.path.rmdir()


class VirtualUSB:
    def __init__(self, installation):
        require(
            read_json("/var/lib/particleve/installation.json")["installation_uuid"] == installation,
            "unexpected disposable installation",
        )
        require(
            run(["systemd-detect-virt", "--vm"]).stdout.strip() in ("qemu", "kvm"), "use the QEMU fixture"
        )
        require(not list(Path("/sys/bus/usb/devices").iterdir()), "do not test with existing USB devices")
        require(not Path("/sys/module/dummy_hcd").exists(), "virtual controller already exists")
        self.modules_before = {p.name for p in Path("/sys/module").iterdir()}
        self.gadgets = []

    def __enter__(self):
        try:
            run(["modprobe", "dummy_hcd", "num=2"])
            run(["modprobe", "libcomposite"])
            require(not list(Path("/sys/kernel/config/usb_gadget").iterdir()), "foreign gadget configuration")
            self.udcs = sorted(p.name for p in Path("/sys/class/udc").iterdir())
            require(
                len(self.udcs) == 2 and all(n.startswith("dummy_udc.") for n in self.udcs), "unexpected UDCs"
            )
            return self
        except Exception:
            self.close()
            raise

    def create(self, name, controller, product, serial, functions):
        gadget = Gadget(name, self.udcs[controller], product, serial, functions)
        self.gadgets.append(gadget)
        return gadget

    def close(self):
        for gadget in reversed(self.gadgets):
            gadget.close()
        run(["udevadm", "settle"])
        pending = {name for name in MODULES - self.modules_before if Path("/sys/module", name).exists()}
        while pending:
            removable = sorted(
                name for name in pending if not list(Path("/sys/module", name, "holders").iterdir())
            )
            require(removable, "virtual USB module dependency did not settle")
            for name in removable:
                run(["rmmod", name])
                pending.remove(name)
        require(not list(Path("/sys/bus/usb/devices").iterdir()), "virtual USB devices remain")

    def __exit__(self, *_exc):
        self.close()
