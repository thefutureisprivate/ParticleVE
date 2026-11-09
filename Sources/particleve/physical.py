"""Bounded read-only physical-interface observations, never device enrollment.

Read published capability attributes only. Do not read descriptor blobs, device
serial/MAC/Thunderbolt UUID attributes, PCI configuration space or device resources.
Kernel node names and topology are retained; this is a local owner report.
Missing optional buses mean unexposed interfaces, not proof of absent hardware.
"""

import itertools
import os
import re
import stat
from pathlib import Path

from .common import Error, require

MAX_NODES = 4096
MAX_ATTRIBUTE = 1024


class Observation:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.remaining = MAX_NODES

    def nodes(self, relative):
        path = self.root / relative
        try:
            nodes = list(itertools.islice(path.iterdir(), self.remaining + 1))
        except FileNotFoundError:
            return {"sysfs_present": False, "devices": []}, []
        require(len(nodes) <= self.remaining, "physical-interface inventory exceeds its node bound")
        self.remaining -= len(nodes)
        require(all(p.name.isprintable() for p in nodes), "invalid physical-interface node name")
        return {"sysfs_present": True, "devices": []}, sorted(nodes)

    @staticmethod
    def attribute(path, *, optional=False):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if optional and path.parent.is_dir():
                return None
            raise
        with os.fdopen(fd, "rb") as stream:
            require(
                stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "physical attribute is not a regular file"
            )
            data = stream.read(MAX_ATTRIBUTE + 1)
        require(len(data) <= MAX_ATTRIBUTE, "physical-interface attribute exceeds its bound")
        try:
            value = data.decode("ascii").rstrip("\n")
        except UnicodeDecodeError as exc:
            raise Error("non-ASCII physical capability attribute") from exc
        require(value and value.isprintable(), "invalid physical capability attribute")
        return value

    def fields(self, path, names):
        return {name: self.attribute(path / name, optional=True) for name in names}

    def flag(self, path, *, optional=False):
        value = self.attribute(path, optional=optional)
        require(value in (None, "0", "1"), "unknown physical-interface boolean state")
        return None if value is None else value == "1"

    def link(self, path, *, under=None):
        try:
            path.lstat()
        except FileNotFoundError:
            require(path.parent.is_dir(), "physical-interface device disappeared")
            return None
        require(path.is_symlink(), "physical-interface reference is not a symbolic link")
        target = path.resolve(strict=True)
        require(target.is_relative_to(under or self.root), "physical-interface reference escapes sysfs")
        require(target.name.isprintable(), "invalid physical-interface reference name")
        return target.name

    def device(self, entry, reader):
        path = entry.resolve(strict=True)
        require(path.is_relative_to(self.root / "devices"), "physical-interface node escapes sysfs devices")
        before = path.stat()
        result = {"node": entry.name} | reader(path)
        after = entry.resolve(strict=True).stat()
        require(
            (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
            "physical-interface device changed during observation",
        )
        return result

    def usb(self):
        report, nodes = self.nodes("bus/usb/devices")
        devices = {}
        interfaces = []
        for entry in nodes:
            if ":" in entry.name:
                interfaces.append(entry)
                continue

            def read(path):
                ids = self.fields(
                    path, ("idVendor", "idProduct", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol")
                )
                require(all(ids.values()), "USB device lacks its capability identifiers")
                require(
                    all(re.fullmatch(r"[0-9a-fA-F]{4}", ids[name]) for name in ("idVendor", "idProduct"))
                    and all(
                        re.fullmatch(r"[0-9a-fA-F]{2}", ids[name])
                        for name in ("bDeviceClass", "bDeviceSubClass", "bDeviceProtocol")
                    ),
                    "invalid USB capability identifier",
                )
                return ids | {
                    "authorized": self.flag(path / "authorized"),
                    "authorized_default": self.attribute(path / "authorized_default", optional=True),
                    "interface_authorized_default": self.flag(
                        path / "interface_authorized_default", optional=True
                    ),
                    "removable": self.attribute(path / "removable", optional=True),
                    "interfaces": [],
                }

            record = self.device(entry, read)
            devices[entry.resolve(strict=True).name] = record
            report["devices"].append(record)
        for entry in interfaces:
            path = entry.resolve(strict=True)
            require(path.parent.name in devices, "USB interface has no observed parent device")

            def read(path):
                fields = self.fields(path, ("bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol"))
                require(
                    all(
                        value is not None and re.fullmatch(r"[0-9a-fA-F]{2}", value)
                        for value in fields.values()
                    ),
                    "invalid USB interface capability",
                )
                return fields | {
                    "driver": self.link(path / "driver"),
                    "authorized": self.flag(path / "authorized", optional=True),
                }

            devices[path.parent.name]["interfaces"].append(self.device(entry, read))
        return report

    def radios(self):
        report, nodes = self.nodes("class/rfkill")
        for entry in nodes:

            def read(path):
                return {
                    "type": self.attribute(path / "type"),
                    "soft_blocked": self.flag(path / "soft"),
                    "hard_blocked": self.flag(path / "hard"),
                }

            report["devices"].append(self.device(entry, read))
        return report

    def thunderbolt(self):
        report, nodes = self.nodes("bus/thunderbolt/devices")
        for entry in nodes:

            def read(path):
                return self.fields(path, ("security", "vendor", "device", "authorized")) | {
                    "iommu_dma_protection": self.flag(path / "iommu_dma_protection", optional=True),
                    "deauthorization": self.flag(path / "deauthorization", optional=True),
                }

            report["devices"].append(self.device(entry, read))
        return report

    def pci(self):
        report, nodes = self.nodes("bus/pci/devices")
        for entry in nodes:

            def read(path):
                ids = self.fields(path, ("class", "vendor", "device"))
                require(
                    ids["class"] is not None
                    and re.fullmatch(r"0x[0-9a-fA-F]{6}", ids["class"])
                    and all(
                        ids[name] is not None and re.fullmatch(r"0x[0-9a-fA-F]{4}", ids[name])
                        for name in ("vendor", "device")
                    ),
                    "invalid PCI capability identifier",
                )
                return ids | {
                    "driver": self.link(path / "driver"),
                    "iommu_group": self.link(path / "iommu_group", under=self.root / "kernel/iommu_groups"),
                    "untrusted": self.flag(path / "untrusted", optional=True),
                    "removable": self.attribute(path / "removable", optional=True),
                }

            report["devices"].append(self.device(entry, read))
        return report

    def network(self):
        report, nodes = self.nodes("class/net")
        for entry in nodes:

            def read(path):
                device = self.link(path / "device", under=self.root / "devices")
                return {
                    "device_node": device,
                    "device_path": str(
                        (path / "device").resolve(strict=True).relative_to(self.root / "devices")
                    )
                    if device is not None
                    else None,
                    "driver": self.link(path / "device/driver") if device is not None else None,
                    "wireless": (path / "wireless").is_dir() or (path / "phy80211").is_symlink(),
                }

            report["devices"].append(self.device(entry, read))
        return report

    def iommu(self):
        report, nodes = self.nodes("kernel/iommu_groups")
        for entry in nodes:
            require(entry.is_dir() and entry.name.isdecimal(), "invalid IOMMU group")
            _, members = self.nodes(f"kernel/iommu_groups/{entry.name}/devices")
            report["devices"].append(
                {
                    "group": entry.name,
                    "type": self.attribute(entry / "type", optional=True),
                    "members": [self.link(member, under=self.root / "devices") for member in members],
                }
            )
        return report


def collect(*, sysfs=Path("/sys")):
    try:
        observer = Observation(sysfs)
        return {
            "schema": 1,
            "usb": observer.usb(),
            "radios": observer.radios(),
            "thunderbolt": observer.thunderbolt(),
            "pci": observer.pci(),
            "network": observer.network(),
            "iommu": observer.iommu(),
        }
    except OSError as exc:
        raise Error("physical-interface observation unavailable or changed: " + str(exc)) from exc
