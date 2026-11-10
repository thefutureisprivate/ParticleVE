"""Linux backend. Disk targets always come from the encrypted installation manifest."""

import ipaddress
import json
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from . import inventory
from .bootloaders import Loaders, loader_path
from .common import (
    Deferred,
    Error,
    atomic_write,
    digest,
    hash_file,
    read_json,
    require,
    require_active_services,
    run,
    sync_dir,
    write_json,
)
from .consoles import baseline as console_baseline
from .consoles import profile as console_profile
from .layout import TYPES, os_label
from .release import fetch, transfers, verify_directory


def image_version():
    values = dict(
        line.split("=", 1) for line in Path("/usr/lib/os-release").read_text().splitlines() if "=" in line
    )
    require(values.get("IMAGE_ID", "").strip('"') == "ParticleVE", "this is not a ParticleVE OS")
    version = values["IMAGE_VERSION"].strip('"')
    from .config import version_key

    version_key(version)
    return version


class Linux:
    def check_resources(self, *, healthy):
        from .resources import status

        return status(self.config, self.manifest["devices"], healthy=healthy)

    def __init__(self, config, directory, *, allow_unbound=False):
        self.config = config
        self.directory = Path(directory)
        self.manifest = read_json(self.directory / "installation.json")
        require(self.manifest.get("schema") == 1, "unknown installation manifest schema")
        require(
            not (self.directory / "reconfiguration.json").exists(),
            "reconfiguration interrupted; resume the exact reviewed operation",
        )
        require(
            allow_unbound or self.manifest["config_sha256"] == digest(config),
            "host configuration changed; recommission explicitly",
        )
        self.cache = self.directory / "releases"
        self.keyring = "/usr/lib/particleve/trust/releases.gpg"
        self.certificate = "/usr/lib/particleve/trust/secure-boot.crt"

    def current_version(self):
        return image_version()

    def check_time(self, *, anchor=None):
        from .timesync import check_configuration, probe

        try:
            check_configuration(self.config["time"])
            return probe(self.config["time"], anchor=anchor)
        except (Error, OSError, ValueError, KeyError) as exc:
            raise Deferred(f"authenticated time unavailable: {exc}") from exc

    def check_dns(self):
        from .dns import probe

        return probe(self.config["network"])

    def boot_id(self):
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    def check_commissioned(self):
        from .commission import requirements_digest

        if not (self.directory / "commissioned.json").exists():
            raise Deferred("not commissioned; automatic OS work is disabled")
        record = read_json(self.directory / "commissioned.json")
        require(
            record["installation_sha256"] == digest(self.manifest),
            "commissioning evidence does not match this host",
        )
        require(record["config_sha256"] == digest(self.config), "configuration has not been commissioned")
        require(
            record.get("acceptance_requirements_sha256") == requirements_digest(),
            "commissioning acceptance requirements changed or lack approval; review and recommission",
        )
        require(
            record.get("reporting_policy_sha256"),
            "commissioning record lacks external reporting evidence; review and recommission",
        )
        require(
            record["reporting_policy_sha256"] == self.reporting_policy(),
            "external reporting policy changed; review and recommission",
        )
        require(
            record.get("startup_policy_sha256") == self.startup_policy(),
            "persistent startup policy changed or lacks owner approval; review and recommission",
        )

    @staticmethod
    def startup_policy():
        from .startup import inventory

        return inventory()["sha256"]

    @staticmethod
    def reporting_policy():
        from .reporting import policy_binding

        binding = policy_binding()
        require_active_services("particleve-report.timer")
        return binding

    def release(self, version=None):
        if version and (self.cache / version).exists():
            return verify_directory(self.cache / version, self.keyring, self.certificate)
        receipt = self.directory / "release-check.json"
        previous = read_json(receipt) if receipt.exists() else None
        require(
            previous is None or (type(previous) is dict and previous.get("schema") == 1),
            "unknown release-check observation",
        )
        observation = {
            "schema": 1,
            "attempted_at": datetime.now(UTC).isoformat(),
            "last_success_at": previous.get("last_success_at") if previous else None,
            "result": "fail",
            "version": previous.get("version") if previous else None,
        }
        try:
            _, manifest = fetch(
                self.config["feed"], self.cache, self.keyring, self.certificate, version=version
            )
        except Error, OSError, ValueError, KeyError, TypeError:
            write_json(receipt, observation)
            raise
        observation.update(
            result="pass", last_success_at=datetime.now(UTC).isoformat(), version=manifest["version"]
        )
        write_json(receipt, observation)
        return manifest

    def local_release(self, version):
        return verify_directory(self.cache / version, self.keyring, self.certificate, artifacts=False)

    def compatibility_approved(self, first, second):
        if first["persistent_state"] == second["persistent_state"]:
            return
        if first["persistent_state"].get("host_state") != second["persistent_state"].get("host_state"):
            raise Deferred("Host-state contract has no migration; provision a new installation")
        if first["persistent_state"].get("boot_console") != second["persistent_state"].get("boot_console"):
            raise Deferred("Boot-console contract has no migration; provision a new installation")
        path = self.directory / "compatibility.json"
        approvals = read_json(path) if path.exists() else []
        pair = {digest(first), digest(second)}
        for approval in approvals:
            if set(approval["release_sha256"]) == pair and approval.get("retained_os_safe") is True:
                evidence = Path(approval["evidence"])
                require(
                    approval.get("approved_by") and evidence.is_file(),
                    "compatibility approval lacks evidence",
                )
                require(hash_file(evidence) == approval["evidence_sha256"], "compatibility evidence changed")
                return
        raise Deferred("Persistent-state change needs explicit, tested retained-OS compatibility approval")

    def check_compatibility(self, current, release):
        self.compatibility_approved(self.local_release(current), release)

    def check_runtime_state(self):
        current = self.local_release(self.current_version())
        ledger = self.directory / "runtime-last-started.json"
        if ledger.exists():
            previous = self.local_release(read_json(ledger)["image_version"])
            self.compatibility_approved(previous, current)
        write_json(
            ledger, {"image_version": current["version"], "persistent_state": current["persistent_state"]}
        )

    def disk(self, role):
        return next(d for d in self.manifest["devices"] if d["role"] == role)

    def current_esp_role(self):
        variable = Path("/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")
        selected = str(uuid.UUID(variable.read_bytes()[4:].decode("utf-16-le").rstrip("\0")))
        matches = [
            d["role"]
            for d in self.manifest["devices"]
            if any(p["role"] == "esp" and p["uuid"] == selected for p in d["partitions"])
        ]
        require(len(matches) == 1, "booted ESP is outside the selected disk pair")
        return matches[0]

    def bless_current(self):
        current = self.current_version()
        role = self.current_esp_role()
        release = self.local_release(current)
        with self.esp(role) as esp:
            entries = self.boot_entries(esp, current)
            require(
                len(entries) == 1 and hash_file(entries[0][0]) == release["artifacts"]["uki"]["sha256"],
                "booted ESP does not hold the authenticated running UKI",
            )
            # Native "good" rejects an entry already booted without a counter.
            _, match = entries[0]
            if match[1] is not None:
                run(["/usr/lib/systemd/systemd-bless-boot", f"--path={esp}", "good"])
        return {"boot_blessed": current, "esp_role": role, **Loaders(self).bless()}

    def check_usr_boot_disk(self):
        from .security import usr_backing_disks, verified_usr_mount

        verified_usr_mount()
        boot_disk = Path(self.disk(self.current_esp_role())["path"]).resolve(strict=True).name
        mapper = Path("/dev/mapper/usr").resolve(strict=True).name
        require(usr_backing_disks(mapper) == {boot_disk}, "verified usr is not on the selected EFI boot disk")
        native = run(["udevadm", "info", "--query=property", "--path=/sys/class/block/" + boot_disk])
        require(not native.stderr.strip(), "boot disk inspection diagnostics: " + native.stderr.strip())
        require(
            "PARTICLEVE_BOOT_DISK=1" in native.stdout.splitlines(),
            "EFI boot-disk selection did not survive the initrd transition",
        )

    @contextmanager
    def esp(self, role):
        device = self.disk(role)
        esp = next(p for p in device["partitions"] if p["role"] == "esp")
        source = Path("/dev/disk/by-partuuid") / esp["uuid"]
        require(source.exists(), f"ESP {role} is missing")
        with tempfile.TemporaryDirectory(prefix=f"particleve-esp-{role}-", dir="/run") as temporary:
            run(
                [
                    "mount",
                    "-t",
                    "vfat",
                    "-o",
                    "rw,nosuid,nodev,noexec,noatime,umask=0077,context=system_u:object_r:boot_t:s0",
                    source,
                    temporary,
                ]
            )
            try:
                yield Path(temporary)
            finally:
                run(["umount", temporary])

    def check_firmware_clear(self):
        if list(Path("/sys/firmware/efi/efivars").glob("BootNext-*")) or Path("/system-update").exists():
            raise Deferred("UEFI BootNext or an offline update is staged")
        result = run(["fwupdmgr", "get-history", "--json"], check=False)
        require(result.returncode in (0, 2), "fwupd history unavailable; cannot exclude staged firmware")
        history = json.loads(result.stdout) if result.stdout.strip() else {}

        def pending(value):
            if isinstance(value, dict):
                if "UpdateState" in value:
                    state = value["UpdateState"]
                    # Native fwupd 2.x JSON uses its numeric UpdateState enum.
                    require(type(state) is int and state in range(6), "unknown fwupd update state")
                    if state in (1, 4):  # Pending or NeedsReboot.
                        return True
                return any(pending(v) for v in value.values())
            return isinstance(value, list) and any(pending(v) for v in value)

        if pending(history):
            raise Deferred("fwupd reports staged firmware")
        for role in ("a", "b"):
            with self.esp(role) as esp:
                if any(esp.glob("EFI/UpdateCapsule/*")) or any(esp.glob("EFI/**/fwupd*.cap")):
                    raise Deferred(f"ESP {role} contains staged firmware")

    def check_storage(self, *, healthy):
        from .storage import status

        if healthy:
            for disk in self.manifest["devices"]:
                actual = inventory.observe_disk(disk)
                require(
                    actual["serial"] == disk["observed"]["serial"]
                    and actual["size"] == disk["observed"]["size"],
                    "selected physical disk identity changed",
                )
        return status(self.manifest, self.config, healthy=healthy)

    def matching_partition(self, role, release, kind):
        label = os_label(release["version"])
        item = release["artifacts"][kind]
        nodes = inventory.walk(inventory.block_tree(self.disk(role)["path"]))
        matches = [
            node
            for node in nodes
            if node.get("type") == "part"
            and node.get("partlabel") == label
            and node.get("parttype") == TYPES[kind]
            and node.get("partuuid") == item["partition_uuid"]
        ]
        if len(matches) != 1:
            return None
        part = matches[0]
        if part["size"] < item["size"]:
            return None
        return part["name"]

    @staticmethod
    def boot_entries(esp, version):
        pattern = re.compile(rf"ParticleVE_{re.escape(version)}_x86-64(?:\+(\d+)(?:-\d+)?)?\.efi\Z")
        return [
            (p, pattern.fullmatch(p.name))
            for p in (esp / "EFI/Linux").glob("*.efi")
            if pattern.fullmatch(p.name)
        ]

    def verify_disk(self, role, release, *, boot):
        for kind in ("usr", "verity", "verity_sig"):
            path = self.matching_partition(role, release, kind)
            if (
                not path
                or hash_file(path, release["artifacts"][kind]["size"]) != release["artifacts"][kind]["sha256"]
            ):
                return False
        if boot:
            with self.esp(role) as esp:
                entries = self.boot_entries(esp, release["version"])
                if len(entries) != 1:
                    return False
                path, match = entries[0]
                if match[1] is not None and int(match[1]) == 0:
                    return False
                if hash_file(path) != release["artifacts"]["uki"]["sha256"]:
                    return False
                path = esp / loader_path(release["artifacts"]["bootloader"]["sha256"])
                if not path.is_file() or hash_file(path) != release["artifacts"]["bootloader"]["sha256"]:
                    return False
                Loaders(self).prove(esp)
        return True

    def transfer(self, role, release, current):
        # The coordinator has authenticated the immutable local source, including all raw hashes.
        source = self.cache / release["version"]
        with tempfile.TemporaryDirectory(prefix="particleve-transfer-", dir="/run") as temporary:
            for name, content in transfers(
                release, disk=self.disk(role)["path"], source=source, current=current
            ).items():
                atomic_write(Path(temporary) / name, content.encode())
            # Native sysupdate refuses a previously acquired partial set until
            # it is vacuumed. The same explicit-disk definitions protect the
            # authenticated running version while discarding pending fragments.
            run(["/usr/lib/systemd/systemd-sysupdate", f"--definitions={temporary}", "vacuum"])
            run(
                [
                    "/usr/lib/systemd/systemd-sysupdate",
                    f"--definitions={temporary}",
                    "update",
                    release["version"],
                ],
                timeout=3600,
            )
            # sysupdate queues GPT-change events. lsblk reads partition identity
            # from udev, which may still contain the temporary acquisition type.
            run(["udevadm", "settle", "--timeout=120"], timeout=130)

    def expose_boot(self, role, release):
        with self.esp(role) as esp:
            entries = self.boot_entries(esp, release["version"])
            require(len(entries) <= 1, "ambiguous boot entries")
            if entries:
                path, match = entries[0]
                require(
                    match[1] is None or int(match[1]) > 0, "boot attempts exhausted; release requires review"
                )
                require(hash_file(path) == release["artifacts"]["uki"]["sha256"], "existing UKI mismatch")
            else:
                item = release["artifacts"]["uki"]
                source = self.cache / release["version"] / item["file"]
                # A hidden temporary filename cannot be discovered as a Type 2 boot entry.
                atomic_write(
                    esp / f"EFI/Linux/ParticleVE_{release['version']}_x86-64+3.efi", source.read_bytes()
                )
            item = release["artifacts"]["bootloader"]
            source = self.cache / release["version"] / item["file"]
            atomic_write(esp / loader_path(item["sha256"]), source.read_bytes())

    def default(self, esp, version=None):
        path = esp / "loader/loader.conf"
        old = (
            path.read_text().splitlines() if path.exists() else ["timeout 5", "editor no", "auto-entries no"]
        )
        lines = [line for line in old if not re.match(r"\s*default\s", line)]
        selected = version if version is not None else "*"
        profile = console_profile(self.config)
        suffix = "@" + profile if profile else ""
        lines.append(f"default ParticleVE_{selected}_x86-64*.efi{suffix}")
        atomic_write(path, ("\n".join(lines) + "\n").encode())

    def pin_current(self, current):
        for role in ("a", "b"):
            with self.esp(role) as esp:
                require(self.boot_entries(esp, current), f"disk {role} has no current fallback entry")
                self.default(esp, current)

    def protect_current(self, current, candidate):
        self.pin_current(current)
        for role in ("a", "b"):
            with self.esp(role) as esp:
                for path in (esp / "EFI/Linux").glob("ParticleVE_*.efi"):
                    if not any(
                        self.boot_entries(esp, v) and path in [p for p, _ in self.boot_entries(esp, v)]
                        for v in (current, candidate)
                        if v is not None
                    ):
                        # Displaced old OS entries must disappear before their slots are reclaimed.
                        path.unlink()
                sync_dir(esp / "EFI/Linux")

    def prove_fallback(self, current):
        require_active_services("boot-complete.target", "systemd-bless-boot.service")
        release = self.local_release(current)
        for role in ("a", "b"):
            for kind in ("usr", "verity", "verity_sig"):
                path = self.matching_partition(role, release, kind)
                require(
                    path
                    and hash_file(path, release["artifacts"][kind]["size"])
                    == release["artifacts"][kind]["sha256"],
                    f"disk {role} no longer has a coherent fallback",
                )
            with self.esp(role) as esp:
                Loaders(self).prove(esp)
                entries = self.boot_entries(esp, current)
                require(
                    len(entries) == 1
                    and (entries[0][1][1] is None or int(entries[0][1][1]) > 0)
                    and hash_file(entries[0][0]) == release["artifacts"]["uki"]["sha256"],
                    f"disk {role} fallback UKI is unavailable",
                )

    def select(self, version):
        for role in ("a", "b"):
            with self.esp(role) as esp:
                entries = self.boot_entries(esp, version)
                require(
                    len(entries) == 1 and (entries[0][1][1] is None or int(entries[0][1][1]) > 0),
                    f"disk {role} has no eligible candidate boot entry",
                )
                # An exact default forces even an exhausted entry. Both complete
                # releases are visible now: native ordering chooses the newer
                # eligible release and falls back when its counter reaches zero.
                self.default(esp)

    def conditional_reboot(self, version):
        # Use the booted ESP's disk for upstream's installed-version comparison.
        # The two-disk guard has already checked every resource on both paths.
        disk = self.disk(self.current_esp_role())
        release = self.local_release(version)
        with tempfile.TemporaryDirectory(prefix="particleve-reboot-", dir="/run") as temporary:
            for name, content in transfers(
                release,
                disk=disk["path"],
                source=self.cache / version,
                current=self.current_version(),
            ).items():
                atomic_write(Path(temporary) / name, content.encode())
            if run(
                ["/usr/lib/systemd/systemd-sysupdate", f"--definitions={temporary}", "pending"], check=False
            ).returncode:
                return False
            loaders = Loaders(self)
            try:
                loaders.queue(release)
                run(["/usr/lib/systemd/systemd-sysupdate", f"--definitions={temporary}", "reboot"])
                jobs = run(["systemctl", "list-jobs", "--no-legend", "--no-pager"], timeout=10).stdout
                state = run(["systemctl", "is-system-running"], check=False, timeout=10).stdout.strip()
                queued = "reboot.target" in jobs or state == "stopping"
                if not queued:
                    loaders.cancel()
                return queued
            except Error, OSError:
                loaders.cancel()
                raise

    def reject(self, version, current):
        Loaders(self).cancel()
        for role in ("a", "b"):
            try:
                with self.esp(role) as esp:
                    self.default(esp, current)
                    for path, _ in self.boot_entries(esp, version):
                        path.rename(path.with_suffix(".rejected"))
            except Error:
                # Quarantine is already durable; require every returned disk to reconcile before activation.
                # A failed ESP write must not prevent the compatible surviving OS from starting VMs.
                continue

    def health(self):
        self.check_storage(healthy=False)
        console_baseline(self.config)
        from .accounts import check

        check()
        require(inventory.kvm_available(), "KVM is unavailable")
        require(inventory.secure_boot(), "Secure Boot is not enabled")
        inventory.measured_boot(normal=True)
        from .security import live_baseline, selinux_access, selinux_baseline, ssh_baseline
        from .startup import check as check_startup

        live_baseline(evidence=False)
        ssh_baseline()
        selinux_baseline()
        selinux_access()
        self.check_usr_boot_disk()
        check_startup()
        require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "SELinux is not enforcing")
        require_active_services(
            "systemd-networkd.service",
            "systemd-resolved.service",
            "chronyd-restricted.service",
            "particleve-firewall.service",
            "sshd.socket",
            "systemd-homed.service",
            "auditd.service",
            "particleve-storage-watch.timer",
        )
        from .timesync import check_configuration

        # Daemon/configuration health is independent of synchronization: loss
        # of NTS defers activation and reports attention, without stopping VMs.
        check_configuration(self.config["time"])
        from .radio import baseline as radio_baseline

        radio_baseline(self.config["physical"]["radios"])
        self.check_dns()
        network = json.loads(
            run(["ip", "--json", "address", "show", "dev", self.config["network"]["management"]]).stdout
        )
        actual = {ipaddress.ip_address(a["local"]) for d in network for a in d.get("addr_info", [])}
        require(
            {ipaddress.ip_interface(a).ip for a in self.config["network"]["addresses"]} <= actual,
            "management addresses missing",
        )
        run(["systemctl", "is-active", "systemd-machined.service"])
        run(["systemd-vmspawn", "--version"])
        require(Path("/usr/lib/systemd/system/systemd-vmspawn@.service").exists(), "vmspawn template missing")
        require(Path("/sys/module/zswap/parameters/enabled").read_text().strip() == "Y", "zswap is disabled")
        swaps = Path("/proc/swaps").read_text().splitlines()[1:]
        require(
            swaps and all("zram" not in line for line in swaps),
            "encrypted block swap is missing or zram is active",
        )
        require(
            all(
                Path(line.split()[0]).resolve() == Path("/dev/mapper/particleve-swap").resolve()
                for line in swaps
            ),
            "unexpected swap outside the encrypted swap mirror",
        )
        source = run(["findmnt", "--noheadings", "--output=SOURCE", "--target", "/usr"]).stdout.strip()
        table = run(["dmsetup", "table", source]).stdout
        require(" verity " in table, "/usr is not protected by dm-verity")

    def accept(self, version):
        # systemd-bless-boot.service runs after boot-complete.target; do not reset remote counters here.
        # Only already healthy, verified images can reach boot-complete.target.
        require(version == self.current_version(), "cannot accept a release that is not running")

    def cleanup_cache(self):
        # Missing disks make the reference set uncertain; retain everything until both return.
        if any(not Path(d["path"]).exists() for d in self.manifest["devices"]):
            return
        retained = {self.current_version()}
        for disk in self.manifest["devices"]:
            for part in inventory.walk(inventory.block_tree(disk["path"])):
                match = re.fullmatch(r"PVE_([0-9.-]+)", part.get("partlabel") or "")
                if match:
                    retained.add(match[1])
        state_path = self.directory / "state.json"
        if state_path.exists() and (pending := read_json(state_path)["pending"]):
            retained.add(pending["version"])
        for directory in self.cache.iterdir():
            if directory.is_dir() and directory.name not in retained and not directory.name.startswith("."):
                manifest = self.local_release(directory.name)
                for item in manifest["artifacts"].values():
                    (directory / item["file"]).unlink(missing_ok=True)
                # Keep authenticated metadata for daemon-state/compatibility history.

    def vm_shutdown(self):
        from .vms import LinuxVMs, Shutdown

        settings = self.config["maintenance"]
        return Shutdown(
            self.directory,
            LinuxVMs(),
            self.boot_id(),
            graceful_seconds=settings["graceful_seconds"],
            restore_seconds=settings["restore_seconds"],
        )

    def freeze_vms(self):
        self.vm_shutdown().freeze()

    def stop_vms(self):
        self.vm_shutdown().stop()

    def assert_no_vms(self):
        self.vm_shutdown().assert_empty()

    def restore_vms(self):
        return self.vm_shutdown().recover()

    def recover_vms(self):
        return self.vm_shutdown().recover()

    def mark_vm_reboot(self):
        self.vm_shutdown().mark_reboot()
