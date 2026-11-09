"""Crash-resumable two-disk transactions; the backend performs platform operations."""

from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .common import Deferred, Error, digest, lock, read_json, require, write_json
from .config import version_key


def reboot_window(now, tolerance=60):
    local = now.astimezone(ZoneInfo("Europe/Berlin"))
    return local.hour == 4 and local.minute == 30 and local.second < tolerance


class Coordinator:
    def __init__(self, directory, backend):
        self.directory = Path(directory)
        self.backend = backend
        self.path = self.directory / "state.json"

    def load(self):
        if not self.path.exists():
            return {
                "schema": 1,
                "maintenance": None,
                "pending": None,
                "accepted": [],
                "rejected": {},
                "last_reason": "not commissioned",
            }
        state = read_json(self.path)
        require(state.get("schema") == 1, "unsupported transaction schema; recovery requires review")
        return state

    def save(self, state):
        state["updated_at"] = datetime.now(UTC).isoformat()
        write_json(self.path, state)

    def reason(self, state, message):
        state["last_reason"] = message
        self.save(state)
        return {"action": "deferred", "reason": message}

    def guard(self, state, *, automatic):
        if state["maintenance"]:
            raise Deferred("persistent manual maintenance: " + state["maintenance"]["reason"])
        if automatic:
            self.backend.check_commissioned()
        self.backend.check_firmware_clear()
        self.backend.check_storage(healthy=True)
        self.backend.check_resources(healthy=True)

    def reconcile(self, state):
        pending = state["pending"]
        if not pending:
            return
        current = self.backend.current_version()
        if pending["version"] == current:
            # Unscheduled restart after readiness is assessed exactly like a scheduled boot.
            require(
                pending["phase"] in ("ready", "booting"),
                "booted an incomplete transaction; manual recovery required",
            )
            return
        if pending["phase"] == "booting" and pending["boot_id"] != self.backend.boot_id():
            # We have returned to another release. Never reset exhausted counters.
            state["rejected"][pending["version"]] = "fallback after activation"
            self.save(state)  # quarantine is durable before ESP reconciliation
            self.backend.reject(pending["version"], current)
            state["pending"] = None
            self.save(state)

    def prepare(self, *, automatic=True):
        with lock(self.directory):
            state = self.load()
            try:
                self.reconcile(state)
                self.guard(state, automatic=automatic)
                current = self.backend.current_version()
                pending = state["pending"]
                if pending and pending["phase"] == "booting":
                    raise Deferred("activation already requested; await boot assessment")
                # A partial transaction keeps its explicit version even if the feed advances.
                release = self.backend.release(pending["version"] if pending else None)
                version = release["version"]
                if version in state["rejected"]:
                    raise Deferred(f"release {version} is quarantined")
                if version_key(version) <= version_key(current):
                    raise Deferred("no newer OS release")
                self.backend.check_compatibility(current, release)
                self.backend.prove_fallback(current)
                if pending:
                    require(pending["sha256"] == digest(release), "transaction release content changed")
                else:
                    pending = {
                        "version": version,
                        "sha256": digest(release),
                        "phase": "preparing",
                        "disks": {},
                    }
                    state["pending"] = pending
                    self.save(state)
                # Before reclaiming the second slot, hide entries for the displaced old release.
                # Keep both current entries as the defaults throughout preparation.
                self.backend.protect_current(current, version)
                for disk in ("a", "b"):
                    # Completion flags are hints; actual disk state is always rechecked.
                    if not self.backend.verify_disk(disk, release, boot=False):
                        pending["disks"].pop(disk, None)
                        pending["phase"] = "preparing"
                        self.save(state)
                        self.backend.transfer(disk, release, current)
                    require(
                        self.backend.verify_disk(disk, release, boot=False),
                        f"disk {disk} OS verification failed",
                    )
                    pending["disks"][disk] = "os-verified"
                    self.save(state)
                # Both complete OS sets exist before either new UKI becomes visible.
                for disk in ("a", "b"):
                    self.backend.expose_boot(disk, release)
                    require(
                        self.backend.verify_disk(disk, release, boot=True),
                        f"disk {disk} boot verification failed",
                    )
                    pending["disks"][disk] = "complete"
                    self.save(state)
                self.guard(state, automatic=automatic)
                pending["phase"] = "ready"
                state["last_reason"] = f"release {version} ready on both disks"
                self.save(state)
                return {"action": "ready", "version": version}
            except Deferred as exc:
                return self.reason(state, str(exc))
            except Error as exc:
                self.reason(state, f"preparation failed: {exc}")
                raise

    def reboot(self, *, now=None, automatic=True):
        with lock(self.directory):
            state = self.load()
            vm_attempt = False
            try:
                self.reconcile(state)
                if automatic and not reboot_window(
                    now or datetime.now(UTC), self.backend.config["maintenance"]["start_tolerance_seconds"]
                ):
                    raise Deferred("outside the 04:30 Europe/Berlin window")
                self.guard(state, automatic=automatic)
                pending = state["pending"]
                if not pending or pending["phase"] != "ready":
                    raise Deferred("no complete pending release")
                version = pending["version"]
                if version in state["rejected"] or version_key(version) <= version_key(
                    self.backend.current_version()
                ):
                    raise Deferred("pending release is rejected or already running")
                release = self.backend.release(version)
                require(digest(release) == pending["sha256"], "pending release identity changed")
                self.backend.check_compatibility(self.backend.current_version(), release)
                for disk in ("a", "b"):
                    require(
                        self.backend.verify_disk(disk, release, boot=True), f"disk {disk} readiness was lost"
                    )
                self.backend.prove_fallback(self.backend.current_version())
                clock = self.backend.check_time()
                if automatic and not reboot_window(
                    datetime.fromtimestamp(clock["wall"], UTC),
                    self.backend.config["maintenance"]["start_tolerance_seconds"],
                ):
                    raise Deferred(
                        "outside the 04:30 Europe/Berlin window after authenticated time inspection"
                    )
                vm_attempt = True
                self.backend.freeze_vms()
                self.backend.stop_vms()
                self.guard(state, automatic=automatic)
                for disk in ("a", "b"):
                    require(
                        self.backend.verify_disk(disk, release, boot=True),
                        f"disk {disk} readiness changed during VM shutdown",
                    )
                self.backend.prove_fallback(self.backend.current_version())
                self.backend.assert_no_vms()
                pending["phase"] = "booting"
                pending["boot_id"] = self.backend.boot_id()
                self.save(state)
                self.backend.select(version)
                self.backend.check_firmware_clear()
                self.backend.assert_no_vms()
                self.backend.check_time(anchor=clock)
                require(
                    self.backend.conditional_reboot(version), "conditional reboot did not queue a host reboot"
                )
                self.backend.mark_vm_reboot()
                return {"action": "activation-requested", "version": version}
            except (Error, OSError) as exc:
                if vm_attempt:
                    try:
                        self.backend.protect_current(
                            self.backend.current_version(), state["pending"]["version"]
                        )
                        state["pending"]["phase"] = "ready"
                        state["pending"].pop("boot_id", None)
                        self.save(state)
                    finally:
                        state["vm_restoration"] = self.backend.restore_vms()
                        self.save(state)
                    failures = state["vm_restoration"].get("failures", [])
                    if failures:
                        message = f"activation failed: {exc}; VM restoration needs owner attention: "
                        message += "; ".join(failures)
                        self.reason(state, message)
                        raise Error(message) from exc
                if isinstance(exc, Deferred):
                    return self.reason(state, str(exc))
                self.reason(state, f"activation failed: {exc}")
                raise

    def runtime_guard(self):
        with lock(self.directory):
            state = self.load()
            self.reconcile(state)
            # Before any VM opens raw disks, firmware variables or vTPM state.
            self.backend.check_runtime_state()
            self.backend.recover_vms()
            self.save(state)

    def assess(self):
        with lock(self.directory):
            state = self.load()
            self.reconcile(state)
            self.backend.check_runtime_state()
            self.backend.health()
            current = self.backend.current_version()
            require(current not in state["rejected"], "running a quarantined release")
            self.backend.accept(current)
            if current not in state["accepted"]:
                state["accepted"].append(current)
            state["last_reason"] = f"release {current} passed bounded boot assessment"
            self.save(state)
            return {"action": "accepted", "version": current}

    def bless(self):
        with lock(self.directory):
            state = self.load()
            current = self.backend.current_version()
            require(
                current in state["accepted"] and current not in state["rejected"],
                "boot assessment must accept the running OS before blessing",
            )
            result = self.backend.bless_current()
            # Keep activation durable until native boot counting has succeeded.
            # A failed blessing must still quarantine this candidate after fallback.
            if state["pending"] and state["pending"]["version"] == current:
                state["pending"] = None
            state["last_reason"] = f"release {current} passed assessment and native boot blessing"
            self.save(state)
            self.backend.cleanup_cache()
            return result

    def maintenance(self, reason=None, *, reviewed=False):
        with lock(self.directory):
            state = self.load()
            pending = state["pending"]
            if reason:
                require(reason.strip(), "maintenance reason is required")
                require(
                    not pending or pending["phase"] != "booting",
                    "activation requested; complete or recover boot first",
                )
                require(
                    not pending or pending["version"] != self.backend.current_version(),
                    "assess this OS before firmware maintenance",
                )
                # Use the proven OS and leave prepared updates pending during firmware work.
                state["maintenance"] = {"reason": reason, "since": datetime.now(UTC).isoformat()}
                self.save(state)  # inhibition survives an ESP failure or a missing disk during replacement
                try:
                    self.backend.protect_current(
                        self.backend.current_version(), pending["version"] if pending else None
                    )
                except Error as exc:
                    state["last_reason"] = f"maintenance inhibited; boot defaults need owner review: {exc}"
            else:
                require(
                    reviewed,
                    "review firmware results, BootNext, recovery and host health before leaving maintenance",
                )
                self.backend.check_firmware_clear()
                self.backend.health()
                state["maintenance"] = None
            self.save(state)
            return {"maintenance": state["maintenance"]}
