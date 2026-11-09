"""Enable automation only against an owner-reviewed acceptance record for this installation."""

from datetime import UTC, datetime
from pathlib import Path

from .common import digest, hash_file, read_json, require, run, write_json

SCENARIOS = (
    "preflight",
    "portable_image",
    "cpu_storage_nic_variation",
    "capacity_sectors",
    "unselected_storage",
    "boot_either_disk",
    "boot_a_absent",
    "boot_b_absent",
    "mirror_io_failure",
    "active_usr_loss",
    "replacement",
    "stale_member_return",
    "unclean_mirror_authority",
    "broken_loader_fallback",
    "tampered_artifacts",
    "interrupted_update",
    "eligible_reboot",
    "no_update_no_reboot",
    "missed_window_dst",
    "failed_boot_quarantine",
    "persistent_state_rollback",
    "vm_shutdown_refusal",
    "late_exit_concurrent_start",
    "interrupted_vm_maintenance",
    "external_startup_policy",
    "writable_root_preservation",
    "nocow_auxiliary_state",
    "btrfs_profiles_errors",
    "maintenance_exclusion",
    "firmware_discovery_trust",
    "tpm_recovery",
    "confinement",
    "homed_ssh",
    "external_health_reporting",
    "persistent_startup_policy",
    "physical_interface_policy",
    "memory_capacity",
    "resource_limits",
)


def requirements_digest():
    # Change the revision when an existing scenario's required meaning changes.
    # Older approvals are rejected, never converted into new owner acceptance.
    return digest({"revision": 1, "scenarios": sorted(SCENARIOS)})


def commission(backend, evidence_path, *, enable=False):
    from .install import enrollment_uuids, member, verify_tpm_policy

    evidence = read_json(evidence_path)
    require(evidence.get("schema") == 1, "unknown acceptance record schema")
    require(evidence.get("approved_by"), "record the commissioning owner")
    require(
        evidence["installation_sha256"] == digest(backend.manifest),
        "acceptance record is for another installation",
    )
    require(evidence["image_version"] == backend.current_version(), "acceptance record is for another image")
    require(evidence.get("measured_minimum_ram_mib", 0) >= 2048, "record a measured host RAM minimum")
    require(
        evidence.get("hardware_coverage") and evidence.get("validation_gaps") is not None,
        "record hardware coverage and gaps",
    )
    for name in SCENARIOS:
        item = evidence["scenarios"].get(name, {})
        require(item.get("result") == "pass", f"commissioning scenario has not passed: {name}")
        path = Path(item["evidence"])
        require(
            path.is_file() and hash_file(path) == item["sha256"],
            f"missing or changed scenario evidence: {name}",
        )
    flashing = evidence.get("firmware_flash", {})
    require(flashing.get("result") in ("pass", "no-eligible-update"), "record supervised firmware validation")
    require(
        flashing.get("evidence"),
        "firmware validation needs evidence, including unsupported devices/transports",
    )
    backend.health()
    backend.check_storage(healthy=True)
    backend.check_resources(healthy=True)
    backend.check_firmware_clear()
    enrollment = read_json(backend.directory / "tpm-enrollment.json")
    require(
        enrollment.get("schema") == 1
        and enrollment.get("policy") == backend.config["tpm_policy"]
        and enrollment.get("luks_uuids") == enrollment_uuids(backend.manifest),
        "TPM enrollment does not cover this installation; enroll from its verified normal boot",
    )
    for device in backend.manifest["devices"]:
        verify_tpm_policy(member(device, "state"))
    verify_tpm_policy("/dev/md/particleve-swap")
    record = {
        "schema": 1,
        "acceptance_requirements_sha256": requirements_digest(),
        "installation_sha256": digest(backend.manifest),
        "config_sha256": digest(backend.config),
        "image_version": backend.current_version(),
        "evidence_sha256": hash_file(evidence_path),
        "approved_by": evidence["approved_by"],
        "commissioned_at": datetime.now(UTC).isoformat(),
        "firmware_flash": flashing["result"],
        "reporting_policy_sha256": backend.reporting_policy(),
        "startup_policy_sha256": backend.startup_policy(),
    }
    if enable:
        write_json(backend.directory / "commissioned.json", record)
        run(
            [
                "systemctl",
                "enable",
                "--now",
                "systemd-sysupdate-update.timer",
                "particleve-maintenance.timer",
            ]
        )
    return {"eligible": True, "automation_enabled": enable, "record": record}
