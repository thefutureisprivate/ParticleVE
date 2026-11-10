//! Automation requires owner-reviewed evidence bound to this exact installation.
use crate::common::{
    Result, digest, field, hash_file, list, read_json, require, run, text, uint, write_json,
};
use crate::linux::Linux;
use serde_json::{Value, json};
use std::path::Path;
pub const SCENARIOS: [&str; 38] = [
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
];
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_none_or(|value| value != 0.),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
pub fn requirements_digest() -> Result<String> {
    let mut scenarios = SCENARIOS.to_vec();
    scenarios.sort_unstable();
    digest(&json!({"revision":1,"scenarios":scenarios}))
}
pub fn commission(backend: &Linux, evidence_path: &Path, enable: bool) -> Result<Value> {
    let evidence = read_json(evidence_path)?;
    require(evidence["schema"] == 1, "unknown acceptance record schema")?;
    require(
        evidence
            .get("approved_by")
            .is_some_and(|v| v.as_str().is_some_and(|v| !v.is_empty())),
        "record the commissioning owner",
    )?;
    require(
        evidence["installation_sha256"] == digest(&backend.manifest)?,
        "acceptance record is for another installation",
    )?;
    require(
        evidence["image_version"] == backend.current_version()?,
        "acceptance record is for another image",
    )?;
    require(
        evidence
            .get("measured_minimum_ram_mib")
            .map(uint)
            .transpose()?
            .unwrap_or(0)
            >= 2048,
        "record a measured host RAM minimum",
    )?;
    require(
        evidence.get("hardware_coverage").is_some_and(truthy)
            && evidence
                .get("validation_gaps")
                .is_some_and(|v| !v.is_null()),
        "record hardware coverage and gaps",
    )?;
    for name in SCENARIOS {
        let item = field(field(&evidence, "scenarios")?, name)?;
        require(
            item["result"] == "pass",
            format!("commissioning scenario has not passed: {name}"),
        )?;
        let path = Path::new(text(field(item, "evidence")?)?);
        require(
            path.is_file() && hash_file(path, None)? == text(field(item, "sha256")?)?,
            format!("missing or changed scenario evidence: {name}"),
        )?;
    }
    let flashing = field(&evidence, "firmware_flash")?;
    require(
        matches!(
            text(field(flashing, "result")?)?,
            "pass" | "no-eligible-update"
        ),
        "record supervised firmware validation",
    )?;
    require(
        flashing.get("evidence").is_some_and(truthy),
        "firmware validation needs evidence, including unsupported devices/transports",
    )?;
    backend.health()?;
    backend.check_storage(true)?;
    backend.check_resources(true)?;
    backend.check_firmware_clear()?;
    let enrollment = read_json(backend.directory.join("tpm-enrollment.json"))?;
    require(
        enrollment["schema"] == 1
            && enrollment["policy"] == backend.config["tpm_policy"]
            && enrollment["luks_uuids"]
                == json!(crate::install::enrollment_uuids(&backend.manifest)?),
        "TPM enrollment does not cover this installation; enroll from its verified normal boot",
    )?;
    for device in list(field(&backend.manifest, "devices")?)? {
        crate::install::verify_tpm_policy(&crate::install::member(device, "state")?)?;
    }
    crate::install::verify_tpm_policy("/dev/md/particleve-swap")?;
    let record = json!({"schema":1,"acceptance_requirements_sha256":requirements_digest()?,"installation_sha256":digest(&backend.manifest)?,"config_sha256":digest(&backend.config)?,"image_version":backend.current_version()?,"evidence_sha256":hash_file(evidence_path,None)?,"approved_by":evidence["approved_by"],"commissioned_at":crate::linux::timestamp(),"firmware_flash":flashing["result"],"reporting_policy_sha256":backend.reporting_policy()?,"startup_policy_sha256":backend.startup_policy()?});
    if enable {
        write_json(backend.directory.join("commissioned.json"), &record)?;
        run(&[
            "systemctl",
            "enable",
            "--now",
            "systemd-sysupdate-update.timer",
            "particleve-maintenance.timer",
        ])?;
    }
    Ok(json!({"eligible":true,"automation_enabled":enable,"record":record}))
}
