//! Explicit crash-resumable operational rebinding, under persistent maintenance.
use crate::common::{Error, Result, digest, lock, object, read_json, require, run, write_json};
use serde_json::{Value, json};
use std::{fs, path::Path};
const RESOURCE_FIELDS: [&str; 3] = ["metadata_max_percent", "reserve_mib", "reserve_percent"];
pub fn fixed_settings(config: &Value) -> Result<Value> {
    let mut result = config.clone();
    let map = result
        .as_object_mut()
        .ok_or_else(|| Error::new("invalid host configuration"))?;
    for field in ["maintenance", "minimum_ram_mib", "resources"] {
        require(map.remove(field).is_some(), "missing operational policy")?;
    }
    for field in RESOURCE_FIELDS {
        result["storage"]
            .as_object_mut()
            .ok_or_else(|| Error::new("invalid storage policy"))?
            .remove(field)
            .ok_or_else(|| Error::new("missing storage threshold"))?;
    }
    Ok(result)
}
// Historical trust bytes are accepted only as the exact installed binding. They
// never become TLS inputs: the reviewed destination must use system anchors.
fn previous_for_review(previous: &Value, manifest: &Value) -> Result<Value> {
    require(
        manifest["config_sha256"] == digest(previous)?,
        "previous configuration does not match its installation binding",
    )?;
    let mut normalized = previous.clone();
    let time = crate::common::field(previous, "time")?;
    let certificates = crate::common::text(crate::common::field(time, "certificates")?)?;
    require(
        certificates.len() <= 65536 && !certificates.contains("PRIVATE KEY"),
        "historical time policy must contain bounded public certificates only",
    )?;
    let sources = crate::common::list(crate::common::field(time, "sources")?)?;
    let mut installation = false;
    for source in sources {
        match crate::common::text(crate::common::field(source, "trust")?)? {
            "system" => (),
            "installation" => installation = true,
            _ => return Err(Error::new("unknown historical NTS trust policy")),
        }
    }
    require(
        !certificates.is_empty() == installation,
        "historical installation NTS trust requires its explicit public certificate set",
    )?;
    if installation {
        require(regex::Regex::new(r"^(?:\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+$")
            .is_ok_and(|pattern| pattern.is_match(certificates)),
            "historical time trust input must contain only PEM certificates")?;
    }
    normalized["time"]["certificates"] = "".into();
    for source in normalized["time"]["sources"]
        .as_array_mut()
        .ok_or_else(|| Error::new("invalid historical NTS sources"))?
    {
        source["trust"] = "system".into();
    }
    crate::config::validate(normalized, true)
}
/// Legacy trust can only enter inhibition; it cannot authorize ordinary host work.
pub fn maintenance_input(config: Value, directory: &Path) -> Result<Value> {
    if crate::config::validate(config.clone(), true).is_ok() {
        return Ok(config);
    }
    let manifest = read_json(directory.join("installation.json"))?;
    previous_for_review(&config, &manifest)?;
    Ok(config)
}
pub fn invalidate(directory: &Path) -> Result<()> {
    match fs::remove_file(directory.join("commissioned.json")) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    fs::File::open(directory)?.sync_all()?;
    run(&[
        "systemctl",
        "disable",
        "--now",
        "systemd-sysupdate-update.timer",
        "particleve-maintenance.timer",
    ])?;
    Ok(())
}
pub fn disable_automation(directory: &Path) -> Result<Value> {
    let _ownership = lock(directory)?;
    invalidate(directory)?;
    Ok(json!({"automation_enabled":false}))
}
pub fn binding_status(config_file: &Path, directory: &Path) -> Result<Value> {
    let manifest = read_json(directory.join("installation.json"))?;
    let mut result = json!({"state":crate::coordinator::load_state(directory)?,"installation_sha256":digest(&manifest)?,"commissioned":directory.join("commissioned.json").exists(),"reconfiguration_pending":directory.join("reconfiguration.json").exists()});
    let binding: Result<Value> = (|| {
        let current = crate::config::validate(read_json(config_file)?, true)?;
        let actual = digest(&current)?;
        Ok(
            json!({"valid":actual==manifest["config_sha256"],"expected":manifest["config_sha256"],"actual":actual}),
        )
    })();
    result["config_binding"] = match binding {
        Ok(v) => v,
        Err(e) => json!({"valid":false,"error":format!("{e}")}),
    };
    Ok(result)
}
pub fn reconfigure(
    directory: &Path,
    destination: &Path,
    previous: Option<Value>,
    proposed: Option<Value>,
    confirmation: Option<&str>,
    resume: bool,
) -> Result<Value> {
    let destination = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir()?.join(destination)
    };
    let _ownership = lock(directory)?;
    let journal = directory.join("reconfiguration.json");
    let interrupted = if journal.exists() {
        Some(read_json(&journal)?)
    } else {
        None
    };
    let (previous, proposed) = if resume {
        require(
            previous.is_none() && proposed.is_none(),
            "journal recovery does not accept new inputs",
        )?;
        let interrupted = interrupted
            .as_ref()
            .ok_or_else(|| Error::new("no interrupted reconfiguration to resume"))?;
        (
            interrupted.get("previous_config").cloned().ok_or_else(|| {
                Error::new("reconfiguration journal lacks its previous configuration")
            })?,
            interrupted.get("proposed_config").cloned().ok_or_else(|| {
                Error::new("reconfiguration journal lacks its proposed configuration")
            })?,
        )
    } else {
        (
            previous
                .ok_or_else(|| Error::new("supply the previous and proposed configurations"))?,
            proposed
                .ok_or_else(|| Error::new("supply the previous and proposed configurations"))?,
        )
    };
    let installed = read_json(directory.join("installation.json"))?;
    let old = interrupted.as_ref().map_or(installed.clone(), |journal| {
        journal["previous_manifest"].clone()
    });
    let reviewed_previous = previous_for_review(&previous, &old)?;
    let proposed = crate::config::validate(proposed, true)?;
    require(
        digest(&previous)? != digest(&proposed)?,
        "no operational policy change was proposed",
    )?;
    require(
        fixed_settings(&reviewed_previous)? == fixed_settings(&proposed)?,
        "reconfiguration permits operational policy only; disk/layout, identity, trust, network and access settings are fixed",
    )?;
    let state = crate::coordinator::load_state(directory)?;
    require(
        !state["maintenance"].is_null() && state["pending"].is_null(),
        "persistent maintenance and no pending OS transaction are required",
    )?;
    require(
        !directory.join("replacement.json").exists(),
        "finish disk replacement before reconfiguration",
    )?;
    let mut new = old.clone();
    object(&new)?;
    new["config_sha256"] = digest(&proposed)?.into();
    require(
        installed == old || installed == new,
        "installation changed during reconfiguration",
    )?;
    let active = read_json(&destination)?;
    require(
        active == previous || active == proposed,
        "active configuration differs from the reviewed inputs",
    )?;
    let mut thresholds = json!({});
    for name in RESOURCE_FIELDS {
        thresholds[name] = proposed["storage"][name].clone();
    }
    let mut plan = json!({"schema":1,"configuration_path":destination.display().to_string(),"installation_sha256":digest(&old)?,"previous_config_sha256":digest(&previous)?,"proposed_config_sha256":digest(&proposed)?,"maintenance":proposed["maintenance"],"minimum_ram_mib":proposed["minimum_ram_mib"],"resources":proposed["resources"],"storage_thresholds":thresholds});
    if previous["time"] != reviewed_previous["time"] {
        plan["system_trust_transition"] = json!({
            "previous_time_policy_sha256": digest(&previous["time"])?,
            "proposed_time_policy_sha256": digest(&proposed["time"])?,
        });
    }
    let transaction = json!({"plan":plan,"previous_manifest":old,"proposed_manifest":new,"previous_config":previous,"proposed_config":proposed});
    require(
        interrupted.as_ref().is_none_or(|v| v == &transaction),
        "resume the exact reviewed reconfiguration first",
    )?;
    let Some(confirmation) = confirmation else {
        return Ok(
            json!({"plan":plan,"confirmation":digest(&plan)?,"resume":interrupted.is_some()}),
        );
    };
    require(
        confirmation == digest(&plan)?,
        "reconfiguration plan changed",
    )?;
    write_json(&journal, &transaction)?;
    invalidate(directory)?;
    write_json(destination, &proposed)?;
    write_json(directory.join("installation.json"), &new)?;
    fs::remove_file(journal)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(
        json!({"action":"reconfigured","installation_sha256":digest(&new)?,"automation_enabled":false,"next":"validate the policy and recommission; maintenance remains active"}),
    )
}
