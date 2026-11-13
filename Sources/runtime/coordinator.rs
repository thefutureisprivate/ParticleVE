//! Crash-resumable, serialized two-disk OS transactions.
use crate::common::{Error, Result, digest, field, lock, read_json, require, text, write_json};
use chrono::{DateTime, Timelike, Utc};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
pub fn reboot_window(now: DateTime<Utc>, tolerance: u32) -> bool {
    let local = now.with_timezone(&chrono_tz::Europe::Berlin);
    local.hour() == 4 && local.minute() == 30 && local.second() < tolerance
}
/// Once enqueue has been attempted, an IPC/observation failure is not a refusal.
pub enum RebootOutcome {
    NotAccepted,
    Accepted,
    Uncertain(String),
}
pub trait Backend {
    fn config(&self) -> &Value;
    fn current_version(&self) -> Result<String>;
    fn boot_id(&self) -> Result<String>;
    fn check_commissioned(&self) -> Result<()>;
    fn check_firmware_clear(&self) -> Result<()>;
    fn check_storage(&self, healthy: bool) -> Result<Value>;
    fn check_resources(&self, healthy: bool) -> Result<Value>;
    fn release(&self, version: Option<&str>) -> Result<Value>;
    fn check_compatibility(&self, current: &str, release: &Value) -> Result<()>;
    fn prove_fallback(&self, current: &str) -> Result<()>;
    fn protect_current(&self, current: &str, candidate: Option<&str>) -> Result<()>;
    fn pin_current(&self, current: &str) -> Result<()>;
    fn verify_disk(&self, role: &str, release: &Value, boot: bool) -> Result<bool>;
    fn transfer(&self, role: &str, release: &Value, current: &str) -> Result<()>;
    fn expose_boot(&self, role: &str, release: &Value) -> Result<()>;
    fn check_time(&self, anchor: Option<&Value>) -> Result<Value>;
    fn freeze_vms(&self) -> Result<()>;
    fn stop_vms(&self) -> Result<()>;
    fn assert_no_vms(&self) -> Result<()>;
    fn restore_vms(&self) -> Result<Value>;
    fn recover_vms(&self) -> Result<Value>;
    fn mark_vm_reboot(&self) -> Result<()>;
    fn select(&self, version: &str) -> Result<()>;
    /// Errors are confined to preparation before a reboot request is attempted.
    fn conditional_reboot(&self, version: &str) -> Result<RebootOutcome>;
    fn reject(&self, version: &str, current: &str) -> Result<()>;
    fn retry_quarantine(&self) -> Result<()>;
    fn check_runtime_state(&self) -> Result<()>;
    fn health(&self) -> Result<()>;
    fn accept(&self, version: &str) -> Result<()>;
    fn bless_current(&self) -> Result<Value>;
    fn cleanup_cache(&self) -> Result<()>;
}
pub fn load_state(directory: &Path) -> Result<Value> {
    let path = directory.join("state.json");
    if !path.exists() {
        return Ok(
            json!({"schema":1,"maintenance":null,"pending":null,"accepted":[],"rejected":{},"last_reason":"not commissioned"}),
        );
    }
    let state = read_json(path)?;
    require(
        state["schema"] == 1,
        "unsupported transaction schema; recovery requires review",
    )?;
    Ok(state)
}
pub struct Coordinator<'a, B: Backend> {
    pub directory: PathBuf,
    pub backend: &'a B,
    pub path: PathBuf,
}
impl<'a, B: Backend> Coordinator<'a, B> {
    pub fn new(directory: &Path, backend: &'a B) -> Self {
        Self {
            directory: directory.into(),
            backend,
            path: directory.join("state.json"),
        }
    }
    pub fn load(&self) -> Result<Value> {
        let state = load_state(&self.directory)?;
        // Persisted absence is not authorization: malformed journals must fail before disk work.
        let maintenance = field(&state, "maintenance")?;
        require(
            maintenance.is_null() || maintenance.is_object(),
            "invalid persistent maintenance record",
        )?;
        if !maintenance.is_null() {
            text(field(maintenance, "reason")?)?;
        }
        let pending = field(&state, "pending")?;
        if !pending.is_null() {
            crate::config::version_key(text(field(pending, "version")?)?)?;
            require(
                matches!(
                    text(field(pending, "phase")?)?,
                    "preparing" | "ready" | "booting"
                ),
                "unknown transaction phase",
            )?;
            text(field(pending, "sha256")?)?;
            crate::common::object(field(pending, "disks")?)?;
            if pending["phase"] == "booting" {
                text(field(pending, "boot_id")?)?;
            }
        }
        crate::common::list(field(&state, "accepted")?)?;
        crate::common::object(field(&state, "rejected")?)?;
        Ok(state)
    }
    pub fn save(&self, state: &mut Value) -> Result<()> {
        state["updated_at"] = Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
            .into();
        write_json(&self.path, state)
    }
    fn reason(&self, state: &mut Value, message: impl Into<String>) -> Result<Value> {
        let message = message.into();
        state["last_reason"] = message.clone().into();
        self.save(state)?;
        Ok(json!({"action":"deferred","reason":message}))
    }
    fn guard(&self, state: &Value, automatic: bool) -> Result<()> {
        if !state["maintenance"].is_null() {
            return Err(Error::deferred(format!(
                "persistent manual maintenance: {}",
                text(field(&state["maintenance"], "reason")?)?
            )));
        }
        if automatic {
            self.backend.check_commissioned()?;
        }
        self.backend.check_firmware_clear()?;
        self.backend.check_storage(true)?;
        self.backend.check_resources(true)?;
        Ok(())
    }
    fn guard_reboot_intent(&self, state: &Value) -> Result<()> {
        require(
            state["pending"]["phase"] != "booting"
                || state["pending"]["boot_id"] != self.backend.boot_id()?,
            "a reboot request may be in progress; reconcile before changing boot selection or restoring VMs",
        )
    }
    fn reconcile(&self, state: &mut Value) -> Result<()> {
        if state["pending"]["phase"] == "booting"
            && state["pending"]["boot_id"] == self.backend.boot_id()?
        {
            return Ok(());
        }
        self.backend.retry_quarantine()?;
        if state["pending"].is_null() {
            return Ok(());
        }
        let pending = state["pending"].clone();
        let version = text(field(&pending, "version")?)?;
        let current = self.backend.current_version()?;
        if version == current {
            require(
                matches!(text(field(&pending, "phase")?)?, "ready" | "booting"),
                "booted an incomplete transaction; manual recovery required",
            )?;
            return Ok(());
        }
        if pending["phase"] == "booting" && pending["boot_id"] != self.backend.boot_id()? {
            state["rejected"][version] = "fallback after activation".into();
            self.save(state)?;
            self.backend.reject(version, &current)?;
            state["pending"] = Value::Null;
            self.save(state)?;
        }
        Ok(())
    }
    pub fn prepare(&self, automatic: bool) -> Result<Value> {
        let _ownership = lock(&self.directory)?;
        let mut state = self.load()?;
        let result = (|| {
            self.reconcile(&mut state)?;
            self.guard(&state, automatic)?;
            let current = self.backend.current_version()?;
            let pending = state["pending"].clone();
            if pending["phase"] == "booting" {
                return Err(Error::deferred(
                    "activation already requested; await boot assessment",
                ));
            }
            let release = self
                .backend
                .release(pending.get("version").map(text).transpose()?)?;
            let version = text(field(&release, "version")?)?.to_owned();
            if state["rejected"].get(&version).is_some() {
                return Err(Error::deferred(format!("release {version} is quarantined")));
            }
            if crate::config::version_key(&version)? <= crate::config::version_key(&current)? {
                return Err(Error::deferred("no newer OS release"));
            }
            self.backend.check_compatibility(&current, &release)?;
            self.backend.prove_fallback(&current)?;
            if !pending.is_null() {
                require(
                    pending["sha256"] == digest(&release)?,
                    "transaction release content changed",
                )?;
            } else {
                state["pending"] = json!({"version":version,"sha256":digest(&release)?,"phase":"preparing","disks":{}});
                self.save(&mut state)?;
            }
            self.backend.protect_current(&current, Some(&version))?;
            for role in ["a", "b"] {
                if !self.backend.verify_disk(role, &release, false)? {
                    state["pending"]["disks"]
                        .as_object_mut()
                        .ok_or_else(|| Error::new("invalid transaction disks"))?
                        .remove(role);
                    state["pending"]["phase"] = "preparing".into();
                    self.save(&mut state)?;
                    self.backend.transfer(role, &release, &current)?;
                }
                require(
                    self.backend.verify_disk(role, &release, false)?,
                    format!("disk {role} OS verification failed"),
                )?;
                state["pending"]["disks"][role] = "os-verified".into();
                self.save(&mut state)?;
            }
            for role in ["a", "b"] {
                self.backend.expose_boot(role, &release)?;
                require(
                    self.backend.verify_disk(role, &release, true)?,
                    format!("disk {role} boot verification failed"),
                )?;
                state["pending"]["disks"][role] = "complete".into();
                self.save(&mut state)?;
            }
            self.guard(&state, automatic)?;
            state["pending"]["phase"] = "ready".into();
            state["last_reason"] = format!("release {version} ready on both disks").into();
            self.save(&mut state)?;
            Ok(json!({"action":"ready","version":version}))
        })();
        match result {
            Ok(v) => Ok(v),
            Err(e) if e.deferred => self.reason(&mut state, e.message),
            Err(e) => {
                self.reason(&mut state, format!("preparation failed: {e}"))?;
                Err(e)
            }
        }
    }
    pub fn reboot(&self, now: Option<DateTime<Utc>>, automatic: bool) -> Result<Value> {
        let _ownership = lock(&self.directory)?;
        let mut state = self.load()?;
        let mut vm_attempt = false;
        let mut reboot_uncertain = false;
        let result = (|| {
            self.reconcile(&mut state)?;
            let tolerance = crate::common::uint(
                &self.backend.config()["maintenance"]["start_tolerance_seconds"],
            )? as u32;
            if automatic && !reboot_window(now.unwrap_or_else(Utc::now), tolerance) {
                return Err(Error::deferred("outside the 04:30 Europe/Berlin window"));
            }
            self.guard(&state, automatic)?;
            let pending = state["pending"].clone();
            if pending.is_null() || pending["phase"] != "ready" {
                return Err(Error::deferred("no complete pending release"));
            }
            let version = text(field(&pending, "version")?)?.to_owned();
            let current = self.backend.current_version()?;
            if state["rejected"].get(&version).is_some()
                || crate::config::version_key(&version)? <= crate::config::version_key(&current)?
            {
                return Err(Error::deferred(
                    "pending release is rejected or already running",
                ));
            }
            let release = self.backend.release(Some(&version))?;
            require(
                digest(&release)? == pending["sha256"],
                "pending release identity changed",
            )?;
            self.backend.check_compatibility(&current, &release)?;
            for role in ["a", "b"] {
                require(
                    self.backend.verify_disk(role, &release, true)?,
                    format!("disk {role} readiness was lost"),
                )?;
            }
            self.backend.prove_fallback(&current)?;
            let clock = self.backend.check_time(None)?;
            let wall = clock["wall"]
                .as_f64()
                .ok_or_else(|| Error::new("invalid authenticated clock"))?;
            let seconds = wall.floor() as i64;
            let nanos = ((wall - wall.floor()) * 1e9) as u32;
            let checked = DateTime::from_timestamp(seconds, nanos)
                .ok_or_else(|| Error::new("invalid authenticated clock"))?;
            if automatic && !reboot_window(checked, tolerance) {
                return Err(Error::deferred(
                    "outside the 04:30 Europe/Berlin window after authenticated time inspection",
                ));
            }
            vm_attempt = true;
            self.backend.freeze_vms()?;
            self.backend.stop_vms()?;
            self.guard(&state, automatic)?;
            for role in ["a", "b"] {
                require(
                    self.backend.verify_disk(role, &release, true)?,
                    format!("disk {role} readiness changed during VM shutdown"),
                )?;
            }
            self.backend
                .prove_fallback(&self.backend.current_version()?)?;
            self.backend.assert_no_vms()?;
            state["pending"]["phase"] = "booting".into();
            state["pending"]["boot_id"] = self.backend.boot_id()?.into();
            self.save(&mut state)?;
            self.backend.select(&version)?;
            self.backend.check_firmware_clear()?;
            self.backend.assert_no_vms()?;
            self.backend.check_time(Some(&clock))?;
            // Both journals must describe the possible reboot before crossing
            // the enqueue boundary. No fallible marker write follows acceptance.
            self.backend.mark_vm_reboot()?;
            match self.backend.conditional_reboot(&version)? {
                RebootOutcome::NotAccepted => {
                    return Err(Error::new("conditional reboot did not queue a host reboot"));
                }
                RebootOutcome::Accepted => (),
                RebootOutcome::Uncertain(reason) => {
                    reboot_uncertain = true;
                    return Err(Error::new(format!(
                        "reboot acceptance is uncertain: {reason}"
                    )));
                }
            }
            Ok(json!({"action":"activation-requested","version":version}))
        })();
        match result {
            Ok(v) => Ok(v),
            Err(error) => {
                if reboot_uncertain {
                    // A failed observation or journal write cannot authorize
                    // changing BootNext/defaults under a possibly queued reboot.
                    self.reason(&mut state, format!("{error}; activation intent retained"))?;
                    return Err(error);
                }
                if vm_attempt {
                    let restore_boot = (|| {
                        let current = self.backend.current_version()?;
                        let candidate = state["pending"].get("version").map(text).transpose()?;
                        self.backend.protect_current(&current, candidate)?;
                        state["pending"]["phase"] = "ready".into();
                        state["pending"]
                            .as_object_mut()
                            .ok_or_else(|| Error::new("invalid transaction"))?
                            .remove("boot_id");
                        self.save(&mut state)
                    })(); // Restore this attempt's VMs even if ESP repair fails; the journal remains authoritative.
                    let restoration = self.backend.restore_vms();
                    match restoration {
                        Ok(value) => {
                            state["vm_restoration"] = value;
                            self.save(&mut state)?;
                        }
                        Err(e) => {
                            self.reason(
                                &mut state,
                                format!("activation failed: {error}; VM restoration failed: {e}"),
                            )?;
                            return Err(e);
                        }
                    }
                    if let Some(failures) = state["vm_restoration"]
                        .get("failures")
                        .and_then(Value::as_array)
                        && !failures.is_empty()
                    {
                        let message = format!(
                            "activation failed: {error}; VM restoration needs owner attention: {}",
                            failures
                                .iter()
                                .map(|v| v.as_str().unwrap_or("unknown restoration failure"))
                                .collect::<Vec<_>>()
                                .join("; ")
                        );
                        self.reason(&mut state, &message)?;
                        return Err(Error::new(message));
                    }
                    restore_boot?;
                }
                if error.deferred {
                    self.reason(&mut state, error.message)
                } else {
                    self.reason(&mut state, format!("activation failed: {error}"))?;
                    Err(error)
                }
            }
        }
    }
    pub fn runtime_guard(&self) -> Result<()> {
        let _ownership = lock(&self.directory)?;
        let mut state = self.load()?;
        self.guard_reboot_intent(&state)?;
        self.reconcile(&mut state)?;
        self.backend.check_runtime_state()?;
        self.backend.recover_vms()?;
        self.save(&mut state)
    }
    pub fn recover_vms(&self) -> Result<Value> {
        let _ownership = lock(&self.directory)?;
        self.guard_reboot_intent(&self.load()?)?;
        self.backend.recover_vms()
    }
    pub fn assess(&self) -> Result<Value> {
        let _ownership = lock(&self.directory)?;
        let mut state = self.load()?;
        self.guard_reboot_intent(&state)?;
        self.reconcile(&mut state)?;
        self.backend.check_runtime_state()?;
        self.backend.health()?;
        let current = self.backend.current_version()?;
        require(
            state["rejected"].get(&current).is_none(),
            "running a quarantined release",
        )?;
        self.backend.accept(&current)?;
        let accepted = state["accepted"]
            .as_array_mut()
            .ok_or_else(|| Error::new("invalid accepted releases"))?;
        if !accepted.iter().any(|v| v == &current) {
            accepted.push(current.clone().into());
        }
        state["last_reason"] = format!("release {current} passed bounded boot assessment").into();
        self.save(&mut state)?;
        Ok(json!({"action":"accepted","version":current}))
    }
    pub fn bless(&self) -> Result<Value> {
        let _ownership = lock(&self.directory)?;
        let mut state = self.load()?;
        self.guard_reboot_intent(&state)?;
        let current = self.backend.current_version()?;
        require(
            state["accepted"]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v == &current))
                && state["rejected"].get(&current).is_none(),
            "boot assessment must accept the running OS before blessing",
        )?;
        let result = self.backend.bless_current()?;
        if state["pending"]["version"] == current {
            state["pending"] = Value::Null;
        }
        state["last_reason"] =
            format!("release {current} passed assessment and native boot blessing").into();
        self.save(&mut state)?;
        self.backend.cleanup_cache()?;
        Ok(result)
    }
    pub fn maintenance(&self, reason: Option<&str>, reviewed: bool) -> Result<Value> {
        let _ownership = lock(&self.directory)?;
        let mut state = self.load()?;
        if let Some(reason) = reason {
            require(!reason.trim().is_empty(), "maintenance reason is required")?;
            require(
                state["pending"]["phase"] != "booting",
                "activation requested; complete or recover boot first",
            )?;
            require(
                state["pending"]["version"] != self.backend.current_version()?,
                "assess this OS before firmware maintenance",
            )?;
            state["maintenance"] = json!({"reason":reason,"since":Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros,false)});
            self.save(&mut state)?;
            if let Err(e) = self.backend.pin_current(&self.backend.current_version()?) {
                state["last_reason"] =
                    format!("maintenance inhibited; boot defaults need owner review: {e}").into();
            }
        } else {
            require(
                reviewed,
                "review firmware results, BootNext, recovery and host health before leaving maintenance",
            )?;
            self.backend.check_firmware_clear()?;
            self.backend.health()?;
            state["maintenance"] = Value::Null;
        }
        self.save(&mut state)?;
        Ok(json!({"maintenance":state["maintenance"]}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct FakeState {
        current: String,
        boot: String,
        latest: String,
        calls: Vec<String>,
        fail: Option<String>,
        blocked: Option<String>,
        disks: BTreeMap<String, String>,
        entries: BTreeMap<String, String>,
        refuse: bool,
        step: bool,
        queue: bool,
        uncertain: bool,
        fail_journal_after_enqueue: Option<PathBuf>,
        content_changed: bool,
        corrected_wall: Option<f64>,
        stop_block: Option<String>,
    }
    struct Fake {
        config: Value,
        state: RefCell<FakeState>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                config: json!({"maintenance":{"start_tolerance_seconds":60}}),
                state: RefCell::new(FakeState {
                    current: "45.0.1.1-1.1".into(),
                    boot: "first".into(),
                    latest: "45.0.1.2-1.1".into(),
                    queue: true,
                    ..FakeState::default()
                }),
            }
        }
        fn event(&self, name: &str) -> Result<()> {
            let mut state = self.state.borrow_mut();
            state.calls.push(name.into());
            require(
                state.fail.as_deref() != Some(name),
                format!("interrupted {name}"),
            )
        }
        fn block(&self, kind: &str) -> Result<()> {
            if self.state.borrow().blocked.as_deref() == Some(kind) {
                return Err(Error::deferred(format!("blocked {kind}")));
            }
            Ok(())
        }
    }
    impl Backend for Fake {
        fn config(&self) -> &Value {
            &self.config
        }
        fn current_version(&self) -> Result<String> {
            Ok(self.state.borrow().current.clone())
        }
        fn boot_id(&self) -> Result<String> {
            Ok(self.state.borrow().boot.clone())
        }
        fn check_commissioned(&self) -> Result<()> {
            self.block("commissioned")
        }
        fn check_firmware_clear(&self) -> Result<()> {
            self.block("firmware")
        }
        fn check_storage(&self, _healthy: bool) -> Result<Value> {
            self.block("storage")?;
            Ok(Value::Null)
        }
        fn check_resources(&self, _healthy: bool) -> Result<Value> {
            self.block("memory")?;
            Ok(Value::Null)
        }
        fn release(&self, version: Option<&str>) -> Result<Value> {
            Ok(
                json!({"version":version.map(str::to_owned).unwrap_or_else(||self.state.borrow().latest.clone()),"artifacts":{"usr":{"sha256":if self.state.borrow().content_changed {"changed"} else {"immutable"}}}}),
            )
        }
        fn check_compatibility(&self, _current: &str, _release: &Value) -> Result<()> {
            self.block("schema")
        }
        fn prove_fallback(&self, _current: &str) -> Result<()> {
            self.event("fallback")
        }
        fn protect_current(&self, _current: &str, _candidate: Option<&str>) -> Result<()> {
            self.event("protect")
        }
        fn pin_current(&self, _current: &str) -> Result<()> {
            self.event("pin")
        }
        fn verify_disk(&self, role: &str, release: &Value, boot: bool) -> Result<bool> {
            let state = self.state.borrow();
            Ok(
                state.disks.get(role).map(String::as_str) == release["version"].as_str()
                    && (!boot
                        || state.entries.get(role).map(String::as_str)
                            == release["version"].as_str()),
            )
        }
        fn transfer(&self, role: &str, release: &Value, _current: &str) -> Result<()> {
            self.event(&format!("transfer-{role}"))?;
            self.state
                .borrow_mut()
                .disks
                .insert(role.into(), text(&release["version"])?.into());
            self.event(&format!("transferred-{role}"))
        }
        fn expose_boot(&self, role: &str, release: &Value) -> Result<()> {
            require(
                self.state
                    .borrow()
                    .disks
                    .values()
                    .filter(|v| v.as_str() == release["version"].as_str().unwrap_or(""))
                    .count()
                    == 2,
                "OS entries exposed too early",
            )?;
            self.event(&format!("expose-{role}"))?;
            self.state
                .borrow_mut()
                .entries
                .insert(role.into(), text(&release["version"])?.into());
            self.event(&format!("exposed-{role}"))
        }
        fn check_time(&self, anchor: Option<&Value>) -> Result<Value> {
            self.event(if anchor.is_some() {
                "time-recheck"
            } else {
                "time-check"
            })?;
            self.block("time")?;
            if anchor.is_some() && self.state.borrow().step {
                return Err(Error::deferred("clock stepped"));
            }
            Ok(
                json!({"wall":self.state.borrow().corrected_wall.unwrap_or(1793935800.),"boottime":100.}),
            )
        }
        fn freeze_vms(&self) -> Result<()> {
            self.event("freeze-vms")
        }
        fn stop_vms(&self) -> Result<()> {
            self.event("stop-vms")?;
            let stop_block = self.state.borrow().stop_block.clone();
            if let Some(blocked) = stop_block {
                self.state.borrow_mut().blocked = Some(blocked);
            }
            if self.state.borrow().refuse {
                Err(Error::deferred("VM refused poweroff"))
            } else {
                Ok(())
            }
        }
        fn assert_no_vms(&self) -> Result<()> {
            self.event("no-vms")
        }
        fn restore_vms(&self) -> Result<Value> {
            self.event("restore-vms")?;
            Ok(json!({"action":"restored"}))
        }
        fn recover_vms(&self) -> Result<Value> {
            self.event("recover-vms")?;
            Ok(Value::Null)
        }
        fn mark_vm_reboot(&self) -> Result<()> {
            self.event("mark-vm-reboot")
        }
        fn select(&self, _version: &str) -> Result<()> {
            self.event("select")
        }
        fn conditional_reboot(&self, _version: &str) -> Result<RebootOutcome> {
            self.event("reboot")?;
            if let Some(path) = &self.state.borrow().fail_journal_after_enqueue {
                // Retain the persisted intent while forcing the next atomic
                // replacement to fail, independently of the test runner's UID.
                std::fs::rename(path, path.with_extension("retained.json")).unwrap();
                std::fs::create_dir(path).unwrap();
            }
            Ok(if self.state.borrow().uncertain {
                RebootOutcome::Uncertain("post-enqueue observation failed".into())
            } else if self.state.borrow().queue {
                RebootOutcome::Accepted
            } else {
                RebootOutcome::NotAccepted
            })
        }
        fn reject(&self, version: &str, _current: &str) -> Result<()> {
            self.event(&format!("reject-{version}"))?;
            self.state.borrow_mut().entries.retain(|_, v| v != version);
            Ok(())
        }
        fn retry_quarantine(&self) -> Result<()> {
            self.event("retry-quarantine")
        }
        fn check_runtime_state(&self) -> Result<()> {
            self.event("daemon-state")
        }
        fn health(&self) -> Result<()> {
            self.event("health")
        }
        fn accept(&self, _version: &str) -> Result<()> {
            self.event("accept")
        }
        fn bless_current(&self) -> Result<Value> {
            self.event("bless")?;
            Ok(json!({"boot_blessed":self.state.borrow().current}))
        }
        fn cleanup_cache(&self) -> Result<()> {
            self.event("cleanup")
        }
    }
    fn window() -> DateTime<Utc> {
        "2026-11-06T03:30:00Z".parse().expect("fixed UTC date")
    }
    #[test]
    fn complete_transaction_blesses_only_after_assessment_and_never_repeats_reboot() {
        let directory = tempfile::tempdir().expect("temporary state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        assert_eq!(
            coordinator.prepare(true).expect("prepare")["action"],
            "ready"
        );
        assert_eq!(
            coordinator.reboot(Some(window()), true).expect("activate")["action"],
            "activation-requested"
        );
        assert_eq!(
            coordinator
                .reboot(Some(window()), true)
                .expect("repeat deferred")["action"],
            "deferred"
        );
        backend.state.borrow_mut().current = "45.0.1.2-1.1".into();
        backend.state.borrow_mut().boot = "second".into();
        assert!(coordinator.bless().is_err());
        coordinator.assess().expect("assess");
        assert!(!coordinator.load().expect("state")["pending"].is_null());
        coordinator.bless().expect("bless");
        assert!(coordinator.load().expect("state")["pending"].is_null());
        assert_eq!(
            backend
                .state
                .borrow()
                .calls
                .iter()
                .filter(|v| v.as_str() == "reboot")
                .count(),
            1
        );
    }
    #[test]
    fn every_preparation_interruption_resumes_the_original_release() {
        for boundary in [
            "protect",
            "transfer-a",
            "transferred-a",
            "transfer-b",
            "transferred-b",
            "expose-a",
            "exposed-a",
            "expose-b",
            "exposed-b",
        ] {
            let directory = tempfile::tempdir().expect("state");
            let backend = Fake::new();
            backend.state.borrow_mut().fail = Some(boundary.into());
            let coordinator = Coordinator::new(directory.path(), &backend);
            assert!(coordinator.prepare(true).is_err(), "{boundary}");
            backend.state.borrow_mut().fail = None;
            backend.state.borrow_mut().latest = "45.0.1.3-1.1".into();
            let result = coordinator.prepare(true).expect("resume");
            assert_eq!(result["version"], "45.0.1.2-1.1", "{boundary}");
            assert!(!backend.state.borrow().calls.iter().any(|v| v == "reboot"));
        }
    }
    #[test]
    fn accepted_and_uncertain_reboots_preserve_boot_selection_and_vm_intent() {
        for uncertain in [false, true] {
            let directory = tempfile::tempdir().expect("state");
            let backend = Fake::new();
            let coordinator = Coordinator::new(directory.path(), &backend);
            coordinator.prepare(true).expect("prepare");
            backend.state.borrow_mut().calls.clear();
            backend.state.borrow_mut().uncertain = uncertain;
            let outcome = coordinator.reboot(Some(window()), true);
            if uncertain {
                assert!(
                    outcome
                        .expect_err("uncertain request")
                        .message
                        .contains("uncertain")
                );
            } else {
                assert_eq!(outcome.expect("accepted")["action"], "activation-requested");
            }
            assert_eq!(
                coordinator.load().expect("intent")["pending"]["phase"],
                "booting"
            );
            assert!(coordinator.runtime_guard().is_err());
            assert!(coordinator.recover_vms().is_err());
            assert!(coordinator.assess().is_err());
            assert!(coordinator.bless().is_err());
            let state = backend.state.borrow();
            let marker = state
                .calls
                .iter()
                .position(|c| c == "mark-vm-reboot")
                .expect("VM intent");
            let enqueue = state
                .calls
                .iter()
                .position(|c| c == "reboot")
                .expect("request");
            assert!(marker < enqueue);
            assert!(!state.calls.iter().any(|c| ["protect", "pin", "restore-vms", "recover-vms"].contains(&c.as_str())));
        }
    }
    #[test]
    fn failed_vm_reboot_marker_precedes_enqueue_and_allows_ordinary_abort() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        coordinator.prepare(true).expect("prepare");
        backend.state.borrow_mut().calls.clear();
        backend.state.borrow_mut().fail = Some("mark-vm-reboot".into());
        assert!(coordinator.reboot(Some(window()), true).is_err());
        assert_eq!(
            coordinator.load().expect("intent")["pending"]["phase"],
            "ready"
        );
        let state = backend.state.borrow();
        assert!(!state.calls.iter().any(|c| c == "reboot"));
        assert!(state.calls.iter().any(|c| c == "restore-vms"));
    }
    #[test]
    fn post_enqueue_journal_failure_preserves_intent_without_ordinary_abort() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        coordinator.prepare(true).expect("prepare");
        {
            let mut state = backend.state.borrow_mut();
            state.calls.clear();
            state.uncertain = true;
            state.fail_journal_after_enqueue = Some(coordinator.path.clone());
        }
        assert!(coordinator.reboot(Some(window()), true).is_err());
        assert_eq!(
            read_json(coordinator.path.with_extension("retained.json")).unwrap()["pending"]["phase"],
            "booting"
        );
        let state = backend.state.borrow();
        assert!(state.calls.iter().any(|c| c == "reboot"));
        assert!(
            !state
                .calls
                .iter()
                .any(|c| ["protect", "pin", "restore-vms"].contains(&c.as_str()))
        );
    }
    #[test]
    fn refusal_clock_step_and_unqueued_reboot_restore_owned_vms() {
        for mode in ["refusal", "step", "queue"] {
            let directory = tempfile::tempdir().expect("state");
            let backend = Fake::new();
            let coordinator = Coordinator::new(directory.path(), &backend);
            coordinator.prepare(true).expect("prepare");
            match mode {
                "refusal" => backend.state.borrow_mut().refuse = true,
                "step" => backend.state.borrow_mut().step = true,
                _ => backend.state.borrow_mut().queue = false,
            };
            let result = coordinator.reboot(Some(window()), true);
            if mode == "queue" {
                assert!(result.is_err());
            } else {
                assert_eq!(result.expect("deferred")["action"], "deferred");
            }
            assert!(
                backend
                    .state
                    .borrow()
                    .calls
                    .iter()
                    .any(|v| v == "restore-vms")
            );
            assert_eq!(
                coordinator.load().expect("state")["pending"]["phase"],
                "ready"
            );
        }
    }
    #[test]
    fn failed_blessing_keeps_fallback_quarantine_authority() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        coordinator.prepare(true).expect("prepare");
        coordinator.reboot(Some(window()), true).expect("activate");
        backend.state.borrow_mut().current = "45.0.1.2-1.1".into();
        backend.state.borrow_mut().boot = "candidate".into();
        coordinator.assess().expect("assess");
        backend.state.borrow_mut().fail = Some("bless".into());
        assert!(coordinator.bless().is_err());
        backend.state.borrow_mut().fail = None;
        backend.state.borrow_mut().current = "45.0.1.1-1.1".into();
        backend.state.borrow_mut().boot = "fallback".into();
        coordinator.runtime_guard().expect("guard");
        let state = coordinator.load().expect("state");
        assert_eq!(
            state["rejected"]["45.0.1.2-1.1"],
            "fallback after activation"
        );
        assert!(state["pending"].is_null());
        let calls = &backend.state.borrow().calls;
        assert!(
            calls
                .iter()
                .position(|v| v == "reject-45.0.1.2-1.1")
                .expect("reject")
                < calls
                    .iter()
                    .rposition(|v| v == "daemon-state")
                    .expect("daemon")
        );
    }
    #[test]
    fn maintenance_only_pins_and_failed_esp_write_still_inhibits() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        backend.state.borrow_mut().fail = Some("pin".into());
        let result = coordinator
            .maintenance(Some("supervised firmware"), false)
            .expect("inhibited");
        assert_eq!(result["maintenance"]["reason"], "supervised firmware");
        assert_eq!(backend.state.borrow().calls, vec!["pin"]);
        assert_eq!(
            coordinator.prepare(true).expect("deferred")["action"],
            "deferred"
        );
    }
    #[test]
    fn summer_winter_dst_and_missed_windows_have_no_catch_up() {
        for utc in ["2026-03-29T02:30:00Z", "2026-10-25T03:30:00Z"] {
            let now = utc.parse().expect("fixed date");
            assert!(reboot_window(now, 60));
            assert!(!reboot_window(now - chrono::Duration::minutes(1), 60));
            assert!(!reboot_window(now + chrono::Duration::minutes(1), 60));
        }
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        coordinator.prepare(true).expect("prepare");
        assert_eq!(
            coordinator
                .reboot(Some(window() + chrono::Duration::hours(1)), true)
                .expect("defer")["action"],
            "deferred"
        );
        assert!(
            !backend
                .state
                .borrow()
                .calls
                .iter()
                .any(|v| v == "freeze-vms")
        );
    }
    #[test]
    fn manual_activation_retains_each_live_authority_guard() {
        for blocked in ["firmware", "storage", "memory", "time"] {
            let directory = tempfile::tempdir().expect("state");
            let backend = Fake::new();
            let coordinator = Coordinator::new(directory.path(), &backend);
            backend.state.borrow_mut().blocked = Some("commissioned".into());
            assert_eq!(
                coordinator.prepare(true).expect("automatic deferred")["action"],
                "deferred"
            );
            coordinator.prepare(false).expect("supervised preparation");
            backend.state.borrow_mut().blocked = Some(blocked.into());
            assert_eq!(
                coordinator.reboot(None, false).expect("manual deferred")["action"],
                "deferred"
            );
            assert!(
                !backend
                    .state
                    .borrow()
                    .calls
                    .iter()
                    .any(|call| call == "freeze-vms")
            );
            assert!(
                !backend
                    .state
                    .borrow()
                    .calls
                    .iter()
                    .any(|call| call == "reboot")
            );
        }
    }
    #[test]
    fn missing_journal_authority_or_lost_disk_prevents_guest_shutdown() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        write_json(
            &coordinator.path,
            &json!({"schema":1,"pending":null,"accepted":[],"rejected":{}}),
        )
        .expect("corrupt journal");
        assert!(coordinator.prepare(false).is_err());
        assert!(backend.state.borrow().calls.is_empty());
        std::fs::remove_file(&coordinator.path).expect("reset isolated journal");
        coordinator.prepare(false).expect("prepare");
        backend.state.borrow_mut().disks.remove("b");
        assert!(coordinator.reboot(None, false).is_err());
        assert!(
            !backend
                .state
                .borrow()
                .calls
                .iter()
                .any(|call| call == "freeze-vms")
        );
    }
    #[test]
    fn every_preparation_guard_defers_before_any_transfer() {
        for blocked in ["firmware", "storage", "schema", "memory", "commissioned"] {
            let directory = tempfile::tempdir().expect("state");
            let backend = Fake::new();
            backend.state.borrow_mut().blocked = Some(blocked.into());
            let coordinator = Coordinator::new(directory.path(), &backend);
            assert_eq!(
                coordinator.prepare(true).expect("defer")["action"],
                "deferred"
            );
            assert!(
                !backend
                    .state
                    .borrow()
                    .calls
                    .iter()
                    .any(|call| call.starts_with("transfer-"))
            );
        }
    }
    #[test]
    fn maintenance_preserves_pending_state_requires_review_and_holds_shared_lock() {
        for prepared in [false, true] {
            let directory = tempfile::tempdir().expect("state");
            let backend = Fake::new();
            let coordinator = Coordinator::new(directory.path(), &backend);
            if prepared {
                coordinator.prepare(false).expect("prepare");
            }
            let pending = coordinator.load().expect("state")["pending"].clone();
            let before = backend.state.borrow().calls.len();
            coordinator
                .maintenance(Some("firmware"), false)
                .expect("maintenance");
            assert_eq!(&backend.state.borrow().calls[before..], &["pin"]);
            assert_eq!(coordinator.load().expect("state")["pending"], pending);
            assert_eq!(
                coordinator.prepare(false).expect("deferred")["action"],
                "deferred"
            );
            assert!(coordinator.maintenance(None, false).is_err());
            coordinator.maintenance(None, true).expect("reviewed");
            let _ownership = lock(directory.path()).expect("lock");
            assert!(coordinator.prepare(false).expect_err("busy").deferred);
        }
    }
    #[test]
    fn same_boot_does_not_imply_fallback_and_changed_release_cannot_resume() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        let coordinator = Coordinator::new(directory.path(), &backend);
        coordinator.prepare(false).expect("prepare");
        coordinator.reboot(None, false).expect("activate");
        assert!(
            coordinator.runtime_guard().is_err(),
            "same-boot reboot intent is still authoritative"
        );
        assert_eq!(coordinator.load().expect("state")["rejected"], json!({}));
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        backend.state.borrow_mut().fail = Some("transferred-a".into());
        let coordinator = Coordinator::new(directory.path(), &backend);
        assert!(coordinator.prepare(false).is_err());
        backend.state.borrow_mut().fail = None;
        backend.state.borrow_mut().content_changed = true;
        assert!(
            coordinator
                .prepare(false)
                .expect_err("immutable release")
                .message
                .contains("content changed")
        );
    }
    #[test]
    fn no_update_corrected_daytime_and_post_shutdown_firmware_never_queue_reboots() {
        let directory = tempfile::tempdir().expect("state");
        let backend = Fake::new();
        backend.state.borrow_mut().latest = "45.0.1.1-1.1".into();
        let coordinator = Coordinator::new(directory.path(), &backend);
        assert_eq!(
            coordinator.prepare(false).expect("not newer")["reason"],
            "no newer OS release"
        );
        assert_eq!(
            coordinator.reboot(None, false).expect("not pending")["action"],
            "deferred"
        );
        backend.state.borrow_mut().latest = "45.0.1.2-1.1".into();
        coordinator.prepare(false).expect("prepare");
        backend.state.borrow_mut().corrected_wall = Some(1793939400.);
        assert!(
            coordinator
                .reboot(Some(window()), true)
                .expect("corrected clock")["reason"]
                .as_str()
                .expect("reason")
                .contains("after authenticated time inspection")
        );
        assert!(
            !backend
                .state
                .borrow()
                .calls
                .iter()
                .any(|call| call == "freeze-vms")
        );
        backend.state.borrow_mut().corrected_wall = None;
        backend.state.borrow_mut().stop_block = Some("firmware".into());
        assert_eq!(
            coordinator.reboot(None, false).expect("staged firmware")["action"],
            "deferred"
        );
        assert!(
            backend
                .state
                .borrow()
                .calls
                .iter()
                .any(|call| call == "restore-vms")
        );
        assert!(
            !backend
                .state
                .borrow()
                .calls
                .iter()
                .any(|call| call == "reboot")
        );
    }
}
