//! Native vmspawn maintenance, with durable intent and no forced guest termination.
use crate::common::{
    Error, Result, atomic_write, command, field, list, parse_json, read_bounded, read_json,
    require, text, write_json,
};
use crate::confinement::{matches, own_cgroup, verify_processes};
use crate::processes::{Identity, Process};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;
pub const GATE: &str = "/run/particleve/vm-start-inhibited";
pub const DROPIN: &str =
    "/run/systemd/system/systemd-vmspawn@.service.d/zz-particleve-maintenance.conf";
pub fn valid_unit(unit: &str) -> Result<bool> {
    matches(r"\Asystemd-vmspawn@[A-Za-z0-9_.:\\-]+\.service\z", unit)
}
fn native(args: &[String], seconds: u64, check: bool) -> Result<crate::common::Output> {
    command(
        args,
        None,
        Some(Duration::from_secs(seconds)),
        8 * 1024 * 1024,
        check,
    )
}
pub fn properties(command: &str, name: &str, fields: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut args = vec![command.to_owned(), "show".into(), name.into()];
    args.extend(fields.iter().map(|s| format!("--property={s}")));
    Ok(native(&args, 15, true)?
        .stdout
        .lines()
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect())
}
pub fn process_identity(pid: u32, proc: &Path) -> Result<Option<Identity>> {
    match Process::open(pid, None, proc).and_then(|p| p.identity()) {
        Ok(id) => Ok(Some(id)),
        Err(e) if e.is_not_found() || e.is_errno(libc::ESRCH) => Ok(None),
        Err(e) => Err(e),
    }
}
pub fn unit_state(unit: &str) -> Result<BTreeMap<String, String>> {
    require(
        valid_unit(unit)?,
        "VM is not owned by the packaged vmspawn template",
    )?;
    properties(
        "systemctl",
        unit,
        &[
            "ActiveState",
            "SubState",
            "MainPID",
            "ControlGroup",
            "InvocationID",
            "Restart",
            "RefuseManualStart",
            "ExecStart",
            "ExecStartPre",
        ],
    )
}
pub fn cgroup_processes(cgroup: &str) -> Result<Vec<Identity>> {
    cgroup_processes_at(cgroup, Path::new("/sys/fs/cgroup"), Path::new("/proc"))
}
pub fn cgroup_processes_at(cgroup: &str, root: &Path, proc: &Path) -> Result<Vec<Identity>> {
    require(
        cgroup.starts_with('/') && !cgroup.split('/').any(|s| s == ".."),
        "invalid VM cgroup",
    )?;
    let root = root.join(cgroup.trim_start_matches('/'));
    match root.metadata() {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut directories = vec![root];
    let mut pids = BTreeSet::new();
    let mut visited = 0;
    while let Some(directory) = directories.pop() {
        visited += 1;
        require(
            visited <= 65536,
            "VM cgroup inventory exceeds its directory bound",
        )?;
        let path = directory.join("cgroup.procs");
        match read_bounded(path, 1024 * 1024) {
            Ok(bytes) => {
                for value in String::from_utf8(bytes)?.lines() {
                    let pid = value
                        .parse::<u32>()
                        .map_err(|_| Error::new("invalid VM cgroup PID"))?;
                    require(pid > 0, "invalid VM cgroup PID")?;
                    pids.insert(pid);
                    require(
                        pids.len() <= 65536,
                        "VM process inventory exceeds its bound",
                    )?;
                }
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    let mut result = Vec::new();
    for pid in pids {
        if let Some(id) = process_identity(pid, proc)? {
            result.push(id);
        }
    }
    Ok(result)
}
pub fn qemu_processes() -> Result<Vec<Identity>> {
    let mut result = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let path = entry?.path();
        let Some(pid) = path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let link = match fs::read_link(path.join("exe")) {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => continue,
            Err(e) => return Err(e.into()),
        };
        let Some(name) = link.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with("qemu-system-") || name == "qemu-kvm" {
            let id = process_identity(pid, Path::new("/proc"))?
                .ok_or_else(|| Error::new("QEMU inventory changed"))?;
            result.push(id);
        }
    }
    Ok(result)
}
pub fn stop_instance(name: &str) -> Result<()> {
    let unit = format!("systemd-vmspawn@{name}.service");
    require(valid_unit(&unit)?, "invalid vmspawn instance")?;
    let group = own_cgroup()?;
    require(
        Path::new(&group).file_name().and_then(|s| s.to_str()) == Some(unit.as_str()),
        "VM stop helper must run in its owning unit",
    )?;
    await_graceful_exit(
        || {
            Ok(cgroup_processes(&group)?
                .iter()
                .any(|p| p.pid != std::process::id()))
        },
        || {
            Ok(native(
                &["machinectl", "poweroff", "--", name].map(str::to_owned),
                15,
                false,
            )?
            .code
                == 0)
        },
        || std::thread::sleep(Duration::from_secs(1)),
        |message| eprintln!("{message}"),
    )
}
fn await_graceful_exit<R, A, P, N>(
    mut remaining: R,
    mut poweroff: A,
    mut pause: P,
    mut notice: N,
) -> Result<()>
where
    R: FnMut() -> Result<bool>,
    A: FnMut() -> Result<bool>,
    P: FnMut(),
    N: FnMut(&str),
{
    if !remaining()? {
        return Ok(());
    }
    match poweroff() {
        Ok(false) => {
            notice("Graceful VM poweroff request failed; waiting for owner-assisted guest exit")
        }
        Err(error) => notice(&format!(
            "Graceful VM poweroff request failed: {error}; waiting for owner-assisted guest exit"
        )),
        Ok(true) => {}
    }
    // No signal or final kill deadline: the cgroup must actually become empty.
    while remaining()? {
        pause();
    }
    Ok(())
}
fn managed_vm(machine: &Value) -> Result<bool> {
    if machine["machine"] == ".host" && machine["class"] == "host" {
        return Ok(false);
    }
    if machine["class"] != "vm" {
        return Err(Error::deferred(
            "unexpected host container; VM maintenance inventory is incomplete",
        ));
    }
    require(
        machine["service"] == "systemd-vmspawn",
        "unmanaged VM runner present",
    )?;
    Ok(true)
}
fn invocation_liveness(original: bool, active: bool, same: bool) -> (bool, bool) {
    (original || (same && active), active && !same)
}
pub trait VmPlatform {
    fn inhibit(&self) -> Result<()>;
    fn release(&self) -> Result<()>;
    fn jobs(&self) -> Result<Vec<String>>;
    fn inventory(&self, inhibited: bool) -> Result<Vec<Value>>;
    fn alive(&self, entry: &Value) -> Result<(bool, bool)>;
    fn poweroff(&self, entry: &Value) -> Result<()>;
    fn start(&self, entry: &Value) -> Result<()>;
    fn empty(&self) -> Result<()>;
    fn normal_operation(&self) -> Result<bool>;
    fn clock(&self) -> f64;
    fn pause(&self, duration: Duration);
}
pub struct LinuxVMs;
fn prop<'a>(props: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    props
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| Error::new(format!("incomplete native VM property: {name}")))
}
impl VmPlatform for LinuxVMs {
    fn inhibit(&self) -> Result<()> {
        atomic_write(GATE, b"OS maintenance in progress\n", 0o600)?;
        atomic_write(DROPIN,b"[Unit]\nRefuseManualStart=yes\nConditionPathExists=!/run/particleve/vm-start-inhibited\n[Service]\nRestart=no\n",0o644)?;
        native(
            &["systemctl", "daemon-reload"].map(str::to_owned),
            120,
            true,
        )?;
        Ok(())
    }
    fn release(&self) -> Result<()> {
        match fs::remove_file(DROPIN) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        native(
            &["systemctl", "daemon-reload"].map(str::to_owned),
            120,
            true,
        )?;
        match fs::remove_file(GATE) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let parent = Path::new(GATE)
            .parent()
            .ok_or_else(|| Error::new("missing VM gate parent"))?;
        if parent.try_exists()? {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    fn jobs(&self) -> Result<Vec<String>> {
        Ok(native(
            &[
                "systemctl",
                "list-jobs",
                "--no-legend",
                "--no-pager",
                "--full",
            ]
            .map(str::to_owned),
            15,
            true,
        )?
        .stdout
        .lines()
        .filter(|s| s.contains("systemd-vmspawn@"))
        .map(str::to_owned)
        .collect())
    }
    fn inventory(&self, inhibited: bool) -> Result<Vec<Value>> {
        let response = native(
            &[
                "systemctl",
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--no-pager",
                "--full",
                "systemd-vmspawn@*.service",
            ]
            .map(str::to_owned),
            15,
            true,
        )?;
        let mut units = BTreeMap::new();
        for line in response.stdout.lines().filter(|s| !s.trim().is_empty()) {
            let name = line
                .split_whitespace()
                .next()
                .ok_or_else(|| Error::new("invalid VM unit inventory"))?;
            units.insert(name.to_owned(), unit_state(name)?);
        }
        require(
            self.jobs()?.is_empty(),
            "VM start/restart jobs have not settled",
        )?;
        let response = native(
            &["machinectl", "--all", "--output=json", "list"].map(str::to_owned),
            15,
            true,
        )?;
        let machines = parse_json(response.stdout.as_bytes())?;
        let mut result = Vec::new();
        for machine in list(&machines)? {
            if !managed_vm(machine)? {
                continue;
            }
            let name = text(field(machine, "machine")?)?;
            let info = properties("machinectl", name, &["Unit", "Leader", "Class", "Service"])?;
            let unit = prop(&info, "Unit")?;
            require(
                units.contains_key(unit) && valid_unit(unit)?,
                "VM registration does not match an owning template unit",
            )?;
            let state = &units[unit];
            require(
                prop(state, "ActiveState")? == "active" && prop(state, "SubState")? == "running",
                "VM unit is transitioning",
            )?;
            let exec = prop(state, "ExecStart")?;
            require(
                ["systemd-vmspawn", "--register=yes", "--keep-unit"]
                    .iter()
                    .all(|s| exec.contains(s)),
                "external unit must preserve vmspawn registration and ownership",
            )?;
            require(
                prop(state, "ExecStartPre")?.contains("vm-start-guard"),
                "VM start guard was removed by external configuration",
            )?;
            require(
                exec.contains("path=/usr/libexec/particleve-vm-run "),
                "native VM lifecycle supervisor was removed by external configuration",
            )?;
            if inhibited {
                require(
                    prop(state, "RefuseManualStart")? == "yes" && prop(state, "Restart")? == "no",
                    "temporary VM inhibition was overridden",
                )?;
            }
            let processes = cgroup_processes(prop(state, "ControlGroup")?)?;
            verify_processes(&processes, Path::new("/proc"))?;
            let leader: u32 = prop(&info, "Leader")?
                .parse()
                .map_err(|_| Error::new("invalid VM leader PID"))?;
            require(
                processes.iter().any(|p| p.pid == leader),
                "QEMU leader is not in its owning unit",
            )?;
            result.push(json!({"machine":name,"unit":unit,"invocation":prop(state,"InvocationID")?,"cgroup":prop(state,"ControlGroup")?,"processes":processes}));
        }
        let mut active = BTreeSet::new();
        for (name, state) in &units {
            let pid: u32 = prop(state, "MainPID")?
                .parse()
                .map_err(|_| Error::new("invalid VM main PID"))?;
            if ["active", "activating", "deactivating"].contains(&prop(state, "ActiveState")?)
                || pid != 0
            {
                active.insert(name.as_str());
            }
        }
        let registered = result
            .iter()
            .map(|e| text(&e["unit"]))
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            active == registered,
            "unit/process state and machined registrations differ",
        )?;
        let mut owned = BTreeSet::new();
        for machine in &result {
            for process in list(&machine["processes"])? {
                owned.insert(
                    process["pid"]
                        .as_u64()
                        .ok_or_else(|| Error::new("invalid VM process identity"))?,
                );
            }
        }
        require(
            qemu_processes()?
                .iter()
                .all(|p| owned.contains(&u64::from(p.pid))),
            "QEMU process exists outside registered vmspawn units",
        )?;
        Ok(result)
    }
    fn alive(&self, entry: &Value) -> Result<(bool, bool)> {
        let mut original = false;
        for process in list(field(entry, "processes")?)? {
            let identity: Identity = serde_json::from_value(process.clone())?;
            original |= process_identity(identity.pid, Path::new("/proc"))? == Some(identity);
        }
        let state = unit_state(text(field(entry, "unit")?)?)?;
        let active = !cgroup_processes(text(field(entry, "cgroup")?)?)?.is_empty()
            || ["active", "activating", "deactivating"].contains(&prop(&state, "ActiveState")?);
        let same = prop(&state, "InvocationID")? == text(field(entry, "invocation")?)?;
        Ok(invocation_liveness(original, active, same))
    }
    fn poweroff(&self, entry: &Value) -> Result<()> {
        native(
            &[
                "machinectl",
                "poweroff",
                "--",
                text(field(entry, "machine")?)?,
            ]
            .map(str::to_owned),
            15,
            true,
        )?;
        Ok(())
    }
    fn start(&self, entry: &Value) -> Result<()> {
        let (original, replacement) = self.alive(entry)?;
        if original || replacement {
            return Ok(());
        }
        let unit = text(field(entry, "unit")?)?;
        native(&["systemctl", "start", unit].map(str::to_owned), 120, true)?;
        let state = unit_state(unit)?;
        require(
            prop(&state, "ActiveState")? == "active"
                && prop(&state, "MainPID")?
                    .parse::<u32>()
                    .map_err(|_| Error::new("invalid VM main PID"))?
                    > 0,
            format!("VM restoration did not reach running state: {unit}"),
        )
    }
    fn empty(&self) -> Result<()> {
        require(self.jobs()?.is_empty(), "a VM start/restart is pending")?;
        require(
            self.inventory(true)?.is_empty() && qemu_processes()?.is_empty(),
            "VM processes have not all exited",
        )
    }
    fn normal_operation(&self) -> Result<bool> {
        Ok(["running", "degraded"].contains(
            &native(
                &["systemctl", "is-system-running"].map(str::to_owned),
                10,
                false,
            )?
            .stdout
            .trim(),
        ))
    }
    fn clock(&self) -> f64 {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }; // SAFETY: clock_gettime fills this correctly sized record; CLOCK_MONOTONIC is mandatory on supported Linux.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
        assert_eq!(result, 0, "CLOCK_MONOTONIC unavailable");
        value.tv_sec as f64 + value.tv_nsec as f64 / 1e9
    }
    fn pause(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
pub struct Shutdown<P: VmPlatform> {
    pub path: PathBuf,
    pub platform: P,
    pub boot_id: String,
    graceful_seconds: u64,
    restore_seconds: u64,
}
impl<P: VmPlatform> Shutdown<P> {
    pub fn new(
        directory: &Path,
        platform: P,
        boot_id: &str,
        graceful_seconds: u64,
        restore_seconds: u64,
    ) -> Self {
        Self {
            path: directory.join("vm-shutdown.json"),
            platform,
            boot_id: boot_id.into(),
            graceful_seconds,
            restore_seconds,
        }
    }
    fn save(&self, record: &Value) -> Result<()> {
        write_json(&self.path, record)
    }
    pub fn freeze(&self) -> Result<()> {
        if self.path.try_exists()? {
            let previous = read_json(&self.path)?;
            require(
                ["restored", "reboot-completed"].contains(&text(field(&previous, "phase")?)?),
                "previous VM shutdown attempt needs reconciliation",
            )?;
        }
        let mut record = json!({"schema":1,"boot_id":self.boot_id,"phase":"inhibiting","running":[],"requested":[],"restored":[],"failures":[]});
        self.save(&record)?;
        self.platform.inhibit()?;
        let deadline = self.platform.clock() + self.graceful_seconds.min(60) as f64;
        while !self.platform.jobs()?.is_empty() {
            require(
                self.platform.clock() < deadline,
                "concurrent VM starts/restarts did not settle",
            )?;
            self.platform.pause(Duration::from_secs(1));
        }
        record["running"] = json!(self.platform.inventory(true)?);
        record["phase"] = json!("frozen");
        self.save(&record)
    }
    pub fn stop(&self) -> Result<()> {
        let mut record = read_json(&self.path)?;
        require(
            record["phase"] == "frozen",
            "VM inventory has not been frozen",
        )?;
        record["phase"] = json!("stopping");
        record["deadline"] = json!(self.platform.clock() + self.graceful_seconds as f64);
        self.save(&record)?;
        let running = list(field(&record, "running")?)?.clone();
        for entry in &running {
            record["requested"]
                .as_array_mut()
                .ok_or_else(|| Error::new("invalid VM shutdown requests"))?
                .push(field(entry, "unit")?.clone());
            self.save(&record)?;
            self.platform.poweroff(entry)?;
        }
        loop {
            let observations = running
                .iter()
                .map(|e| self.platform.alive(e))
                .collect::<Result<Vec<_>>>()?;
            require(
                !observations.iter().any(|(_, replacement)| *replacement),
                "a VM restarted despite inhibition",
            )?;
            if !observations.iter().any(|(original, _)| *original) {
                self.platform.empty()?;
                record["phase"] = json!("stopped");
                return self.save(&record);
            }
            if self.platform.clock()
                >= record["deadline"]
                    .as_f64()
                    .ok_or_else(|| Error::new("invalid VM shutdown deadline"))?
            {
                return Err(Error::deferred(
                    "VM refused graceful poweroff; host reboot cancelled",
                ));
            }
            self.platform.pause(Duration::from_secs(1));
        }
    }
    pub fn assert_empty(&self) -> Result<()> {
        require(
            read_json(&self.path)?["phase"] == "stopped",
            "VM shutdown is incomplete",
        )?;
        self.platform.empty()
    }
    pub fn mark_reboot(&self) -> Result<()> {
        let mut record = read_json(&self.path)?;
        record["phase"] = json!("reboot-requested");
        self.save(&record)
    }
    pub fn recover(&self) -> Result<Value> {
        if !self.path.try_exists()? {
            return Ok(json!({"action":"nothing-to-recover"}));
        }
        let mut record = read_json(&self.path)?;
        require(
            record["schema"] == json!(1),
            "unknown VM shutdown transaction schema",
        )?;
        if record["boot_id"] != self.boot_id {
            let previous = record["phase"].clone();
            self.platform.release()?;
            record["phase"] = json!("reboot-completed");
            self.save(&record)?;
            return Ok(json!({"action":"external-startup-policy","previous_phase":previous}));
        }
        if ["restored", "reboot-completed"].contains(&text(field(&record, "phase")?)?) {
            return Ok(json!({"action":record["phase"]}));
        }
        if !self.platform.normal_operation()? {
            record["failures"] =
                json!(["host is shutting down or normal operation cannot be confirmed"]);
            self.save(&record)?;
            return Ok(json!({"action":"restoration-deferred","failures":record["failures"]}));
        }
        record["phase"] = json!("restoring");
        if record.get("restore_deadline").is_none() {
            record["restore_deadline"] = json!(self.platform.clock() + self.restore_seconds as f64);
        }
        self.save(&record)?;
        self.platform.release()?;
        let requested = list(field(&record, "requested")?)?;
        let restored = list(field(&record, "restored")?)?;
        let mut pending: Vec<_> = list(field(&record, "running")?)?
            .iter()
            .filter(|e| requested.contains(&e["unit"]) && !restored.contains(&e["unit"]))
            .cloned()
            .collect();
        let mut failures = BTreeMap::new();
        while !pending.is_empty() {
            for entry in pending.clone() {
                let (original, replacement) = self.platform.alive(&entry)?;
                if original {
                    continue;
                }
                let result = if replacement {
                    Ok(())
                } else {
                    self.platform.start(&entry)
                };
                match result {
                    Ok(()) => {
                        record["restored"]
                            .as_array_mut()
                            .ok_or_else(|| Error::new("invalid restored VM list"))?
                            .push(entry["unit"].clone());
                        pending.retain(|e| e != &entry);
                        self.save(&record)?;
                    }
                    Err(e) => {
                        failures.insert(text(field(&entry, "unit")?)?.to_owned(), e.to_string());
                    }
                }
            }
            if pending.is_empty()
                || self.platform.clock()
                    >= record["restore_deadline"]
                        .as_f64()
                        .ok_or_else(|| Error::new("invalid VM restore deadline"))?
            {
                break;
            }
            self.platform.pause(Duration::from_secs(1));
        }
        let mut messages = Vec::new();
        for entry in &pending {
            let unit = text(field(entry, "unit")?)?;
            messages.push(failures.get(unit).cloned().unwrap_or_else(|| {
                format!("{unit}: still running after ACPI; late exit needs review")
            }));
        }
        record["failures"] = json!(messages);
        record["phase"] = json!(if pending.is_empty() {
            "restored"
        } else {
            "restoration-failed"
        });
        self.save(&record)?;
        Ok(
            json!({"action":record["phase"],"restored":record["restored"],"failures":record["failures"]}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Fake {
        now: Cell<f64>,
        inhibited: Cell<bool>,
        delays: RefCell<BTreeMap<String, Option<f64>>>,
        exits: RefCell<BTreeMap<String, Option<f64>>>,
        started: RefCell<Vec<String>>,
        replacement: RefCell<BTreeSet<String>>,
        fail_start: RefCell<BTreeSet<String>>,
        inventory_failure: Cell<bool>,
        normal: Cell<bool>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                now: Cell::new(0.0),
                inhibited: Cell::new(false),
                delays: RefCell::new(BTreeMap::new()),
                exits: RefCell::new(BTreeMap::new()),
                started: RefCell::new(Vec::new()),
                replacement: RefCell::new(BTreeSet::new()),
                fail_start: RefCell::new(BTreeSet::new()),
                inventory_failure: Cell::new(false),
                normal: Cell::new(true),
            }
        }
        fn entries() -> Vec<Value> {
            ["a","b"].into_iter().map(|name|json!({"unit":name,"machine":name,"processes":[],"invocation":"original"})).collect()
        }
    }
    impl VmPlatform for Fake {
        fn inhibit(&self) -> Result<()> {
            self.inhibited.set(true);
            Ok(())
        }
        fn release(&self) -> Result<()> {
            self.inhibited.set(false);
            Ok(())
        }
        fn jobs(&self) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn inventory(&self, _: bool) -> Result<Vec<Value>> {
            if self.inventory_failure.get() {
                Err(Error::new("unregistered QEMU process"))
            } else {
                Ok(Self::entries())
            }
        }
        fn alive(&self, entry: &Value) -> Result<(bool, bool)> {
            let name = text(&entry["unit"])?;
            let original = self
                .exits
                .borrow()
                .get(name)
                .copied()
                .flatten()
                .is_none_or(|deadline| self.now.get() < deadline);
            Ok((original, self.replacement.borrow().contains(name)))
        }
        fn poweroff(&self, entry: &Value) -> Result<()> {
            let name = text(&entry["unit"])?;
            let deadline = self
                .delays
                .borrow()
                .get(name)
                .copied()
                .unwrap_or(Some(0.0))
                .map(|delay| self.now.get() + delay);
            self.exits.borrow_mut().insert(name.into(), deadline);
            Ok(())
        }
        fn start(&self, entry: &Value) -> Result<()> {
            assert!(!self.inhibited.get());
            let name = text(&entry["unit"])?;
            if self.fail_start.borrow().contains(name) {
                return Err(Error::new("start failed"));
            }
            if self.replacement.borrow_mut().insert(name.into()) {
                self.started.borrow_mut().push(name.into());
            }
            Ok(())
        }
        fn empty(&self) -> Result<()> {
            for entry in Self::entries() {
                let (original, replacement) = self.alive(&entry)?;
                require(!original && !replacement, "VM process still alive")?;
            }
            Ok(())
        }
        fn normal_operation(&self) -> Result<bool> {
            Ok(self.normal.get())
        }
        fn clock(&self) -> f64 {
            self.now.get()
        }
        fn pause(&self, duration: Duration) {
            self.now.set(self.now.get() + duration.as_secs_f64());
        }
    }
    #[test]
    fn graceful_transaction_waits_for_real_exit_and_preserves_gate() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot1", 5, 5);
        shutdown
            .platform
            .delays
            .borrow_mut()
            .insert("a".into(), Some(3.0));
        shutdown.freeze().unwrap();
        shutdown.stop().unwrap();
        shutdown.assert_empty().unwrap();
        assert_eq!(shutdown.platform.now.get(), 3.0);
        assert!(shutdown.platform.inhibited.get());
        shutdown.mark_reboot().unwrap();
        let next = Shutdown::new(directory.path(), shutdown.platform, "boot2", 5, 5);
        assert_eq!(next.recover().unwrap()["action"], "external-startup-policy");
        assert!(!next.platform.inhibited.get());
        assert!(next.platform.started.borrow().is_empty());
    }
    #[test]
    fn refusal_restores_only_exited_guests_and_reports_late_uncertainty() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown
            .platform
            .delays
            .borrow_mut()
            .insert("a".into(), None);
        shutdown.freeze().unwrap();
        assert!(shutdown.stop().unwrap_err().deferred);
        let result = shutdown.recover().unwrap();
        assert_eq!(result["action"], "restoration-failed");
        assert_eq!(*shutdown.platform.started.borrow(), ["b"]);
        assert!(result["failures"][0].as_str().unwrap().contains("a:"));
        assert!(shutdown.freeze().is_err());
    }
    #[test]
    fn late_exit_is_restored_and_recovery_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown
            .platform
            .delays
            .borrow_mut()
            .insert("a".into(), Some(7.0));
        shutdown.freeze().unwrap();
        assert!(shutdown.stop().unwrap_err().deferred);
        assert_eq!(shutdown.recover().unwrap()["action"], "restored");
        assert_eq!(shutdown.recover().unwrap()["action"], "restored");
        assert_eq!(shutdown.platform.started.borrow().len(), 2);
    }
    #[test]
    fn ambiguous_inventory_never_touches_guests() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown.platform.inventory_failure.set(true);
        assert!(shutdown.freeze().is_err());
        assert_eq!(shutdown.recover().unwrap()["action"], "restored");
        assert!(shutdown.platform.exits.borrow().is_empty());
        assert!(shutdown.platform.started.borrow().is_empty());
    }
    #[test]
    fn host_shutdown_never_starts_guests() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown.freeze().unwrap();
        shutdown.stop().unwrap();
        shutdown.platform.normal.set(false);
        assert_eq!(
            shutdown.recover().unwrap()["action"],
            "restoration-deferred"
        );
        assert!(shutdown.platform.started.borrow().is_empty());
    }
    #[test]
    fn interrupted_attempt_resumes_from_disk_and_new_invocations_are_left_alone() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown.freeze().unwrap();
        shutdown.stop().unwrap();
        let resumed = Shutdown::new(directory.path(), shutdown.platform, "boot", 5, 5);
        assert_eq!(resumed.recover().unwrap()["action"], "restored");
        assert_eq!(resumed.recover().unwrap()["action"], "restored");
        assert_eq!(resumed.platform.started.borrow().len(), 2);
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown.freeze().unwrap();
        shutdown
            .platform
            .replacement
            .borrow_mut()
            .insert("a".into());
        assert!(
            shutdown
                .stop()
                .unwrap_err()
                .message
                .contains("restarted despite inhibition")
        );
        assert_eq!(shutdown.recover().unwrap()["action"], "restored");
        assert!(!shutdown.platform.started.borrow().contains(&"a".to_owned()));
    }
    #[test]
    fn failed_restoration_is_durable() {
        let directory = tempfile::tempdir().unwrap();
        let shutdown = Shutdown::new(directory.path(), Fake::new(), "boot", 5, 5);
        shutdown.freeze().unwrap();
        shutdown.stop().unwrap();
        shutdown.platform.fail_start.borrow_mut().insert("a".into());
        assert_eq!(shutdown.recover().unwrap()["action"], "restoration-failed");
        assert!(
            !list(&read_json(&shutdown.path).unwrap()["failures"])
                .unwrap()
                .is_empty()
        );
        assert!(shutdown.freeze().is_err());
    }
    #[test]
    fn only_confirmed_process_disappearance_is_absence() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(process_identity(123, directory.path()).unwrap(), None);
        fs::create_dir(directory.path().join("123")).unwrap();
        fs::write(directory.path().join("123/stat"), "123 (qemu) S").unwrap();
        assert!(process_identity(123, directory.path()).is_err());
        assert!(process_identity(0, directory.path()).is_err());
    }
}

#[cfg(test)]
mod replacement_tests {
    use super::*;
    #[test]
    fn cgroup_identity_handles_parentheses_and_reuse() {
        let root = tempfile::tempdir().unwrap();
        let proc = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("test")).unwrap();
        fs::write(root.path().join("test/cgroup.procs"), "123\n123\n").unwrap();
        fs::create_dir(proc.path().join("123")).unwrap();
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "77";
        fs::write(
            proc.path().join("123/stat"),
            format!("123 (qemu (strange) name) {}", fields.join(" ")),
        )
        .unwrap();
        let identities = cgroup_processes_at("/test", root.path(), proc.path()).unwrap();
        assert_eq!(
            identities,
            [Identity {
                pid: 123,
                starttime: 77
            }]
        );
        assert!(Process::open(123, Some(78), proc.path()).is_err());
        fs::write(root.path().join("test/cgroup.procs"), "not-a-pid\n").unwrap();
        assert!(cgroup_processes_at("/test", root.path(), proc.path()).is_err());
        assert!(cgroup_processes_at("/../test", root.path(), proc.path()).is_err());
    }
}

/// ExecStop must retain its owning process while observation is uncertain. A
/// service failure could otherwise advance PID1 into signalling the VM cgroup.
pub fn wait_for_stop(name: &str) {
    retry_stop(
        || stop_instance(name),
        || std::thread::sleep(Duration::from_secs(1)),
        |error| eprintln!("Cannot confirm graceful VM exit; waiting for owner assistance: {error}"),
    );
}
fn retry_stop<F, P, N>(mut stop: F, mut pause: P, mut notice: N)
where
    F: FnMut() -> Result<()>,
    P: FnMut(),
    N: FnMut(&Error),
{
    loop {
        match stop() {
            Ok(()) => return,
            Err(error) => {
                notice(&error);
                pause();
            }
        }
    }
}
#[cfg(test)]
mod stop_retry_tests {
    use super::*;
    #[test]
    fn inspection_failure_keeps_execstop_alive_until_observation_recovers() {
        let attempts = std::cell::Cell::new(0);
        let pauses = std::cell::Cell::new(0);
        let notices = std::cell::RefCell::new(Vec::new());
        retry_stop(
            || {
                attempts.set(attempts.get() + 1);
                match attempts.get() {
                    1 => Err(std::io::Error::from_raw_os_error(libc::EACCES).into()),
                    2 => Err(std::io::Error::from_raw_os_error(libc::EIO).into()),
                    _ => Ok(()),
                }
            },
            || pauses.set(pauses.get() + 1),
            |error| notices.borrow_mut().push(error.io_errno),
        );
        assert_eq!(attempts.get(), 3);
        assert_eq!(pauses.get(), 2);
        assert_eq!(*notices.borrow(), [Some(libc::EACCES), Some(libc::EIO)]);
    }
}

#[cfg(test)]
mod native_stop_tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[test]
    fn failed_acpi_waits_for_every_process_without_a_signal_interface() {
        let observations = Cell::new(0);
        let poweroffs = Cell::new(0);
        let pauses = Cell::new(0);
        let notices = RefCell::new(Vec::new());
        await_graceful_exit(
            || {
                observations.set(observations.get() + 1);
                Ok(observations.get() < 4)
            },
            || {
                poweroffs.set(poweroffs.get() + 1);
                Ok(false)
            },
            || pauses.set(pauses.get() + 1),
            |message| notices.borrow_mut().push(message.to_owned()),
        )
        .unwrap();
        assert_eq!(poweroffs.get(), 1);
        assert_eq!(pauses.get(), 2);
        assert!(notices.borrow()[0].contains("owner-assisted"));
    }
    #[test]
    fn an_already_exited_guest_needs_no_request() {
        await_graceful_exit(
            || Ok(false),
            || panic!("guest already exited"),
            || panic!("no wait needed"),
            |_| panic!("no notice needed"),
        )
        .unwrap();
    }
    #[test]
    fn stop_requires_its_actual_owning_unit_before_native_commands() {
        let group = own_cgroup().unwrap();
        let name = if Path::new(&group).file_name().and_then(|s| s.to_str())
            == Some("systemd-vmspawn@foreign-check.service")
        {
            "other-foreign-check"
        } else {
            "foreign-check"
        };
        assert!(
            stop_instance(name)
                .unwrap_err()
                .message
                .contains("owning unit")
        );
    }
    #[test]
    fn auxiliary_stop_helpers_and_replacements_keep_their_distinct_lifecycle() {
        for (original, cgroup, state, same, expected) in [
            (false, true, "deactivating", true, (true, false)),
            (false, false, "inactive", false, (false, false)),
            (false, true, "activating", false, (false, true)),
            (true, false, "inactive", false, (true, false)),
        ] {
            assert_eq!(
                invocation_liveness(
                    original,
                    cgroup || ["active", "activating", "deactivating"].contains(&state),
                    same
                ),
                expected
            );
        }
    }
    #[test]
    fn only_the_intrinsic_host_entry_is_exempt_from_vm_registration() {
        assert!(!managed_vm(&json!({"machine":".host","class":"host","service":null})).unwrap());
        assert!(
            managed_vm(&json!({"machine":"guest","class":"vm","service":"systemd-vmspawn"}))
                .unwrap()
        );
        assert!(
            managed_vm(
                &json!({"machine":"unexpected","class":"container","service":"systemd-nspawn"})
            )
            .unwrap_err()
            .deferred
        );
        assert!(managed_vm(&json!({"machine":"guest","class":"vm","service":"other"})).is_err());
    }
}
