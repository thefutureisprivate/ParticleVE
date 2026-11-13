//! Bounded privileged observations followed by an irreversible unprivileged TLS handoff.
use crate::common::{
    Error, Result, canonical, command, digest, field, hex, list, object, parse_json, read_json,
    require, text, uint,
};
use crate::linux::Linux;
use crate::vms::{LinuxVMs, VmPlatform};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
pub const MAX_REPORT: usize = 65536;
pub const MAX_HANDOFF: usize = 2 * MAX_REPORT + 4096;
const SETTINGS: &str = "/etc/particleve/reporting.json";
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
pub fn private_file(path: &Path, secret: bool) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let info = file.metadata()?;
    let mode = info.permissions().mode() & 0o7777;
    let reviewed_mode = if secret {
        [0o400, 0o600].contains(&mode)
    } else {
        [0o400, 0o600, 0o644].contains(&mode)
    };
    require(
        info.is_file()
            && info.uid() == 0
            && info.nlink() == 1
            && reviewed_mode
            && info.len() > 0
            && info.len() <= if secret { 2048 } else { MAX_REPORT as u64 },
        "reporting input must be a bounded, root-owned regular file with reviewed permissions",
    )?;
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_REPORT + 1) as u64)
        .read_to_end(&mut data)?;
    require(
        data.len() <= MAX_REPORT,
        "reporting input exceeds its size limit",
    )?;
    Ok(data)
}
pub fn settings() -> Result<Value> {
    let config = parse_json(&private_file(Path::new(SETTINGS), true)?)?;
    let map = object(&config)?;
    require(
        map.len() == 4
            && [
                "schema",
                "endpoint",
                "maximum_update_check_age_seconds",
                "private_ca",
            ]
            .iter()
            .all(|k| map.contains_key(*k))
            && config["schema"] == 1,
        "unknown reporting configuration",
    )?;
    crate::config::https_url(text(field(&config, "endpoint")?)?)?;
    require(
        crate::config::integer(
            field(&config, "maximum_update_check_age_seconds")?,
            3600,
            "maximum update-check age",
        )? <= 7 * 86400,
        "update-check age cannot exceed seven days",
    )?;
    require(
        config["private_ca"].is_boolean(),
        "declare reporting private-CA policy",
    )?;
    require(
        config["private_ca"] == false,
        "reporting uses the system trust store; set private_ca to false and install anchors through the system trust configuration",
    )?;
    Ok(config)
}
pub fn policy_binding() -> Result<String> {
    let config = settings()?;
    // Retain the persisted false-policy digest; no private CA can enter this binding.
    digest(&json!({"settings":config,"private_ca_sha256":null}))
}
pub fn journal() -> Result<Value> {
    let args = [
        "journalctl",
        "--quiet",
        "--since=-10min",
        "--lines=65",
        "--output=json",
        "--output-fields=__CURSOR,MESSAGE",
        "--grep=avc:.*denied",
        "_TRANSPORT=audit",
        "+",
        "_TRANSPORT=kernel",
    ]
    .map(String::from);
    let observed = command(
        &args,
        None,
        Some(Duration::from_secs(10)),
        256 * 1024,
        false,
    )?;
    require(
        observed.code == 0 || (observed.code == 1 && observed.stdout.is_empty()),
        "SELinux journal observation failed",
    )?;
    require(
        observed.stderr.is_empty(),
        "SELinux journal observation produced diagnostics",
    )?;
    let rows = observed
        .stdout
        .lines()
        .map(|line| parse_json(line.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    let mut events = Vec::new();
    let permissions = Regex::new(r"avc:\s+denied\s+\{\s*([a-z_ ]{1,128})\s*\}")
        .map_err(|e| Error::new(e.to_string()))?;
    for row in rows.iter().take(64) {
        let message = text(field(row, "MESSAGE")?)?;
        let mut event =
            json!({"id":hex(&Sha256::digest(text(field(row,"__CURSOR")?)?.as_bytes()))});
        for key in ["scontext", "tcontext", "tclass"] {
            let regex = Regex::new(&format!(r"\b{key}=([A-Za-z0-9_:,.-]{{1,128}})(?:\s|$)"))
                .map_err(|e| Error::new(e.to_string()))?;
            if let Some(m) = regex.captures(message) {
                event[key] = m[1].into();
            }
        }
        if let Some(m) = permissions.captures(message) {
            event["permissions"] = json!(m[1].split_whitespace().collect::<Vec<_>>());
        }
        events.push(event);
    }
    Ok(json!({"window_seconds":600,"limited":rows.len()>64,"events":events}))
}
fn select(value: &Value, keys: &[&str]) -> Value {
    let mut result = json!({});
    for key in keys {
        if let Some(v) = value.get(*key) {
            result[*key] = v.clone();
        }
    }
    result
}
fn truncate(value: &Value, maximum: usize) -> Result<(Value, bool)> {
    let values = list(value)?;
    Ok((
        json!(values.iter().take(maximum).collect::<Vec<_>>()),
        values.len() > maximum,
    ))
}
fn summarize(name: &str, observed: Value) -> Result<(Option<Value>, bool)> {
    let mut attention = false;
    let details = match name {
        "storage" => {
            let mut result = json!({});
            for key in [
                "free_bytes",
                "reserve_bytes",
                "swap_degraded",
                "swap_sync_action",
            ] {
                result[key] = field(&observed, key)?.clone();
            }
            Some(result)
        }
        "resources" => {
            let physical = list(field(&observed, "physical_disks")?)?;
            let oom = field(&observed, "oom_events")?;
            let (events, events_limited) = truncate(field(oom, "events")?, 8)?;
            let (alerts, alerts_limited) = truncate(field(&observed, "alerts")?, 8)?;
            let vms = list(field(&observed, "virtual_machines")?)?;
            let mut oom = oom.clone();
            oom["events"] = events;
            oom["limited"] =
                json!(crate::common::boolean(field(&oom, "limited")?)? || events_limited);
            attention = !list(field(&observed, "alerts")?)?.is_empty()
                || crate::common::boolean(field(&observed, "alerts_limited")?)?
                || physical.iter().any(|disk| disk["status"] != "passed");
            Some(json!({
                "memory":field(&observed,"memory")?,
                "disk_status":physical.iter().map(|disk|Ok(json!({"role":field(disk,"role")?,"status":field(disk,"status")?}))).collect::<Result<Vec<_>>>()?,
                "pressure":field(&observed,"pressure")?,
                "oom_events":oom,
                "alerts":alerts,
                "alerts_limited":crate::common::boolean(field(&observed,"alerts_limited")?)? || alerts_limited,
                "vm_count":vms.len(),
                "vm_details_limited":vms.len()>8,
                "virtual_machines":vms.iter().take(8).map(|vm|select(vm,&["unit","state","result","oom_policy","oom_group","limits","memory_current_bytes","memory_peak_bytes","memory_events","tasks_current","task_events","pressure"])).collect::<Vec<_>>()
            }))
        }
        "selinux_denials" => {
            let (events, limited) = truncate(field(&observed, "events")?, 32)?;
            attention = !list(field(&observed, "events")?)?.is_empty()
                || crate::common::boolean(field(&observed, "limited")?)?;
            let mut result = observed;
            result["events"] = events;
            result["limited"] =
                json!(crate::common::boolean(field(&result, "limited")?)? || limited);
            Some(result)
        }
        "vm_confinement" | "authenticated_time" => Some(observed),
        _ => None,
    };
    Ok((details, attention))
}
fn quarantined_versions(state: &Value) -> Result<Vec<String>> {
    let mut rejected = object(field(state, "rejected")?)?
        .keys()
        .map(|version| crate::config::version_key(version).map(|key| (key, version.clone())))
        .collect::<Result<Vec<_>>>()?;
    rejected.sort();
    Ok(rejected.into_iter().map(|(_, version)| version).collect())
}
fn update_observation(
    update: Option<&Value>,
    commissioned: bool,
    maximum_update_check_age_seconds: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(bool, Option<Value>)> {
    let mut update_ok = !commissioned;
    let mut observed = None;
    if let Some(update) = update {
        require(
            update.is_object() && update["schema"] == 1,
            "unknown release-check observation",
        )?;
        require(
            matches!(text(field(update, "result")?)?, "pass" | "fail"),
            "unknown release-check result",
        )?;
        update_ok = false;
        if let Some(completed) = update["last_success_at"].as_str() {
            let completed = chrono::DateTime::parse_from_rfc3339(completed)
                .map_err(|e| Error::new(e.to_string()))?;
            let age = now.signed_duration_since(completed).num_milliseconds() as f64 / 1000.;
            update_ok = update["result"] == "pass"
                && age >= 0.
                && age <= maximum_update_check_age_seconds as f64;
        }
        observed = Some(select(
            update,
            &["result", "attempted_at", "last_success_at", "version"],
        ));
    }
    Ok((update_ok, observed))
}
pub fn snapshot(
    backend: &Linux,
    maximum_update_check_age_seconds: u64,
    now: Option<chrono::DateTime<chrono::Utc>>,
    kcore: &Path,
) -> Result<Value> {
    let now = now.unwrap_or_else(chrono::Utc::now);
    let mut checks = Vec::new();
    let mut details = json!({});
    for name in [
        "host_security",
        "authenticated_time",
        "storage",
        "resources",
        "selinux_denials",
        "vm_confinement",
    ] {
        let observed = match name {
            "host_security" => backend.health_with_kcore(kcore).map(|()| Value::Null),
            "authenticated_time" => backend.check_time(None),
            "storage" => backend.check_storage(true),
            "resources" => backend.check_resources(false),
            "selinux_denials" => journal(),
            _ => LinuxVMs
                .inventory(false)
                .map(|v| json!({"running_vm_count":v.len()})),
        };
        match observed.and_then(|value| summarize(name, value)) {
            Err(error) => checks.push(json!({"name":name,"result":"attention","detail":error.message.chars().take(256).collect::<String>()})),
            Ok((observed, attention)) => {
                if let Some(observed) = observed { details[name] = observed; }
                checks.push(json!({"name":name,"result":if attention {"attention"} else {"pass"}}));
            }
        }
    }
    let state = crate::coordinator::load_state(&backend.directory)?;
    let esp = crate::quarantine::status(&backend.directory)?;
    checks
        .push(json!({"name":"esp_quarantine","result":if esp.is_null(){"pass"}else{"attention"}}));
    if !esp.is_null() {
        details["esp_quarantine"] = json!({"version":esp["version"],"roles":{"a":esp["roles"]["a"]["status"],"b":esp["roles"]["b"]["status"]}});
    }
    let rejected = quarantined_versions(&state)?;
    checks.push(json!({"name":"quarantined_releases","result":if rejected.is_empty(){"pass"}else{"attention"}}));
    details["quarantined_releases"] = json!(
        rejected
            .iter()
            .skip(rejected.len().saturating_sub(8))
            .collect::<Vec<_>>()
    );
    let loader_state = crate::bootloaders::Loaders::new(backend).load()?;
    let loaders = list(field(&loader_state, "rejected")?)?;
    details["quarantined_loaders"] = json!(
        loaders
            .iter()
            .skip(loaders.len().saturating_sub(8))
            .collect::<Vec<_>>()
    );
    checks.push(json!({"name":"quarantined_loaders","result":if loaders.is_empty(){"pass"}else{"attention"}}));
    let commissioned = backend.directory.join("commissioned.json").exists();
    let update_file = backend.directory.join("release-check.json");
    let update = if update_file.exists() {
        Some(read_json(update_file)?)
    } else {
        None
    };
    let (update_ok, update_details) = update_observation(
        update.as_ref(),
        commissioned,
        maximum_update_check_age_seconds,
        now,
    )?;
    if let Some(observed) = update_details {
        details["update_check"] = observed;
    }
    checks.push(json!({"name":"update_check","result":if update_ok{"pass"}else{"attention"},"required":commissioned}));
    let result = json!({"schema":1,"installation_uuid":backend.manifest["installation_uuid"],"image_version":backend.current_version()?,"boot_id":backend.boot_id()?,"observed_at":now.to_rfc3339_opts(chrono::SecondsFormat::Micros,false),"commissioned":commissioned,"result":if checks.iter().any(|c|c["result"]!="pass"){"attention"}else{"pass"},"checks":checks,"details":details});
    require(
        canonical(&result)?.len() <= MAX_REPORT,
        "health report exceeds its size limit",
    )?;
    Ok(result)
}
pub fn deliver(report: &Value, endpoint: &str, token: &[u8]) -> Result<Value> {
    let endpoint = crate::config::https_url(endpoint)?;
    let credential = std::str::from_utf8(token)
        .map_err(|_| Error::new("invalid reporting service credential"))?;
    require(
        Regex::new(r"^[A-Za-z0-9._~+/-]{32,2048}={0,2}$")
            .map_err(|e| Error::new(e.to_string()))?
            .is_match(credential),
        "invalid reporting service credential",
    )?;
    let body = canonical(report)?;
    require(
        body.len() <= MAX_REPORT,
        "health report exceeds its size limit",
    )?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(20)))
        .tls_config(crate::release::tls_config()?)
        .build()
        .into();
    let mut response = agent
        .post(&endpoint)
        .header("Authorization", format!("Bearer {credential}"))
        .header("Content-Type", "application/json")
        .header("User-Agent", "ParticleVE-health-report")
        .send(body.as_slice())
        .map_err(|_| Error::new("health receiver connection failed"))?;
    acknowledgement(
        report,
        response.status().as_u16(),
        response.body_mut().as_reader(),
    )
}
fn acknowledgement(report: &Value, status: u16, reader: impl Read) -> Result<Value> {
    require(
        matches!(status, 200 | 202 | 204),
        format!("health receiver refused delivery: HTTP {status}"),
    )?;
    let mut acknowledgement = Vec::new();
    reader.take(1025).read_to_end(&mut acknowledgement)?;
    require(
        acknowledgement.len() <= 1024,
        "health receiver acknowledgement exceeds its size limit",
    )?;
    Ok(json!({"delivered":true,"http_status":status,"report_result":report["result"]}))
}
fn sealed_handoff(payload: &[u8]) -> Result<File> {
    // SAFETY: the static name is NUL terminated; File takes sole ownership of the returned descriptor.
    let descriptor = unsafe {
        libc::memfd_create(
            c"particleve-health-handoff".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x0008,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    } // SAFETY: successful memfd_create returns a new owned descriptor.
    let mut handoff = unsafe { File::from_raw_fd(descriptor) };
    require(
        handoff.metadata()?.permissions().mode() & 0o111 == 0,
        "health handoff must not be executable",
    )?;
    handoff.write_all(payload)?; // SAFETY: fcntl applies seals to the live exclusively owned memfd. No pointer argument is used.
    require(
        unsafe { libc::fcntl(handoff.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } == 0,
        "cannot seal health handoff",
    )?;
    handoff.seek(SeekFrom::Start(0))?;
    Ok(handoff)
}
pub fn send(backend: &Linux) -> Result<Value> {
    let config = settings()?;
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or_else(|| Error::new("send reports through the credential-loaded service"))?;
    require(
        directory.is_absolute(),
        "send reports through the credential-loaded service",
    )?; // SAFETY: geteuid has no memory arguments and only observes this process.
    require(
        unsafe { libc::geteuid() } == 0,
        "host inspection requires the trusted service bootstrap",
    )?;
    let lookup = crate::common::run(&[
        "busctl",
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "LookupDynamicUserByName",
        "s",
        "particleve-report",
    ])?;
    let pattern = Regex::new(r"^u ([0-9]+)\n?$").map_err(|e| Error::new(e.to_string()))?;
    let captures = pattern
        .captures(&lookup.stdout)
        .ok_or_else(|| Error::new("PID1 did not identify the private dynamic reporting user"))?;
    require(
        lookup.stderr.is_empty(),
        "PID1 did not identify the private dynamic reporting user",
    )?;
    let uid = captures[1]
        .parse::<u32>()
        .map_err(|_| Error::new("invalid reporting dynamic UID"))?;
    require(
        (61184..=65519).contains(&uid),
        "report delivery requires a private dynamic UID",
    )?;
    let payload = canonical(
        &json!({"schema":1,"uid":uid,"endpoint":config["endpoint"],"report":snapshot(backend,uint(&config["maximum_update_check_age_seconds"])?,None,Path::new(crate::kernelruntime::REPORT_KCORE))?}),
    )?;
    require(
        payload.len() <= MAX_HANDOFF,
        "health handoff exceeds its size limit",
    )?; // SAFETY: static NUL-terminated name; returned descriptor transfers into exactly one File owner. NOEXEC_SEAL is required without fallback.
    let handoff = sealed_handoff(&payload)?; // SAFETY: atomically replace this inspector's stdin with the sealed memfd; it is deliberately inherited by the replacing sender.
    require(
        unsafe { libc::dup2(handoff.as_raw_fd(), 0) } == 0,
        "cannot hand over health report",
    )?;
    // SAFETY: dup2(fd, fd) preserves CLOEXEC if the caller originally had stdin closed.
    // Stdin is the one intentional inherited protocol descriptor in either allocation case.
    require(
        unsafe { libc::fcntl(0, libc::F_SETFD, 0) } == 0,
        "cannot inherit sealed health handoff",
    )?;
    let error = std::process::Command::new("/usr/bin/setpriv")
        .args([
            format!("--reuid={uid}"),
            format!("--regid={uid}"),
            "--clear-groups".into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--ambient-caps=-all".into(),
            "--no-new-privs".into(),
            "/usr/libexec/particleve-health-sender".into(),
        ])
        .exec();
    Err(error.into())
}
fn credential_acl(uid: u32, permissions: u16) -> Vec<u8> {
    // Linux UAPI posix_acl_xattr.h: version 2 followed by little-endian
    // (tag, permissions, id) entries. Only root and this one UID get access;
    // the owning group and other users get none, including through the mask.
    let mut acl = Vec::with_capacity(44);
    acl.extend(2_u32.to_le_bytes());
    for (tag, access, id) in [
        (1_u16, permissions, u32::MAX), // ACL_USER_OBJ
        (2, permissions, uid),          // ACL_USER
        (4, 0, u32::MAX),               // ACL_GROUP_OBJ
        (16, permissions, u32::MAX),    // ACL_MASK
        (32, 0, u32::MAX),              // ACL_OTHER
    ] {
        acl.extend(tag.to_le_bytes());
        acl.extend(access.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    acl
}
fn credential_access(
    owner: (u32, u32),
    mode: u32,
    uid: u32,
    permissions: u16,
    acl: Option<&[u8]>,
) -> bool {
    let owner_mode = u32::from(permissions) << 6;
    // Current PID1 uses an exclusive named-user ACL where supported, or
    // service ownership on its read-only mount. These are the two native
    // representations in systemd v262.1 exec-credential.c.
    (owner == (uid, uid) && mode == owner_mode && acl.is_none())
        || (owner == (0, 0)
            && mode == (owner_mode | (u32::from(permissions) << 3))
            && acl == Some(credential_acl(uid, permissions).as_slice()))
}
fn credential_access_acl(file: &File) -> Result<Option<[u8; 44]>> {
    let mut acl = [0_u8; 44];
    // SAFETY: the descriptor is live, the name is NUL terminated and the
    // writable buffer is exactly the advertised size. Larger ACLs fail closed.
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_mut_ptr().cast(),
            acl.len(),
        )
    };
    if length < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
            return Ok(None);
        }
        return Err(error.into());
    }
    require(
        length as usize == acl.len(),
        "service credential has an unexpected access ACL",
    )?;
    Ok(Some(acl))
}
pub fn sender_main() -> Result<Value> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0); // SAFETY: each call writes three live uid_t/gid_t scalars; group count query has a null pointer with zero capacity.
    let identities = unsafe {
        libc::getresuid(
            &raw mut real_uid,
            &raw mut effective_uid,
            &raw mut saved_uid,
        ) == 0
            && libc::getresgid(
                &raw mut real_gid,
                &raw mut effective_gid,
                &raw mut saved_gid,
            ) == 0
            && libc::getgroups(0, std::ptr::null_mut()) == 0
    };
    let uid = effective_uid;
    require(
        identities
            && (61184..=65519).contains(&uid)
            && [real_uid, saved_uid, real_gid, effective_gid, saved_gid]
                .iter()
                .all(|v| *v == uid),
        "TLS sender retained another user or group identity",
    )?;
    let data = fs::read_to_string("/proc/self/status")?;
    let status = data
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k, v.trim()))
        .collect::<std::collections::BTreeMap<_, _>>();
    require(
        ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
            .iter()
            .all(|name| {
                status
                    .get(name)
                    .and_then(|v| u64::from_str_radix(v, 16).ok())
                    == Some(0)
            })
            && status.get("NoNewPrivs") == Some(&"1")
            && status.get("Seccomp") == Some(&"2"),
        "TLS sender retained privilege or lost its syscall filter",
    )?;
    let filesystem_abi = crate::landlock::confine_filesystem()?; // SAFETY: duplicate stdin into a new descriptor owned by File; inherited stdin stays valid for seal checks.
    let descriptor = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    } // SAFETY: descriptor is a new successful fcntl duplicate owned only here.
    let mut input = unsafe { File::from_raw_fd(descriptor) };
    let info = input.metadata()?;
    require(
        info.is_file() && info.uid() == 0 && info.len() > 0 && info.len() <= MAX_HANDOFF as u64,
        "untrusted health handoff",
    )?; // SAFETY: F_GET_SEALS has no pointer argument and only queries the inherited live memfd.
    let seals = unsafe { libc::fcntl(0, libc::F_GET_SEALS) };
    require(
        seals >= 0 && seals & SEALS == SEALS,
        "health handoff is not sealed",
    )?;
    let mut data = Vec::new();
    Read::by_ref(&mut input)
        .take((MAX_HANDOFF + 1) as u64)
        .read_to_end(&mut data)?;
    require(
        data.len() <= MAX_HANDOFF,
        "health handoff exceeds its size limit",
    )?;
    let payload = parse_json(&data)?;
    require(
        payload["schema"] == 1 && payload["uid"] == uid,
        "health handoff identity differs",
    )?;
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or_else(|| Error::new("TLS sender has no credential directory for its owning unit"))?;
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let groups = cgroup
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect::<Vec<_>>();
    require(
        groups.len() == 1,
        "TLS sender has no credential directory for its owning unit",
    )?;
    let unit = Path::new(groups[0])
        .file_name()
        .ok_or_else(|| Error::new("invalid owning cgroup"))?;
    require(
        directory == Path::new("/run/credentials").join(unit),
        "TLS sender has no credential directory for its owning unit",
    )?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let info = directory.metadata()?;
    let acl = credential_access_acl(&directory)?;
    let mut mount = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: directory owns the live descriptor and mount is aligned writable
    // storage for the kernel's complete result.
    let stat_result = unsafe { libc::fstatvfs(directory.as_raw_fd(), mount.as_mut_ptr()) };
    require(stat_result == 0, "cannot inspect credential mount")?; // SAFETY: statvfs succeeded and initialized the entire result structure.
    let mount = unsafe { mount.assume_init() };
    require(
        info.is_dir()
            && credential_access(
                (info.uid(), info.gid()),
                info.permissions().mode() & 0o7777,
                uid,
                5,
                acl.as_ref().map(|value| value.as_slice()),
            )
            && mount.f_flag & libc::ST_RDONLY != 0,
        "service credentials are not in PID1's read-only private mount",
    )?;
    // SAFETY: directory owns the validated parent; the fixed child name cannot
    // escape it, O_NOFOLLOW rejects substitution, and File takes sole ownership.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"report-token".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new descriptor, not owned anywhere else.
    let mut token_file = unsafe { File::from_raw_fd(descriptor) };
    let info = token_file.metadata()?;
    let acl = credential_access_acl(&token_file)?;
    require(
        info.is_file()
            && credential_access(
                (info.uid(), info.gid()),
                info.permissions().mode() & 0o7777,
                uid,
                4,
                acl.as_ref().map(|value| value.as_slice()),
            )
            && info.nlink() == 1
            && info.len() > 0
            && info.len() <= 2048,
        "service credential does not match PID1's private file contract",
    )?;
    let mut token = Vec::new();
    Read::by_ref(&mut token_file)
        .take(2049)
        .read_to_end(&mut token)?;
    if token.last() == Some(&b'\n') {
        token.pop();
    }
    let mut result = deliver(
        field(&payload, "report")?,
        text(field(&payload, "endpoint")?)?,
        &token,
    )?;
    result["sender_uid"] = uid.into();
    result["sender_capabilities"] = "empty".into();
    result["sender_landlock_abi"] = filesystem_abi.into();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pid1_acl_grants_access_to_only_the_selected_dynamic_uid() {
        let acl = credential_acl(62294, 4);
        // Captured after PID1's real credential handoff on the Fedora baseline.
        assert_eq!(
            hex(&acl),
            "0200000001000400ffffffff0200040056f3000004000000ffffffff10000400ffffffff20000000ffffffff"
        );
        assert!(credential_access((0, 0), 0o440, 62294, 4, Some(&acl)));
        let directory = credential_acl(62294, 5);
        assert!(credential_access((0, 0), 0o550, 62294, 5, Some(&directory)));
        assert!(!credential_access((0, 0), 0o440, 62295, 4, Some(&acl)));
        assert!(!credential_access((0, 1), 0o440, 62294, 4, Some(&acl)));
        assert!(!credential_access((0, 0), 0o640, 62294, 4, Some(&acl)));
        assert!(!credential_access((0, 0), 0o440, 62294, 4, None));
    }
    #[test]
    fn credential_acl_rejects_extra_grants_and_malformed_entries() {
        let acl = credential_acl(62294, 4);
        for length in 0..acl.len() {
            assert!(!credential_access(
                (0, 0),
                0o440,
                62294,
                4,
                Some(&acl[..length])
            ));
        }
        for offset in 0..acl.len() {
            let mut changed = acl.clone();
            changed[offset] ^= 1;
            assert!(!credential_access((0, 0), 0o440, 62294, 4, Some(&changed)));
        }
        let mut extra_user = acl.clone();
        extra_user.extend([2, 0, 4, 0, 1, 0, 0, 0]);
        assert!(!credential_access(
            (0, 0),
            0o440,
            62294,
            4,
            Some(&extra_user)
        ));
    }
    #[test]
    fn ownership_based_credentials_require_exclusive_modes_and_no_acl() {
        assert!(credential_access((62294, 62294), 0o400, 62294, 4, None));
        assert!(credential_access((62294, 62294), 0o500, 62294, 5, None));
        assert!(!credential_access((62294, 62294), 0o440, 62294, 4, None));
        assert!(!credential_access((62294, 0), 0o400, 62294, 4, None));
        assert!(!credential_access(
            (62294, 62294),
            0o400,
            62294,
            4,
            Some(&credential_acl(62294, 4))
        ));
    }
    #[test]
    fn report_details_are_bounded_without_turning_missing_evidence_into_success() {
        assert!(summarize("storage", json!({})).is_err());
        assert!(summarize("resources", json!({})).is_err());
        let source = json!({"window_seconds":600,"limited":false,"events":(0..65).map(|n|json!({"id":n})).collect::<Vec<_>>()});
        let (details, attention) = summarize("selinux_denials", source).expect("denials");
        assert!(attention);
        let details = details.expect("details");
        assert_eq!(details["events"].as_array().expect("events").len(), 32);
        assert_eq!(details["limited"], true);
    }
    #[test]
    fn service_credentials_are_validated_before_any_network_operation() {
        for token in [
            b"short".as_slice(),
            b"valid-looking-but-has-newline-aaaaaaaa\n".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:secret".as_slice(),
        ] {
            let failure = deliver(
                &json!({"result":"pass"}),
                "https://updates.example.org/report",
                token,
            )
            .expect_err("invalid credential");
            assert!(
                failure
                    .message
                    .contains("invalid reporting service credential")
            );
        }
    }
    #[test]
    fn handoff_is_sealed_non_executable_and_cannot_be_rewritten() {
        let payload = canonical(&json!({"schema":1,"uid":62300,"report":{"result":"pass"}}))
            .expect("payload");
        let mut handoff = sealed_handoff(&payload).expect("native sealed handoff");
        // SAFETY: F_GET_SEALS observes the live memfd without pointer arguments.
        let seals = unsafe { libc::fcntl(handoff.as_raw_fd(), libc::F_GET_SEALS) };
        assert_eq!(seals & SEALS, SEALS);
        assert_eq!(
            handoff.metadata().expect("metadata").permissions().mode() & 0o111,
            0
        );
        assert_eq!(
            handoff.write_all(b"forged").expect_err("sealed").kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let mut observed = Vec::new();
        handoff.read_to_end(&mut observed).expect("sealed input");
        assert_eq!(observed, payload);
    }
    #[test]
    fn receiver_acknowledgements_reject_redirects_failures_and_oversized_bodies() {
        struct Unread;
        impl Read for Unread {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("refused receiver body must not be read")
            }
        }
        let report = json!({"result":"pass"});
        for status in [200, 202, 204] {
            let result = acknowledgement(&report, status, b"private receiver text".as_slice())
                .expect("accepted");
            assert_eq!(result["http_status"], status);
            assert!(!result.to_string().contains("private receiver text"));
        }
        for status in [301, 302, 307, 403, 500] {
            assert!(acknowledgement(&report, status, Unread).is_err());
        }
        assert!(acknowledgement(&report, 200, vec![0; 1025].as_slice()).is_err());
        assert!(acknowledgement(&report, 200, vec![0; 1024].as_slice()).is_ok());
    }
    #[test]
    fn commissioned_update_freshness_requires_a_successful_non_future_observation() {
        let now = "2026-11-08T00:00:00Z".parse().expect("fixed time");
        assert!(
            update_observation(None, false, 172800, now)
                .expect("uncommissioned")
                .0
        );
        assert!(
            !update_observation(None, true, 172800, now)
                .expect("missing commissioned check")
                .0
        );
        let fresh = json!({"schema":1,"result":"pass","last_success_at":"2026-11-08T00:00:00Z","version":"45.0.1.1-63.1"});
        assert!(
            update_observation(Some(&fresh), true, 172800, now)
                .expect("fresh")
                .0
        );
        for (field, value) in [
            ("result", json!("fail")),
            ("last_success_at", json!("2026-11-05T00:00:00Z")),
            ("last_success_at", json!("2099-01-01T00:00:00Z")),
        ] {
            let mut observation = fresh.clone();
            observation[field] = value;
            assert!(
                !update_observation(Some(&observation), true, 172800, now)
                    .expect("attention")
                    .0
            );
        }
        let mut unknown = fresh;
        unknown["schema"] = 2.into();
        assert!(update_observation(Some(&unknown), true, 172800, now).is_err());
    }
    #[test]
    fn quarantine_versions_are_numeric_and_report_details_remain_bounded() {
        let versions = [
            "44.9.9.9-999.999",
            "45.0.1.8-1.2",
            "45.0.1.8-1.10",
            "45.0.1.8-2.1",
            "45.0.1.8-9.9",
            "45.0.1.8-10.1",
            "45.0.1.9-1.1",
            "45.0.1.10-1.1",
            "45.0.2.0-1.1",
            "45.1.0.0-1.1",
            "46.0.0.0-1.1",
        ];
        let mut rejected = json!({});
        for version in versions.iter().rev() {
            rejected[*version] = "failed boot".into();
        }
        let sorted = quarantined_versions(&json!({"rejected":rejected})).expect("quarantines");
        assert_eq!(
            sorted
                .iter()
                .skip(sorted.len() - 8)
                .map(String::as_str)
                .collect::<Vec<_>>(),
            versions[3..]
        );
        let observed = json!({"memory":{},"physical_disks":[{"role":"a","status":"unavailable"}],"pressure":{},"oom_events":{"events":vec![json!({"id":"opaque"});65],"limited":false},"alerts":vec!["pressure";32],"alerts_limited":false,"virtual_machines":vec![json!({"unit":"systemd-vmspawn@test.service"});16]});
        let (details, attention) = summarize("resources", observed).expect("summary");
        assert!(attention);
        let details = details.expect("details");
        assert_eq!(
            details["virtual_machines"].as_array().expect("VMs").len(),
            8
        );
        assert_eq!(
            details["oom_events"]["events"]
                .as_array()
                .expect("events")
                .len(),
            8
        );
        assert_eq!(details["alerts"].as_array().expect("alerts").len(), 8);
        assert_eq!(details["alerts_limited"], true);
        assert_eq!(details["vm_details_limited"], true);
        assert_eq!(details["oom_events"]["limited"], true);
        assert!(canonical(&details).expect("bounded JSON").len() < MAX_REPORT);
    }
}
