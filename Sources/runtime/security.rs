//! Image-bound assertions and read-only effective security evidence.
use crate::common::{
    Error, Result, boolean, command, field, hash_file, list, object, parse_json, read_bounded,
    read_json, require, run, text,
};
use crate::confinement::get_xattr;
use crate::processes::{Identity, MAX_FDS, MAX_NAMESPACES, Process};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;
pub const POLICY: &str = "usr/lib/particleve/security-policy.json";
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    pub schema: u32,
    pub kernel_required: Vec<String>,
    pub tpm_profile: BTreeMap<String, String>,
    pub selinux_booleans: BTreeMap<String, bool>,
    pub sysctls: BTreeMap<String, String>,
}
pub fn runtime_policy() -> Result<RuntimePolicy> {
    parse_runtime_policy(include_bytes!("../particleve/runtime-policy.json"))
}
fn parse_runtime_policy(data: &[u8]) -> Result<RuntimePolicy> {
    let value = parse_json(data)?;
    let policy: RuntimePolicy = serde_json::from_value(value)?;
    require(policy.schema == 1, "unknown runtime baseline policy schema")?;
    require(
        !policy.kernel_required.is_empty()
            && policy.kernel_required.iter().collect::<BTreeSet<_>>().len()
                == policy.kernel_required.len()
            && policy.kernel_required.iter().all(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            }),
        "invalid required kernel policy",
    )?;
    require(
        policy
            .tpm_profile
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == ["Name", "Attributes"].into_iter().collect()
            && policy.tpm_profile.values().all(|s| !s.is_empty()),
        "invalid TPM creation policy",
    )?;
    require(
        !policy.selinux_booleans.is_empty()
            && policy.selinux_booleans.keys().all(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            }),
        "invalid SELinux boolean policy",
    )?;
    require(
        !policy.sysctls.is_empty()
            && policy.sysctls.iter().all(|(name, value)| {
                !name.is_empty()
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.'
                    })
                    && !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit())
            }),
        "invalid kernel runtime policy",
    )?;
    Ok(policy)
}
pub fn tpm_profile() -> Result<Value> {
    Ok(serde_json::to_value(runtime_policy()?.tpm_profile)?)
}
pub fn selinux_baseline() -> Result<Value> {
    let policy = runtime_policy()?;
    let mut args = vec!["getsebool"];
    args.extend(policy.selinux_booleans.keys().map(String::as_str));
    let response = run(&args)?;
    require(
        response.stderr.trim().is_empty(),
        "SELinux boolean inspection produced diagnostics",
    )?;
    let re = Regex::new(r"\A([a-z0-9_]+) --> (on|off)\z").map_err(|e| Error::new(e.to_string()))?;
    let mut observed = Map::new();
    for line in response.stdout.lines() {
        let row = re
            .captures(line)
            .ok_or_else(|| Error::new("invalid SELinux boolean observation"))?;
        require(
            !observed.contains_key(&row[1]),
            "invalid SELinux boolean observation",
        )?;
        observed.insert(row[1].into(), json!(&row[2] == "on"));
    }
    let expected: Map<_, _> = policy
        .selinux_booleans
        .into_iter()
        .map(|(name, value)| (name, json!(value)))
        .collect();
    require(
        observed == expected,
        "SELinux virtualization boolean policy drift",
    )?;
    Ok(Value::Object(observed))
}
// Stable libselinux public ABI: libselinux/include/selinux/selinux.h, av_decision.
#[repr(C)]
#[derive(Default)]
struct AvDecision {
    allowed: u32,
    decided: u32,
    auditallow: u32,
    auditdeny: u32,
    seqno: u32,
    flags: u32,
}
#[link(name = "libselinux.so.1", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn security_getenforce() -> libc::c_int;
    fn string_to_security_class(name: *const libc::c_char) -> u16;
    fn string_to_av_perm(class: u16, name: *const libc::c_char) -> u32;
    fn security_compute_av_flags_raw(
        source: *const libc::c_char,
        target: *const libc::c_char,
        class: u16,
        requested: u32,
        decision: *mut AvDecision,
    ) -> libc::c_int;
}
fn access_query(
    source: &str,
    target: &str,
    kind: &str,
    action: &str,
    allowed: bool,
) -> Result<u32> {
    let source_c =
        CString::new(source).map_err(|_| Error::new("invalid SELinux source context"))?;
    let target_c =
        CString::new(target).map_err(|_| Error::new("invalid SELinux target context"))?;
    let kind_c = CString::new(kind).map_err(|_| Error::new("invalid SELinux class"))?;
    let action_c = CString::new(action).map_err(|_| Error::new("invalid SELinux permission"))?;
    // SAFETY: each immutable C string outlives its call, no pointer is retained;
    // the stable ABI returns scalar class/permission identifiers and fills an aligned repr(C) decision.
    let class = unsafe { string_to_security_class(kind_c.as_ptr()) };
    let permission = if class == 0 {
        0
    } else {
        unsafe { string_to_av_perm(class, action_c.as_ptr()) }
    };
    require(
        class != 0 && permission != 0,
        format!("SELinux interface is unavailable: {kind}:{action}"),
    )?;
    let mut decision = AvDecision::default(); // SAFETY: live strings/decision use the public ABI above; this only queries effective policy.
    require(
        unsafe {
            security_compute_av_flags_raw(
                source_c.as_ptr(),
                target_c.as_ptr(),
                class,
                permission,
                &mut decision,
            )
        } == 0,
        format!("SELinux effective policy query failed: {source} {kind}:{action}"),
    )?;
    require(
        decision.flags == 0 && decision.decided & permission == permission,
        format!("SELinux domain is permissive or policy decision is incomplete: {source}"),
    )?;
    require(
        (decision.allowed & permission != 0) == allowed,
        format!("SELinux effective interface policy drift: {source} -> {target} {kind}:{action}"),
    )?;
    Ok(decision.seqno)
}
pub fn selinux_access() -> Result<Value> {
    // SAFETY: scalar enforcement query has no pointer or ownership effect.
    require(
        unsafe { security_getenforce() } == 1,
        "SELinux is not enforcing",
    )?;
    let classes = [
        "user_namespace",
        "alg_socket",
        "key_socket",
        "netlink_xfrm_socket",
    ];
    let names = [
        "svirt_t",
        "swtpm_t",
        "particleve_vmspawn_t",
        "systemd_homed_t",
        "systemd_nsresourced_t",
        "systemd_networkd_t",
        "systemd_resolved_t",
        "chronyd_t",
        "chronyd_restricted_t",
        "chronyc_t",
        "sshd_t",
        "unconfined_service_t",
        "unconfined_t",
    ];
    let mut domains = Map::new();
    let mut sequences = BTreeSet::new();
    for domain in names {
        let context = if domain == "unconfined_t" {
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023".to_owned()
        } else {
            format!("system_u:system_r:{domain}:s0")
        };
        let mut expected = Map::new();
        for kind in classes {
            let allowed = (domain == "particleve_vmspawn_t" && kind == "user_namespace")
                || (["unconfined_service_t", "unconfined_t"].contains(&domain)
                    && kind == "alg_socket");
            expected.insert(kind.into(), json!(allowed));
            sequences.insert(access_query(&context, &context, kind, "create", allowed)?);
        }
        domains.insert(domain.into(), Value::Object(expected));
    }
    let mut transitions = Map::new();
    for domain in ["unconfined_t", "unconfined_service_t"] {
        let context = if domain == "unconfined_t" {
            "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023".to_owned()
        } else {
            format!("system_u:system_r:{domain}:s0")
        };
        let target = context.replace(&format!(":{domain}:"), ":chronyc_t:");
        sequences.insert(access_query(
            &context,
            &target,
            "process2",
            "nnp_transition",
            true,
        )?);
        transitions.insert(domain.into(), json!("chronyc_t"));
    }
    require(
        sequences.len() == 1,
        "SELinux policy changed during inspection",
    )?;
    Ok(
        json!({"create":domains,"chrony_query_transitions":transitions,"policy_sequence":sequences.first(),"permissive_domains":false}),
    )
}
pub fn ssh_baseline() -> Result<Value> {
    let common: BTreeMap<&str, &str> = [
        ("usepam", "yes"),
        ("pubkeyauthentication", "yes"),
        ("pubkeyauthoptions", "touch-required verify-required"),
        (
            "authorizedkeyscommand",
            "/usr/bin/userdbctl ssh-authorized-keys %u",
        ),
        ("authorizedkeyscommanduser", "root"),
        ("permitrootlogin", "prohibit-password"),
        ("permitemptypasswords", "no"),
        ("kbdinteractiveauthentication", "no"),
        ("disableforwarding", "yes"),
        ("permittunnel", "no"),
        ("x11forwarding", "no"),
        ("allowagentforwarding", "no"),
    ]
    .into_iter()
    .collect();
    let mut result = Map::new();
    for user in ["root", "particleve-policy-probe"] {
        let native = run(&[
            "/usr/sbin/sshd",
            "-T",
            "-C",
            &format!("user={user},host=localhost,addr=127.0.0.1"),
        ])?;
        require(
            native.stderr.trim().is_empty(),
            format!(
                "SSH policy inspection diagnostics: {}",
                native.stderr.trim()
            ),
        )?;
        let values: BTreeMap<_, _> = native
            .stdout
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        let mut expected = common.clone();
        expected.insert(
            "passwordauthentication",
            if user == "root" { "no" } else { "yes" },
        );
        expected.insert(
            "authenticationmethods",
            if user == "root" {
                "publickey"
            } else {
                "publickey,password"
            },
        );
        require(
            expected.iter().all(|(k, v)| values.get(*k) == Some(v)),
            "SSH authentication/forwarding drift",
        )?;
        let algorithms: BTreeSet<_> = values
            .get("pubkeyacceptedalgorithms")
            .copied()
            .unwrap_or("")
            .split(',')
            .collect();
        require(
            [
                "sk-ssh-ed25519@openssh.com",
                "sk-ecdsa-sha2-nistp256@openssh.com",
            ]
            .iter()
            .all(|a| algorithms.contains(a)),
            "FIDO2 SSH key support is missing",
        )?;
        let mut observed = serde_json::to_value(expected)?;
        observed["fido2_key_types"] = json!(true);
        result.insert(
            if user == "root" { "root" } else { "homed" }.into(),
            observed,
        );
    }
    Ok(Value::Object(result))
}
/// Detect equivalent module/sysctl spellings when rejecting overrides.
pub fn kernel_parameter_key(word: &str) -> String {
    word.split('=')
        .next()
        .unwrap_or("")
        .replace('/', ".")
        .replace('-', "_")
}
/// The signed boot policy and the running kernel must agree on enforcement.
pub fn kernel_boot_policy(cmdline: &str, enforcement: &str) -> Result<()> {
    for expected in [
        "module.sig_enforce=1",
        "sysctl.kernel.unprivileged_bpf_disabled=1",
        "sysctl.net.core.bpf_jit_harden=2",
    ] {
        let key = kernel_parameter_key(expected);
        require(
            cmdline
                .split_whitespace()
                .filter(|word| kernel_parameter_key(word) == key)
                .collect::<Vec<_>>()
                == [expected],
            format!("signed early kernel policy differs: {key}"),
        )?;
    }
    require(
        matches!(enforcement.trim(), "Y" | "1"),
        "kernel module-signature enforcement is not enabled",
    )
}
pub fn kernel_baseline(root: &Path) -> Result<Value> {
    let mut trees = Vec::new();
    for entry in fs::read_dir(root.join("usr/lib/modules"))? {
        let entry = entry?;
        if entry.path().is_dir() {
            trees.push(entry.path());
        }
    }
    require(
        trees.len() == 1,
        "security baseline requires exactly one kernel",
    )?;
    let config = trees[0].join("config");
    let contents = String::from_utf8(read_bounded(&config, 8 * 1024 * 1024)?)?;
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        if let Some((key, value)) = line.strip_prefix("CONFIG_").and_then(|s| s.split_once('='))
            && !key.is_empty()
            && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    let policy = runtime_policy()?;
    let missing: Vec<_> = policy
        .kernel_required
        .iter()
        .filter(|name| values.get(*name).map(String::as_str) != Some("y"))
        .map(String::as_str)
        .collect();
    require(
        missing.is_empty(),
        format!("kernel security support missing: {}", missing.join(", ")),
    )?;
    require(
        values.get("RFKILL").is_some_and(|s| s == "y" || s == "m"),
        "kernel RFKill support is missing",
    )?;
    let mut uarts = Map::new();
    for name in ["SERIAL_8250_NR_UARTS", "SERIAL_8250_RUNTIME_UARTS"] {
        let value = values
            .get(name)
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                Error::new(format!(
                    "kernel lacks the four signed serial consoles: {name}"
                ))
            })?;
        require(
            value >= 4,
            format!("kernel lacks the four signed serial consoles: {name}"),
        )?;
        uarts.insert(name.into(), json!(value));
    }
    let required: BTreeMap<_, _> = policy
        .kernel_required
        .iter()
        .map(|k| (k, values[k].clone()))
        .collect();
    Ok(
        json!({"schema":1,"kernel":trees[0].file_name().and_then(|s|s.to_str()).ok_or_else(||Error::new("invalid kernel directory"))?,"config_sha256":hash_file(&config,None)?,"required":required,"module_sig_force":values.get("MODULE_SIG_FORCE").is_some_and(|s|s=="y"),"rfkill":{"core":values.get("RFKILL"),"deprecated_input":values.get("RFKILL_INPUT").is_some_and(|s|s=="y")},"module_signing_key":values.get("MODULE_SIG_KEY"),"iommu_default_strict":values.get("IOMMU_DEFAULT_DMA_STRICT").is_some_and(|s|s=="y"),"runtime_support":crate::kernelruntime::kernel_support(&values)?,"console_uarts":uarts}),
    )
}
pub fn verified_usr_mount() -> Result<Value> {
    let device = Path::new("/dev/mapper/usr").metadata()?;
    require(
        device.file_type().is_block_device(),
        "verified usr mapper is not a block device",
    )?;
    let observed = run(&[
        "findmnt",
        "--json",
        "--target",
        "/usr",
        "--output",
        "TARGET,SOURCE,FSTYPE,MAJ:MIN,FSROOT,VFS-OPTIONS",
    ])?;
    require(
        observed.stderr.is_empty(),
        "verified usr mount inspection produced diagnostics",
    )?;
    let data = parse_json(observed.stdout.as_bytes())?;
    let mounts = list(field(&data, "filesystems")?)?;
    require(mounts.len() == 1, "verified usr mount is ambiguous")?;
    let mount = &mounts[0];
    let options = text(field(mount, "vfs-options")?)?
        .split(',')
        .collect::<BTreeSet<_>>();
    let major_minor = format!(
        "{}:{}",
        libc::major(device.rdev()),
        libc::minor(device.rdev())
    );
    require(
        mount["target"] == "/usr"
            && mount["fstype"] == "erofs"
            && mount["fsroot"] == "/"
            && mount["maj:min"] == major_minor
            && options.contains("ro")
            && !options.contains("rw"),
        "usr is not the unchanged read-only verified EROFS mount",
    )?;
    Ok(json!({"filesystem":mount["fstype"],"device":mount["maj:min"],"readonly":true}))
}
pub fn usr_backing_disks(mapper: &str, sysfs: &Path) -> Result<BTreeSet<String>> {
    require(
        !mapper.is_empty() && !mapper.contains('/') && mapper != "..",
        "invalid usr mapper name",
    )?;
    let device = sysfs.join("class/block").join(mapper);
    require(
        String::from_utf8(read_bounded(device.join("dm/uuid"), 65536)?)?
            .trim()
            .starts_with("CRYPT-VERITY-"),
        "usr is not dm-verity",
    )?;
    let members = fs::read_dir(device.join("slaves"))?.collect::<std::io::Result<Vec<_>>>()?;
    require(members.len() == 2, "unexpected usr verity backing")?;
    let mut disks = BTreeSet::new();
    for member in members {
        let physical = member.path().canonicalize()?;
        require(
            physical.join("partition").is_file(),
            "usr backing is not a physical disk partition",
        )?;
        disks.insert(
            physical
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::new("invalid physical usr backing disk"))?
                .to_owned(),
        );
    }
    Ok(disks)
}
pub fn capabilities(data: &[u8]) -> Result<Value> {
    require(
        data.len() == 20 || data.len() == 24,
        "unsupported file capability record",
    )?;
    let mut words = Vec::new();
    for chunk in data.as_chunks::<4>().0 {
        words.push(u32::from_le_bytes(*chunk));
    }
    let magic = words[0];
    let revision = magic >> 24;
    require(
        [2, 3].contains(&revision)
            && data.len() == if revision == 3 { 24 } else { 20 }
            && magic & 0xfffffe == 0,
        "unsupported file capability flags",
    )?;
    Ok(
        json!({"effective":magic&1!=0,"permitted":u64::from(words[1])|(u64::from(words[3])<<32),"inheritable":u64::from(words[2])|(u64::from(words[4])<<32),"rootid":if revision==3{words[5]}else{0}}),
    )
}
pub fn privilege_inventory(root: &Path, image: Option<&Path>) -> Result<Value> {
    let mut result = Map::new();
    let mut pending = vec![root.join("usr")];
    let ownership = Regex::new(r"(?m)^Uid:\s*(\d+)\s+Gid:\s*(\d+)\s+Access:")
        .map_err(|e| Error::new(e.to_string()))?;
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let info = fs::symlink_metadata(&path)?;
            if info.is_dir() {
                pending.push(path);
                continue;
            }
            if !info.is_file() {
                continue;
            }
            let caps = match get_xattr(&path, "security.capability") {
                Ok(data) => capabilities(&data)?,
                Err(e) if e.is_errno(libc::ENODATA) => Value::Null,
                Err(e) => return Err(e),
            };
            let mode = info.mode() & 0o7777;
            if mode & 0o6000 == 0 && caps.is_null() {
                continue;
            }
            let (mut uid, mut gid) = (u64::from(info.uid()), u64::from(info.gid()));
            if let Some(image) = image {
                let name = format!(
                    "/{}",
                    path.strip_prefix(root.join("usr"))
                        .map_err(|_| Error::new("privileged path escapes usr"))?
                        .to_str()
                        .ok_or_else(|| Error::new("invalid privileged path"))?
                );
                let response = run(&[
                    "dump.erofs",
                    &format!("--path={name}"),
                    image
                        .to_str()
                        .ok_or_else(|| Error::new("invalid image path"))?,
                ])?;
                let rows: Vec<_> = ownership.captures_iter(&response.stdout).collect();
                require(
                    rows.len() == 1,
                    "ambiguous original privileged-file ownership",
                )?;
                uid = rows[0][1]
                    .parse()
                    .map_err(|_| Error::new("invalid original file UID"))?;
                gid = rows[0][2]
                    .parse()
                    .map_err(|_| Error::new("invalid original file GID"))?;
            }
            let name = format!(
                "/{}",
                path.strip_prefix(root)
                    .map_err(|_| Error::new("privileged path escapes root"))?
                    .to_str()
                    .ok_or_else(|| Error::new("invalid privileged path"))?
            );
            result.insert(
                name,
                json!({"mode":format!("{mode:04o}"),"uid":uid,"gid":gid,"capabilities":caps}),
            );
        }
    }
    Ok(Value::Object(result))
}
fn without_purpose(record: &Value) -> Result<Value> {
    let mut value = object(record)?.clone();
    value.remove("purpose");
    Ok(Value::Object(value))
}
pub fn check_privileges(root: &Path, image: Option<&Path>) -> Result<Value> {
    let policy = read_json(root.join(POLICY))?;
    require(
        policy["schema"] == json!(1),
        "unknown image privilege policy",
    )?;
    let allowed = object(field(&policy, "privileged_files")?)?;
    let mut expected = Map::new();
    for (path, record) in allowed {
        require(
            path.starts_with("/usr/")
                && record
                    .get("purpose")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty()),
            "privilege needs a reviewed purpose",
        )?;
        let mode = u32::from_str_radix(text(field(record, "mode")?)?, 8)
            .map_err(|_| Error::new("invalid privileged-file mode"))?;
        require(
            record["uid"] == json!(0) && mode & 0o022 == 0,
            "unsafe privileged-file owner/mode",
        )?;
        expected.insert(path.clone(), without_purpose(record)?);
    }
    let actual = privilege_inventory(root, image)?;
    require(
        actual == Value::Object(expected),
        "image privileged-file inventory differs from the reviewed policy",
    )?;
    Ok(actual)
}
pub fn process_evidence(identity: &Identity, proc: &Path) -> Result<Value> {
    let fields = [
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    ];
    let process = Process::open(identity.pid, Some(identity.starttime), proc)?;
    let status = process.status()?;
    require(
        fields.iter().all(|f| status.contains_key(*f)),
        "incomplete process security status",
    )?;
    let args = process.arguments()?;
    let mut options = Map::new();
    let mut total = 0usize;
    for option in ["-sandbox", "-accel", "-machine", "-cpu", "-run-with"] {
        let values: Vec<_> = args
            .windows(2)
            .filter(|pair| pair[0] == option)
            .map(|pair| {
                total = total.saturating_add(pair[1].len());
                pair[1].clone()
            })
            .collect();
        options.insert(option.into(), json!(values));
    }
    require(
        total <= 65536,
        "process security options exceed their evidence bound",
    )?;
    let mut devices = BTreeSet::new();
    for fd in process.entries("fd", MAX_FDS)? {
        let info = match process.stat(&format!("fd/{fd}")) {
            Ok(v) => v,
            Err(e) if e.is_not_found() => continue,
            Err(e) => return Err(e),
        };
        if info.file_type().is_char_device() {
            devices.insert(format!(
                "{}:{}",
                libc::major(info.rdev()),
                libc::minor(info.rdev())
            ));
        }
    }
    let mut namespaces = Map::new();
    for name in process.entries("ns", MAX_NAMESPACES)? {
        namespaces.insert(
            name.clone(),
            json!(
                process
                    .readlink(&format!("ns/{name}"))?
                    .to_str()
                    .ok_or_else(|| Error::new("invalid namespace link encoding"))?
            ),
        );
    }
    let status: BTreeMap<_, _> = fields.into_iter().map(|f| (f, status[f].clone())).collect();
    Ok(
        json!({"pid":identity.pid,"starttime":identity.starttime,"status":status,"selinux":process.text("attr/current",4096)?.trim_end_matches(['\0','\n']),"namespaces":namespaces,"character_devices":devices,"security_options":options}),
    )
}
pub fn firmware_evidence() -> Result<Value> {
    let firmware = command(
        &["fwupdmgr", "security", "--json"].map(str::to_owned),
        None,
        Some(Duration::from_secs(60)),
        256 * 1024,
        false,
    )?;
    require(
        firmware.stderr.trim().is_empty(),
        "fwupd security inspection produced diagnostics",
    )?;
    let data = parse_json(firmware.stdout.as_bytes())?;
    require(data.is_object(), "invalid fwupd security response")?;
    if firmware.code != 0 {
        require(
            data.get("Error").is_some_and(Value::is_object),
            "unknown fwupd security failure",
        )?;
        return Ok(json!({"available":false,"reason":data["Error"],"attributes":[]}));
    }
    let attributes = list(field(&data, "SecurityAttributes")?)?;
    require(
        !attributes.is_empty() && attributes.iter().all(Value::is_object),
        "unknown/empty fwupd security attributes",
    )?;
    Ok(json!({"available":true,"attributes":attributes}))
}
pub fn live_baseline(root: &Path, evidence: bool, kcore: &Path) -> Result<Value> {
    let mut baseline = kernel_baseline(root)?;
    baseline["kernel_runtime"] = crate::kernelruntime::baseline(
        Path::new("/proc"),
        Path::new("/dev"),
        kcore,
        boolean(field(field(&baseline, "runtime_support")?, "kexec_core")?)?,
    )?;
    require(
        baseline["runtime_support"]["proc_kcore"] == baseline["kernel_runtime"]["root_only_kcore"],
        "kernel core metadata availability differs from the verified kernel configuration",
    )?;
    baseline["memory_privacy"] =
        crate::memoryprivacy::baseline(Path::new("/proc"), Path::new("/sys"))?;
    baseline["resource_controllers"] = json!(crate::resourceusage::controllers(Path::new(
        "/sys/fs/cgroup"
    ))?);
    baseline["landlock_abi"] = json!(crate::landlock::abi_version()?);
    let mut uname = std::mem::MaybeUninit::<libc::utsname>::uninit(); // SAFETY: uname initializes this entire ABI record on success.
    require(
        unsafe { libc::uname(uname.as_mut_ptr()) } == 0,
        "cannot inspect running kernel",
    )?; // SAFETY: successful uname initialized the fixed-size NUL-terminated release field.
    let uname = unsafe { uname.assume_init() };
    let release = unsafe { CStr::from_ptr(uname.release.as_ptr()) }
        .to_str()
        .map_err(|_| Error::new("invalid running kernel release"))?;
    require(
        baseline["kernel"] == release,
        "running kernel differs from verified /usr",
    )?;
    let cmdline = String::from_utf8(read_bounded("/proc/cmdline", 1024 * 1024)?)?;
    require(
        cmdline
            .split_whitespace()
            .any(|s| s == "systemd.ssh_auto=no"),
        "automatic SSH socket generation is enabled",
    )?;
    let lockdown = String::from_utf8(read_bounded("/sys/kernel/security/lockdown", 65536)?)?;
    let re = Regex::new(r"\[(\w+)\]").map_err(|e| Error::new(e.to_string()))?;
    let selected: Vec<_> = re
        .captures_iter(&lockdown)
        .map(|c| c[1].to_owned())
        .collect();
    require(
        selected == ["integrity"] || selected == ["confidentiality"],
        "kernel lockdown is not enforced",
    )?;
    let enforcement = String::from_utf8(read_bounded(
        "/sys/module/module/parameters/sig_enforce",
        65536,
    )?)?
    .trim()
    .to_owned();
    kernel_boot_policy(&cmdline, &enforcement)?;
    let mut nested = Map::new();
    for entry in fs::read_dir("/sys/module")? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::new("invalid module name"))?;
        let path = entry.path().join("parameters/nested");
        if name.starts_with("kvm_") && path.try_exists()? {
            nested.insert(
                name,
                json!(String::from_utf8(read_bounded(path, 65536)?)?.trim()),
            );
        }
    }
    require(
        !nested.is_empty() && nested.values().all(|v| v == "N" || v == "0"),
        "nested virtualization is enabled",
    )?;
    baseline["lockdown"] = json!(selected[0]);
    baseline["module_sig_enforce"] = json!(enforcement);
    baseline["nested"] = Value::Object(nested);
    baseline["allocator"] = crate::allocator::host_policy()?;
    if !evidence {
        return Ok(baseline);
    }
    baseline["physical_interfaces"] = crate::physical::collect(Path::new("/sys"))?;
    let mut keys = Map::new();
    for name in [
        ".builtin_trusted_keys",
        ".secondary_trusted_keys",
        ".machine",
        ".platform",
    ] {
        keys.insert(
            name.into(),
            json!(run(&["keyctl", "list", &format!("%:{name}")])?.stdout),
        );
    }
    baseline["accepted_keyrings"] = Value::Object(keys);
    let mut vulnerabilities = Map::new();
    for entry in fs::read_dir("/sys/devices/system/cpu/vulnerabilities")? {
        let entry = entry?;
        vulnerabilities.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| Error::new("invalid CPU vulnerability name"))?,
            json!(String::from_utf8(read_bounded(entry.path(), 65536)?)?.trim()),
        );
    }
    baseline["cpu_vulnerabilities"] = Value::Object(vulnerabilities);
    let cpuinfo = String::from_utf8(read_bounded("/proc/cpuinfo", 8 * 1024 * 1024)?)?;
    let re = Regex::new(r"(?m)^microcode\s*:\s*(.+)$").map_err(|e| Error::new(e.to_string()))?;
    baseline["microcode"] = json!(
        re.captures_iter(&cpuinfo)
            .map(|c| c[1].to_owned())
            .collect::<BTreeSet<_>>()
    );
    baseline["iommu_groups"] = json!(
        fs::read_dir("/sys/kernel/iommu_groups")?
            .collect::<std::io::Result<Vec<_>>>()?
            .len()
    );
    baseline["firmware_security"] = firmware_evidence()?;
    Ok(baseline)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_boot_policy_requires_unique_signed_flags_and_enabled_module_enforcement() {
        let policy = "module.sig_enforce=1 sysctl.kernel.unprivileged_bpf_disabled=1 sysctl.net.core.bpf_jit_harden=2";
        for enabled in ["Y", "1", "Y\n"] {
            kernel_boot_policy(policy, enabled).unwrap();
        }
        for disabled in ["N", "0", "", "unknown"] {
            assert!(kernel_boot_policy(policy, disabled).is_err());
        }
        for word in policy.split_whitespace() {
            let key = word.split('=').next().unwrap();
            let alias = if let Some(path) = key.strip_prefix("sysctl.") {
                format!("sysctl.{}", path.replace('.', "/"))
            } else {
                key.replace('_', "-")
            };
            for cmdline in [
                policy.replace(word, ""),
                format!("{policy} {key}=0"),
                format!("{policy} {word}"),
                format!("{policy} {alias}=0"),
            ] {
                assert!(kernel_boot_policy(&cmdline, "Y").is_err(), "{cmdline}");
            }
        }
    }
    #[test]
    fn file_capability_revision_and_flags_are_strict() {
        let mut bytes = vec![0u8; 20];
        bytes[..4].copy_from_slice(&(0x02000001u32).to_le_bytes());
        bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            capabilities(&bytes).unwrap(),
            json!({"effective":true,"permitted":4,"inheritable":0,"rootid":0})
        );
        bytes[0] |= 2;
        assert!(capabilities(&bytes).is_err());
        assert!(capabilities(&[0; 24]).is_err());
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn runtime_policy_schema_is_exact_and_shared() {
        let policy = runtime_policy().unwrap();
        assert_eq!(policy.schema, 1);
        assert_eq!(policy.sysctls["vm.memfd_noexec"], "1");
        assert_eq!(policy.tpm_profile["Name"], "custom:particleve");
        let original = parse_json(include_bytes!("../particleve/runtime-policy.json")).unwrap();
        for mutation in [
            json!({"schema":2}),
            json!({"extra":true}),
            json!({"kernel_required":["SECCOMP","SECCOMP"]}),
            json!({"sysctls":{}}),
            json!({"tpm_profile":{"Name":"custom:particleve","Attributes":"policy","extra":"bad"}}),
            json!({"selinux_booleans":{"virt_use_execmem":"off"}}),
        ] {
            let mut value = original.clone();
            for (k, v) in mutation.as_object().unwrap() {
                value[k] = v.clone();
            }
            assert!(parse_runtime_policy(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn evidence_exports_only_selected_options_not_credentials() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("123");
        fs::create_dir_all(directory.join("attr")).unwrap();
        fs::create_dir(directory.join("ns")).unwrap();
        fs::create_dir(directory.join("fd")).unwrap();
        let mut stat = vec!["0"; 20];
        stat[0] = "S";
        stat[19] = "77";
        fs::write(
            directory.join("stat"),
            format!("123 (qemu) {}", stat.join(" ")),
        )
        .unwrap();
        fs::write(directory.join("status"),"Uid:\t0 0 0 0\nGid:\t0 0 0 0\nGroups:\nCapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\nNoNewPrivs: 1\nSeccomp: 2\nSeccomp_filters: 1\n").unwrap();
        fs::write(
            directory.join("attr/current"),
            "system_u:system_r:svirt_t:s0:c10,c20\0\n",
        )
        .unwrap();
        fs::write(
            directory.join("cmdline"),
            b"qemu\0-fw_cfg\0secret-sensitive-credential\0-machine\0q35\0",
        )
        .unwrap();
        symlink("mnt:[123]", directory.join("ns/mnt")).unwrap();
        symlink("/dev/null", directory.join("fd/0")).unwrap();
        let evidence = process_evidence(
            &Identity {
                pid: 123,
                starttime: 77,
            },
            root.path(),
        )
        .unwrap();
        assert!(!evidence.to_string().contains("secret-sensitive-credential"));
        assert_eq!(evidence["security_options"]["-machine"], json!(["q35"]));
        assert_eq!(evidence["namespaces"]["mnt"], "mnt:[123]");
        assert_eq!(evidence["character_devices"], json!(["1:3"]));
        assert!(
            process_evidence(
                &Identity {
                    pid: 123,
                    starttime: 78
                },
                root.path()
            )
            .is_err()
        );
    }
}
