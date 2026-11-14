//! Fail-closed native VM launch contract; provisioning owns persistent labels.
use crate::common::{Error, Result, read_bounded, require};
use crate::memoryprivacy::process_policy;
use crate::processes::{Identity, Process};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::Command;
pub const MACHINES: &str = "/var/lib/machines";
pub const RUNTIME: &str = "/run/particleve-vm";
pub const GATE: &str = "/run/particleve/vm-start-inhibited";
pub const CONTROLLER: &str = "particleve_vmspawn_t";
pub const QEMU_HANDOFF: &str = "/usr/libexec/particleve-qemu/qemu";
pub const SWTPM_HANDOFF: &str = "/usr/libexec/particleve-swtpm/swtpm";
pub const PTY_ALLOC: &str = "system_u:object_r:particleve_vmspawn_pty_alloc_t:s0:c0.c1023";
pub const PTY_TYPE: &str = "particleve_vmspawn_devpts_t";
pub const QEMU_SANDBOX: &str =
    "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny";
pub const QEMU_MEMORY_PRIVACY: &str = "mem-merge=off,dump-guest-core=off";
pub const VM_ADDRESS_FAMILIES: &[&str] = &[
    "AF_UNIX",
    "AF_NETLINK",
    "AF_INET",
    "AF_INET6",
    "AF_PACKET",
    "AF_VSOCK",
];
pub const CONTROLLER_CAPABILITIES: &[&str] = &[
    "cap_setfcap",
    "cap_setgid",
    "cap_setpcap",
    "cap_setuid",
    "cap_sys_admin",
    "cap_sys_resource",
];
pub const VM_CHILD_PRIVILEGES: &[&str] = &[
    "--no-new-privs",
    "--bounding-set=-all",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--clear-groups",
    "--",
];
#[link(name = "libselinux.so.1", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn fgetfilecon(fd: libc::c_int, context: *mut *mut libc::c_char) -> libc::c_int;
    fn fsetfilecon(fd: libc::c_int, context: *const libc::c_char) -> libc::c_int;
    fn freecon(context: *mut libc::c_char);
}
pub fn matches(pattern: &str, value: &str) -> Result<bool> {
    Ok(Regex::new(pattern)
        .map_err(|e| Error::new(e.to_string()))?
        .is_match(value))
}
pub fn qemu_arguments(arguments: &[String]) -> Result<Vec<String>> {
    let mut result = arguments.to_vec();
    let mut selected = Vec::new();
    for (index, arg) in result.iter().enumerate() {
        if arg.starts_with('-') && arg.trim_start_matches('-').split('=').next() == Some("sandbox")
        {
            require(
                arg == "-sandbox" && index + 1 < result.len(),
                "unsupported QEMU sandbox override",
            )?;
            selected.push(result[index + 1].as_str());
        }
    }
    require(
        selected.is_empty() || selected == [QEMU_SANDBOX],
        "QEMU syscall sandbox must not be weakened",
    )?;
    if selected.is_empty() {
        result.extend(["-sandbox".to_owned(), QEMU_SANDBOX.to_owned()]);
    }
    if result.len() < 2 || result[result.len() - 2..] != ["-machine", QEMU_MEMORY_PRIVACY] {
        result.extend(["-machine".to_owned(), QEMU_MEMORY_PRIVACY.to_owned()]);
    }
    Ok(result)
}
pub fn verify_child_privileges(process: &Process) -> Result<()> {
    let values = process.status()?;
    let value = |name: &str| values.get(name).map(String::as_str).unwrap_or("");
    require(
        value("Seccomp") == "2"
            && matches(r"\A[1-9][0-9]{0,9}\z", value("Seccomp_filters"))?
            && value("NoNewPrivs") == "1",
        "VM child syscall filtering is not active",
    )?;
    require(
        ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]
            .iter()
            .all(|name| {
                let s = value(name);
                !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b == b'0')
            })
            && values.get("Groups").map(String::as_str) == Some(""),
        "VM child retained capabilities or supplementary groups",
    )
}
pub fn verify_qemu_sandbox(process: &Process) -> Result<()> {
    verify_child_privileges(process)?;
    let args = process.arguments()?;
    require(
        args.iter().filter(|a| a.as_str() == "-sandbox").count() == 1
            && qemu_arguments(&args)? == args,
        "QEMU's own sandbox is missing",
    )?;
    process_policy(process, true)
}
pub fn check_unit_values(values: &BTreeMap<String, String>) -> Result<()> {
    let value = |name: &str| values.get(name).map(String::as_str).unwrap_or("");
    require(
        value("ExecStart").contains("path=/usr/libexec/particleve-vm-run "),
        "external unit must launch the native runner through particleve-vm-run",
    )?;
    require(
        value("ExecStop").contains("particleve-vm-stop"),
        "VM synchronous stop helper is required",
    )?;
    require(
        value("CapabilityBoundingSet")
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            == CONTROLLER_CAPABILITIES.iter().copied().collect(),
        "VM trusted-launcher capabilities changed",
    )?;
    require(
        value("SystemCallArchitectures") == "native",
        "VM host syscall ABI restriction changed",
    )?;
    for field in ["IOAccounting", "MemoryAccounting", "TasksAccounting"] {
        require(
            value(field) == "yes",
            format!("VM resource accounting changed: {field}"),
        )?;
    }
    let mut limits = BTreeMap::new();
    for field in ["MemoryHigh", "MemoryMax", "TasksMax"] {
        let s = value(field);
        require(
            matches(r"\A[1-9][0-9]{0,19}\z", s)?,
            format!("external VM unit needs a finite positive {field}"),
        )?;
        let amount: u64 = s
            .parse()
            .map_err(|_| Error::new("native resource limit exceeds supported range"))?;
        limits.insert(field, amount);
    }
    require(
        limits["MemoryHigh"] < limits["MemoryMax"],
        "VM MemoryHigh must be below MemoryMax",
    )?;
    require(
        value("OOMPolicy") == "kill" && value("OOMScoreAdjust") == "0",
        "VM group OOM policy changed",
    )?;
    require(
        value("RestrictAddressFamilies")
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            == VM_ADDRESS_FAMILIES.iter().copied().collect(),
        "VM host socket-family restriction changed",
    )?;
    for (field, expected) in [
        ("KillMode", "mixed"),
        ("KillSignal", "15"),
        ("WatchdogSignal", "15"),
        ("SendSIGKILL", "no"),
        ("TimeoutStartUSec", "infinity"),
        ("TimeoutStopUSec", "infinity"),
        ("TimeoutAbortUSec", "infinity"),
        ("NotifyAccess", "all"),
        ("ExitType", "cgroup"),
        ("LimitCORE", "0"),
        ("LimitCORESoft", "0"),
        ("CoredumpFilter", "0x0"),
    ] {
        require(
            value(field) == expected,
            format!("VM lifecycle protection overridden: {field}"),
        )?;
    }
    Ok(())
}
pub fn check_unit_contract(unit: &str) -> Result<()> {
    let mut args = vec!["systemctl".to_owned(), "show".to_owned(), unit.to_owned()];
    for field in [
        "ExecStart",
        "ExecStop",
        "KillMode",
        "KillSignal",
        "WatchdogSignal",
        "SendSIGKILL",
        "TimeoutStartUSec",
        "TimeoutStopUSec",
        "TimeoutAbortUSec",
        "NotifyAccess",
        "ExitType",
        "CapabilityBoundingSet",
        "SystemCallArchitectures",
        "RestrictAddressFamilies",
        "LimitCORE",
        "LimitCORESoft",
        "CoredumpFilter",
        "IOAccounting",
        "MemoryAccounting",
        "TasksAccounting",
        "MemoryHigh",
        "MemoryMax",
        "TasksMax",
        "OOMPolicy",
        "OOMScoreAdjust",
    ] {
        args.push(format!("--property={field}"));
    }
    let result = crate::common::command(
        &args,
        None,
        Some(std::time::Duration::from_secs(120)),
        8 * 1024 * 1024,
        true,
    )?;
    require(
        result.stderr.is_empty(),
        "native VM unit inspection produced diagnostics",
    )?;
    check_unit_values(
        &result
            .stdout
            .lines()
            .filter_map(|s| s.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    )
}
pub fn context(value: &str, expected_type: &str) -> Result<[u16; 2]> {
    let parts: Vec<_> = value
        .trim_end_matches(['\0', '\n'])
        .splitn(5, ':')
        .collect();
    require(
        parts.len() == 5 && parts[2] == expected_type && parts[3] == "s0",
        "unexpected VM SELinux context",
    )?;
    let re = Regex::new(r"\Ac([0-9]+)(?:\.c([0-9]+))?\z").map_err(|e| Error::new(e.to_string()))?;
    let mut categories = Vec::new();
    for item in parts[4].split(',') {
        let capture = re
            .captures(item)
            .ok_or_else(|| Error::new("invalid VM MCS category"))?;
        let first: u16 = capture[1]
            .parse()
            .map_err(|_| Error::new("invalid VM MCS category"))?;
        let last: u16 = capture.get(2).map_or(Ok(first), |m| {
            m.as_str()
                .parse()
                .map_err(|_| Error::new("invalid VM MCS category"))
        })?;
        require(
            first <= last && last < 1024 && last - first <= 1,
            "VM needs exactly two MCS categories",
        )?;
        categories.extend(first..=last);
        require(
            categories.len() <= 2,
            "VM needs exactly two distinct MCS categories",
        )?;
    }
    require(
        categories.len() == 2 && categories[0] != categories[1],
        "VM needs exactly two distinct MCS categories",
    )?;
    categories.sort_unstable();
    Ok([categories[0], categories[1]])
}
pub fn get_xattr(path: &Path, name: &str) -> Result<Vec<u8>> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::new("invalid attribute path"))?;
    let name = CString::new(name).map_err(|_| Error::new("invalid attribute name"))?;
    let mut bytes = vec![0u8; 65536];
    // SAFETY: C strings live for the call, lgetxattr never follows the terminal symlink,
    // and at most the initialized 64-KiB buffer is written. Oversized attributes fail.
    let count = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    bytes.truncate(count as usize);
    Ok(bytes)
}
pub fn label(path: &Path) -> Result<String> {
    Ok(String::from_utf8(get_xattr(path, "security.selinux")?)?)
}
pub fn private_directory(path: &Path) -> Result<fs::Metadata> {
    let info = fs::symlink_metadata(path)?;
    require(
        info.is_dir() && info.uid() == 0 && info.mode() & 0o7777 == 0o700,
        format!(
            "VM directory must be a root-owned, nonsymlink directory with mode 0700: {}",
            path.display()
        ),
    )?;
    Ok(info)
}
fn which(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|p| p.join(name))
        .find(|path| {
            let Ok(c) = CString::new(path.as_os_str().as_bytes()) else {
                return false;
            }; // SAFETY: access reads only this terminated path and retains no memory.
            path.is_file() && unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0
        })
}
pub fn check_tpm_arguments(name: &str, command: &[String]) -> Result<()> {
    let options: Vec<_> = command
        .iter()
        .filter(|arg| ["--tpm", "--tpm-state"].contains(&arg.split('=').next().unwrap_or("")))
        .collect();
    require(
        options.iter().all(|arg| arg.contains('=')),
        "use explicit --tpm= and --tpm-state= arguments",
    )?;
    let modes: Vec<_> = options
        .iter()
        .filter_map(|arg| arg.strip_prefix("--tpm="))
        .collect();
    let paths: Vec<_> = options
        .iter()
        .filter_map(|arg| arg.strip_prefix("--tpm-state="))
        .collect();
    require(
        modes == ["no"] || modes == ["yes"],
        "declare --tpm=no or --tpm=yes exactly once",
    )?;
    if modes == ["no"] {
        return require(
            paths.is_empty(),
            "disabled TPM must not select retained state",
        );
    }
    require(
        paths.len() == 1,
        "enabled TPM requires one explicitly provisioned state directory",
    )?;
    require(
        which("swtpm").as_deref() == Some(Path::new(SWTPM_HANDOFF)),
        "VM TPM requires the guarded swtpm handoff",
    )?;
    let state = Path::new(paths[0]);
    let root = Path::new(MACHINES).join(name);
    require(
        state.parent() == Some(root.as_path())
            && state.file_name().is_some()
            && !paths[0].ends_with("/.")
            && !paths[0].ends_with("/.."),
        "TPM state must be inside its VM subvolume",
    )?;
    private_directory(state)?;
    let categories = context(&label(&root)?, "virt_var_lib_t")?;
    require(
        context(&label(state)?, "virt_var_lib_t")? == categories,
        "TPM directory categories differ",
    )?;
    let permanent = state.join("tpm2-00.permall");
    let info = fs::symlink_metadata(&permanent)?;
    RetainedTpmMetadata {
        regular: info.is_file(),
        uid: info.uid(),
        gid: info.gid(),
        mode: info.mode(),
        size: info.len(),
        links: info.nlink(),
    }
    .validate()?;
    require(
        context(&label(&permanent)?, "virt_var_lib_t")? == categories,
        "TPM state categories differ",
    )
}
struct RetainedTpmMetadata {
    regular: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    links: u64,
}
impl RetainedTpmMetadata {
    fn validate(&self) -> Result<()> {
        require(
            self.regular
                && self.uid == 0
                && self.gid == 0
                && self.mode & 0o007 == 0
                && self.size > 0
                && self.links == 1,
            "provision a fresh private TPM with the image's profile before enabling it; retained state is never reset",
        )
    }
}
fn check_storage_categories<L>(
    root: &Path,
    machines: &Path,
    categories: [u16; 2],
    mut read_label: L,
) -> Result<()>
where
    L: FnMut(&Path) -> Result<String>,
{
    require(
        context(&read_label(root)?, "virt_var_lib_t")? == categories,
        "VM subvolume and unit categories differ",
    )?;
    for entry in fs::read_dir(machines)? {
        let other = entry?.path();
        if other == root || !other.is_dir() {
            continue;
        }
        require(
            !fs::symlink_metadata(&other)?.is_symlink(),
            "symlink in VM storage inventory",
        )?;
        require(
            context(&read_label(&other)?, "virt_var_lib_t")? != categories,
            format!(
                "VM MCS category pair is already assigned: {}",
                other.display()
            ),
        )?;
    }
    Ok(())
}
pub fn own_cgroup() -> Result<String> {
    let value = String::from_utf8(read_bounded("/proc/self/cgroup", 1024 * 1024)?)?;
    let groups: Vec<_> = value
        .lines()
        .filter_map(|s| s.strip_prefix("0::"))
        .collect();
    require(groups.len() == 1, "VM helper requires its owning unit")?;
    Ok(groups[0].to_owned())
}
fn launch_authority<G>(uid: u32, inhibited: G) -> Result<()>
where
    G: FnOnce() -> Result<bool>,
{
    require(uid == 0, "VM launch requires root")?;
    require(
        !inhibited()?,
        "VM starts are temporarily inhibited for OS maintenance",
    )
}
pub fn start_guard(name: &str) -> Result<[u16; 2]> {
    crate::allocator::current()?;
    // SAFETY: geteuid only reads the calling task's identity.
    launch_authority(unsafe { libc::geteuid() }, || {
        Ok(Path::new(GATE).try_exists()?)
    })?;
    require(
        String::from_utf8(read_bounded("/sys/fs/selinux/enforce", 65536)?)?.trim() == "1",
        "VM launch requires SELinux enforcing",
    )?;
    // SAFETY: /dev/kvm is a static terminated path and access performs no device I/O.
    require(
        unsafe { libc::access(c"/dev/kvm".as_ptr(), libc::R_OK | libc::W_OK) } == 0,
        "KVM acceleration is required",
    )?;
    require(
        which("qemu").as_deref() == Some(Path::new(QEMU_HANDOFF)),
        "VM launch requires the guarded QEMU handoff",
    )?;
    require(
        matches(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]*\z", name)?,
        "invalid VM instance name",
    )?;
    let unit = format!("systemd-vmspawn@{name}.service");
    require(
        Path::new(&own_cgroup()?).file_name() == Some(std::ffi::OsStr::new(&unit)),
        "VM guard must run in its owning unit",
    )?;
    check_unit_contract(&unit)?;
    let categories = context(
        &String::from_utf8(read_bounded("/proc/self/attr/current", 4096)?)?,
        CONTROLLER,
    )?;
    let root = Path::new(MACHINES).join(name);
    require(
        private_directory(&root)?.ino() == 256,
        "VM root must be a Btrfs subvolume",
    )?;
    check_storage_categories(&root, Path::new(MACHINES), categories, label)?;
    let runtime = Path::new(RUNTIME).join(name);
    private_directory(&runtime)?;
    require(
        label(&runtime)?.split(':').nth(2) == Some("qemu_var_run_t"),
        "unexpected VM runtime directory type",
    )?;
    let path = CString::new(runtime.as_os_str().as_bytes())
        .map_err(|_| Error::new("invalid VM runtime path"))?;
    let value = format!(
        "system_u:object_r:qemu_var_run_t:s0:c{},c{}\0",
        categories[0], categories[1]
    );
    // SAFETY: only PID1's private ephemeral directory is relabelled; retained guest data is untouched.
    require(
        unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                c"security.selinux".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        } == 0,
        "cannot label VM runtime directory",
    )?;
    Ok(categories)
}
fn owning_name() -> Result<String> {
    owning_name_from_group(&own_cgroup()?)
}
fn owning_name_from_group(group: &str) -> Result<String> {
    let unit = Path::new(group)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::new("VM handoff requires its owning unit"))?;
    let name = unit
        .strip_prefix("systemd-vmspawn@")
        .and_then(|s| s.strip_suffix(".service"))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::new("VM handoff requires its owning unit"))?;
    Ok(name.to_owned())
}
fn descriptor_label(fd: i32) -> Result<String> {
    let mut ptr = std::ptr::null_mut(); // SAFETY: libselinux allocates the NUL-terminated context and initializes ptr on success.
    let status = unsafe { fgetfilecon(fd, &mut ptr) };
    require(
        status >= 0 && !ptr.is_null(),
        "cannot inspect native console label",
    )?;
    struct Context(*mut libc::c_char);
    impl Drop for Context {
        fn drop(&mut self) {
            // SAFETY: libselinux owns this allocation and requires freecon exactly once.
            unsafe { freecon(self.0) };
        }
    }
    let owned = Context(ptr); // SAFETY: successful fgetfilecon returned an allocated C string, kept alive by owned.
    Ok(unsafe { CStr::from_ptr(owned.0) }
        .to_str()
        .map_err(|_| Error::new("invalid console label encoding"))?
        .to_owned())
}
fn exec_child(binary: &str, arguments: &[String]) -> Result<()> {
    let limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    }; // SAFETY: setrlimit copies this aligned live fixed-size record; affects only this child.
    require(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limits) } == 0,
        "cannot disable VM core dumps",
    )?;
    // exec preserves vmspawn's native TAP/QMP/drive descriptors, UID and retained identity.
    let error = child_command(binary, arguments).exec();
    Err(error.into())
}
fn child_command(binary: &str, arguments: &[String]) -> Command {
    let mut command = Command::new("/usr/bin/setpriv");
    command
        .args(VM_CHILD_PRIVILEGES)
        .arg(binary)
        .args(arguments);
    command
}
fn label_console<G, S>(pair: [u16; 2], mut get: G, set: S) -> Result<()>
where
    G: FnMut() -> Result<String>,
    S: FnOnce() -> Result<()>,
{
    let mut current = get()?;
    if current == PTY_ALLOC {
        set()?;
        current = get()?;
    }
    require(
        context(&current, PTY_TYPE)? == pair,
        "native console and VM categories differ",
    )
}
pub fn qemu_handoff(arguments: &[String]) -> Result<()> {
    let pair = start_guard(&owning_name()?)?;
    let arguments = qemu_arguments(arguments)?;
    let target = CString::new(format!(
        "system_u:object_r:{PTY_TYPE}:s0:c{},c{}",
        pair[0], pair[1]
    ))
    .map_err(|_| Error::new("invalid console label"))?;
    for fd in [0, 1, 2] {
        // SAFETY: isatty only inspects an inherited descriptor and transfers no ownership.
        if unsafe { libc::isatty(fd) } == 0 {
            continue;
        }
        label_console(
            pair,
            || descriptor_label(fd),
            || {
                // SAFETY: target stays live and only this inherited console descriptor is relabelled.
                require(
                    unsafe { fsetfilecon(fd, target.as_ptr()) } == 0,
                    "cannot label native console",
                )
            },
        )?;
    }
    exec_child("/usr/bin/qemu-kvm", &arguments)
}
pub fn swtpm_handoff(arguments: &[String]) -> Result<()> {
    let name = owning_name()?;
    require(
        arguments.first().map(String::as_str) == Some("socket"),
        "VM TPM requires the native socket transport",
    )?;
    start_guard(&name)?;
    exec_child("/usr/bin/swtpm", arguments)
}
pub fn verify_processes(processes: &[Identity], proc: &Path) -> Result<()> {
    let mut categories = None;
    let mut types = BTreeSet::new();
    for entry in processes {
        let process = Process::open(entry.pid, Some(entry.starttime), proc)?;
        crate::allocator::process_policy(&process)?;
        let current = process.text("attr/current", 4096)?;
        let kind = current
            .split(':')
            .nth(2)
            .ok_or_else(|| Error::new("invalid VM SELinux context"))?;
        require(
            [CONTROLLER, "svirt_t", "swtpm_t"].contains(&kind),
            "VM unit contains an unexpected or unconfined process",
        )?;
        let pair = context(&current, kind)?;
        if let Some(expected) = categories {
            require(
                pair == expected,
                "VM processes have different MCS categories",
            )?;
        } else {
            categories = Some(pair);
        }
        types.insert(kind.to_owned());
        if kind == "svirt_t" {
            verify_qemu_sandbox(&process)?;
        } else {
            if kind == "swtpm_t" {
                verify_child_privileges(&process)?;
            }
            process_policy(&process, false)?;
        }
    }
    require(
        types.contains(CONTROLLER) && types.contains("svirt_t"),
        "VM controller or confined QEMU is missing",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn categories_are_exact() {
        assert_eq!(
            context("system_u:system_r:svirt_t:s0:c20,c10\0", "svirt_t").unwrap(),
            [10, 20]
        );
        assert_eq!(
            context("system_u:system_r:svirt_t:s0:c10.c11", "svirt_t").unwrap(),
            [10, 11]
        );
        for bad in [
            "s:u:svirt_t:s0:c0.c1023",
            "s:u:svirt_t:s0:c10,c10",
            "s:u:svirt_t:s0:c10,c20,c30",
            "s:u:svirt_t:s0:c1024,c0",
        ] {
            assert!(context(bad, "svirt_t").is_err());
        }
    }
    #[test]
    fn sandbox_is_mandatory_and_idempotent() {
        let result = qemu_arguments(&[]).unwrap();
        assert_eq!(qemu_arguments(&result).unwrap(), result);
        for args in [
            vec!["--sandbox=off".to_owned()],
            vec!["-sandbox".to_owned(), "off".to_owned()],
        ] {
            assert!(qemu_arguments(&args).is_err());
        }
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    fn unit() -> BTreeMap<String, String> {
        let mut values: BTreeMap<String, String> = [
            (
                "ExecStart",
                "{ path=/usr/libexec/particleve-vm-run ; argv[]=... }",
            ),
            ("ExecStop", "particleve-vm-stop"),
            ("SystemCallArchitectures", "native"),
            ("IOAccounting", "yes"),
            ("MemoryAccounting", "yes"),
            ("TasksAccounting", "yes"),
            ("MemoryHigh", "1024"),
            ("MemoryMax", "2048"),
            ("TasksMax", "64"),
            ("OOMPolicy", "kill"),
            ("OOMScoreAdjust", "0"),
            ("KillMode", "mixed"),
            ("KillSignal", "15"),
            ("WatchdogSignal", "15"),
            ("SendSIGKILL", "no"),
            ("TimeoutStartUSec", "infinity"),
            ("TimeoutStopUSec", "infinity"),
            ("TimeoutAbortUSec", "infinity"),
            ("NotifyAccess", "all"),
            ("ExitType", "cgroup"),
            ("LimitCORE", "0"),
            ("LimitCORESoft", "0"),
            ("CoredumpFilter", "0x0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        values.insert(
            "CapabilityBoundingSet".into(),
            CONTROLLER_CAPABILITIES.join(" "),
        );
        values.insert(
            "RestrictAddressFamilies".into(),
            VM_ADDRESS_FAMILIES.join(" "),
        );
        values
    }
    #[test]
    fn external_units_cannot_weaken_lifecycle_or_authority() {
        assert!(check_unit_values(&unit()).is_ok());
        for (key, value) in [
            ("SendSIGKILL", "yes"),
            ("TimeoutStartUSec", "5000000"),
            ("TimeoutStopUSec", "5000000"),
            ("TimeoutAbortUSec", "5000000"),
            ("KillSignal", "9"),
            ("WatchdogSignal", "6"),
            ("NotifyAccess", "main"),
            ("ExitType", "main"),
            ("MemoryMax", "infinity"),
            ("MemoryHigh", "2048"),
            ("TasksMax", "0"),
            ("OOMPolicy", "stop"),
            ("OOMScoreAdjust", "-900"),
            ("CapabilityBoundingSet", "cap_sys_admin cap_sys_ptrace"),
            ("RestrictAddressFamilies", "AF_UNIX AF_ALG"),
            ("LimitCORESoft", "1024"),
            ("CoredumpFilter", "0x33"),
        ] {
            let mut values = unit();
            values.insert(key.into(), value.into());
            assert!(
                check_unit_values(&values).is_err(),
                "accepted {key}={value}"
            );
        }
    }
    fn process_fixture(status: &str) -> (tempfile::TempDir, Process) {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("123")).unwrap();
        fs::write(root.path().join("123/status"), status).unwrap();
        let process = Process::open(123, None, root.path()).unwrap();
        (root, process)
    }
    #[test]
    fn child_authority_requires_every_capability_set_and_groups() {
        let good = "Seccomp:\t2\nSeccomp_filters:\t1\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nGroups:\t\n";
        let (_root, process) = process_fixture(good);
        verify_child_privileges(&process).unwrap();
        for bad in [
            good.replace("Groups:\t\n", ""),
            good.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
            good.replace("Seccomp_filters:\t1", "Seccomp_filters:\t0"),
            good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            good.replace("Groups:\t\n", "Groups:\t0\n"),
        ] {
            let (_root, process) = process_fixture(&bad);
            assert!(verify_child_privileges(&process).is_err());
        }
    }
}

#[cfg(test)]
mod handoff_boundary_tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[test]
    fn only_quarantined_console_descriptors_may_be_relabelled() {
        let target = "system_u:object_r:particleve_vmspawn_devpts_t:s0:c10,c20";
        let labels = RefCell::new(vec![PTY_ALLOC.to_owned(), target.to_owned()].into_iter());
        let calls = RefCell::new(Vec::new());
        label_console(
            [10, 20],
            || {
                calls.borrow_mut().push("get");
                Ok(labels.borrow_mut().next().unwrap())
            },
            || {
                calls.borrow_mut().push("set");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["get", "set", "get"]);
        label_console(
            [10, 20],
            || Ok(target.into()),
            || panic!("existing owner label must not be reset"),
        )
        .unwrap();
        for foreign in [
            "system_u:object_r:particleve_vmspawn_devpts_t:s0:c30,c40",
            "system_u:object_r:particleve_vmspawn_devpts_t:s0",
            "system_u:object_r:devpts_t:s0",
        ] {
            assert!(
                label_console(
                    [10, 20],
                    || Ok(foreign.into()),
                    || panic!("foreign console must not be relabelled")
                )
                .is_err()
            );
        }
        assert!(
            label_console(
                [10, 20],
                || Err(Error::new("cannot inspect")),
                || panic!("failed observation grants no write")
            )
            .is_err()
        );
        let reads = Cell::new(0);
        assert!(
            label_console(
                [10, 20],
                || {
                    reads.set(reads.get() + 1);
                    Ok(PTY_ALLOC.into())
                },
                || Err(Error::new("cannot set label"))
            )
            .is_err()
        );
        assert_eq!(reads.get(), 1);
        let reads = Cell::new(0);
        assert!(
            label_console(
                [10, 20],
                || {
                    reads.set(reads.get() + 1);
                    if reads.get() == 1 {
                        Ok(PTY_ALLOC.into())
                    } else {
                        Err(Error::new("cannot confirm new label"))
                    }
                },
                || Ok(())
            )
            .is_err()
        );
    }
    #[test]
    fn native_argument_and_zero_privilege_handoffs_preserve_activation_descriptors() {
        for (binary, arguments) in [
            (
                "/usr/bin/qemu-kvm",
                vec![
                    "-add-fd".to_owned(),
                    "fd=7,set=1".to_owned(),
                    "-netdev".to_owned(),
                    "tap,fd=8".to_owned(),
                ],
            ),
            (
                "/usr/bin/swtpm",
                vec![
                    "socket".to_owned(),
                    "--tpm2".to_owned(),
                    "--tpmstate".to_owned(),
                    "dir=/var/lib/machines/test/tpm".to_owned(),
                    "--ctrl".to_owned(),
                    "type=unixio,fd=3".to_owned(),
                ],
            ),
        ] {
            let command = child_command(binary, &arguments);
            assert_eq!(command.get_program(), "/usr/bin/setpriv");
            let expected = [
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--clear-groups",
                "--",
            ]
            .into_iter()
            .chain(std::iter::once(binary))
            .chain(arguments.iter().map(String::as_str))
            .map(std::ffi::OsStr::new)
            .collect::<Vec<_>>();
            assert_eq!(command.get_args().collect::<Vec<_>>(), expected);
        }
    }
    #[test]
    fn retained_tpm_files_cannot_be_public_shared_empty_or_linked() {
        let valid = || RetainedTpmMetadata {
            regular: true,
            uid: 0,
            gid: 0,
            mode: 0o640,
            size: 128,
            links: 1,
        };
        valid().validate().unwrap();
        for change in 0..6 {
            let mut info = valid();
            match change {
                0 => info.regular = false,
                1 => info.uid = 1000,
                2 => info.gid = 1000,
                3 => info.mode = 0o644,
                4 => info.size = 0,
                _ => info.links = 2,
            }
            assert!(info.validate().is_err());
        }
    }
    #[test]
    fn permanent_mcs_pairs_are_unique_before_ephemeral_state_can_be_labelled() {
        let machines = tempfile::tempdir().unwrap();
        let root = machines.path().join("test");
        let peer = machines.path().join("peer");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&peer).unwrap();
        for collision in [false, true] {
            let reads = RefCell::new(Vec::new());
            let result = check_storage_categories(&root, machines.path(), [10, 20], |path| {
                reads.borrow_mut().push(path.to_owned());
                Ok(format!(
                    "system_u:object_r:virt_var_lib_t:s0:{}",
                    if path == root || collision {
                        "c10,c20"
                    } else {
                        "c30,c40"
                    }
                ))
            });
            assert_eq!(result.is_err(), collision);
            assert_eq!(reads.borrow()[0], root);
            assert_eq!(reads.borrow().len(), 2);
        }
        fs::remove_dir(&peer).unwrap();
        std::os::unix::fs::symlink(&root, &peer).unwrap();
        assert!(
            check_storage_categories(&root, machines.path(), [10, 20], |_| Ok(
                "system_u:object_r:virt_var_lib_t:s0:c10,c20".into()
            ))
            .unwrap_err()
            .message
            .contains("symlink")
        );
    }
    #[test]
    fn private_directory_never_follows_a_link() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        assert!(private_directory(&link).is_err());
    }
}

#[cfg(test)]
mod guard_order_tests {
    use super::*;
    #[test]
    fn root_authority_and_inhibition_fail_before_platform_or_storage_work() {
        assert!(
            launch_authority(1000, || panic!(
                "nonroot must fail before observing platform"
            ))
            .unwrap_err()
            .message
            .contains("root")
        );
        assert!(
            launch_authority(0, || Ok(true))
                .unwrap_err()
                .message
                .contains("temporarily inhibited")
        );
        launch_authority(0, || Ok(false)).unwrap();
    }
    #[test]
    fn foreign_cgroups_never_supply_a_vm_handoff_name() {
        assert_eq!(
            owning_name_from_group("/machine.slice/systemd-vmspawn@test.service").unwrap(),
            "test"
        );
        for group in [
            "/system.slice/foreign.service",
            "/systemd-vmspawn@.service",
            "/systemd-vmspawn@test.scope",
        ] {
            assert!(owning_name_from_group(group).is_err());
        }
    }
}
