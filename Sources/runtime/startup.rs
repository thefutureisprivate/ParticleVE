//! Descriptor-relative, no-follow inventory of writable startup authority.
use crate::common::{self, Error, Result, digest, field, require};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};
const MAX_FILES: usize = 4096;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILE: usize = 4 * 1024 * 1024;
const FROZEN: &[&str] = &[
    "etc/selinux",
    "etc/audit",
    "etc/authselect",
    "etc/security",
    "etc/pam.d",
    "etc/nsswitch.conf",
    "etc/environment",
    "etc/profile",
    "etc/profile.d",
    "etc/bashrc",
    "etc/bash.bashrc",
    "etc/ld.so.conf",
    "etc/ld.so.conf.d",
    "etc/ld.so.preload",
    "etc/modprobe.d",
    "etc/udev",
    "etc/polkit-1/rules.d",
    "etc/dbus-1",
    "etc/rc.d",
    "etc/rc.local",
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "etc/cron.weekly",
    "etc/cron.monthly",
    "etc/crontab",
    "etc/systemd/system-generators",
    "etc/systemd/user-generators",
    "etc/systemd/system-environment-generators",
    "etc/systemd/system.control",
    "etc/systemd/system.attached",
];
fn metadata(info: &libc::stat, path: &str) -> Result<Value> {
    require(
        info.st_uid == 0,
        format!("startup input is not owned by root: /{path}"),
    )?;
    let kind = info.st_mode & libc::S_IFMT;
    require(
        kind == libc::S_IFLNK || info.st_mode & 0o022 == 0,
        format!("startup input is writable by another account: /{path}"),
    )?;
    require(
        matches!(kind, libc::S_IFDIR | libc::S_IFLNK | libc::S_IFREG),
        format!("special file in startup configuration: /{path}"),
    )?;
    require(
        kind != libc::S_IFREG || info.st_nlink == 1,
        format!("hard-linked startup input: /{path}"),
    )?;
    Ok(json!({"path":path,"uid":info.st_uid,"gid":info.st_gid,"mode":info.st_mode&0o7777}))
}
fn cstring(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::new("NUL in startup path"))
}
fn stat_at(fd: i32, name: &str) -> Result<libc::stat> {
    let name = cstring(name)?;
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: name is NUL terminated, value points to writable storage for stat, and fd is held by the traversal.
    let status = unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful fstatat initialized the entire stat record.
    Ok(unsafe { value.assume_init() })
}
fn fstat(fd: i32) -> Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: writable stat storage and a live borrowed descriptor are supplied.
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful fstat initialized the stat record.
    Ok(unsafe { value.assume_init() })
}
fn open_at(fd: i32, name: &str, flags: i32) -> Result<File> {
    let name = cstring(name)?;
    // SAFETY: borrowed parent stays live, the C string is valid, and no create flag requires a mode argument.
    let opened = unsafe { libc::openat(fd, name.as_ptr(), flags) };
    if opened < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned one owned descriptor that is transferred to File exactly once.
    Ok(unsafe { File::from_raw_fd(opened) })
}
fn link_at(fd: i32, name: &str) -> Result<String> {
    let name = cstring(name)?;
    let mut bytes = vec![0u8; 65537];
    // SAFETY: readlinkat writes within the owned bounded buffer; parent and name stay valid.
    let count =
        unsafe { libc::readlinkat(fd, name.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
    if count < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    require(
        (count as usize) < bytes.len(),
        "startup symlink exceeds its size limit",
    )?;
    bytes.truncate(count as usize);
    String::from_utf8(bytes).map_err(Into::into)
}
fn acl(fd: i32, path: &str, metadata_only: bool) -> Result<()> {
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        let name = cstring(name)?;
        // SAFETY: null buffer with size zero queries only xattr presence. For O_PATH descriptors the proc path holds the same open inode.
        let status = if metadata_only {
            let proc = cstring(&format!("/proc/self/fd/{fd}"))?;
            unsafe { libc::getxattr(proc.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) }
        } else {
            unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) }
        };
        if status < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                continue;
            }
            return Err(err.into());
        }
        return Err(Error::new(format!(
            "unreviewed ACL on startup input: /{path}"
        )));
    }
    Ok(())
}
fn normalize_link(path: &str, target: &str) -> String {
    let joined = if target.starts_with('/') {
        target.to_owned()
    } else {
        format!(
            "/{}/{}",
            path.rsplit_once('/').map_or("", |(p, _)| p),
            target
        )
    };
    let mut parts = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}
fn metadata_only(path: &str) -> bool {
    matches!(
        path,
        "etc/passwd"
            | "etc/group"
            | "etc/shadow"
            | "etc/gshadow"
            | "etc/particleve/report-token"
            | "etc/.pwd.lock"
            | "etc/.updated"
    ) || regex::Regex::new(r"^etc/ssh/ssh_host_(?:ecdsa|ed25519|rsa)_key(?:\.pub)?$")
        .expect("constant expression")
        .is_match(path)
}
fn local_unit(path: &str) -> bool {
    regex::Regex::new(r"^etc/systemd/system/(?:systemd-vmspawn@[A-Za-z0-9_][A-Za-z0-9_.-]*\.service\.d/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.conf|getty\.target\.d/50-particleve-console\.conf|serial-getty@ttyS[0-9]+\.service\.d/50-particleve\.conf)$").expect("constant expression").is_match(path)
}
struct Inventory {
    rows: Vec<Value>,
    total: usize,
}
impl Inventory {
    fn visit(&mut self, parent: i32, name: &str, path: &str) -> Result<()> {
        let info = stat_at(parent, name)?;
        let mut row = metadata(&info, path)?;
        require(
            self.rows.len() < MAX_FILES,
            "startup inventory exceeds its entry limit",
        )?;
        let kind = info.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            let target = link_at(parent, name)?;
            let normalized = normalize_link(path, &target);
            let special = match path {
                "etc/mtab" => Some("/proc/self/mounts"),
                "etc/resolv.conf" => Some("/run/systemd/resolve/stub-resolv.conf"),
                _ => None,
            };
            require(
                normalized.starts_with("/usr/")
                    || normalized == "/dev/null"
                    || special == Some(normalized.as_str()),
                format!("startup link escapes verified usr: /{path}"),
            )?;
            row["kind"] = json!("symlink");
            row["target"] = json!(target);
            self.rows.push(row);
            return Ok(());
        }
        let meta = metadata_only(path);
        let flags = if meta && kind == libc::S_IFREG {
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if kind == libc::S_IFDIR {
                    libc::O_DIRECTORY
                } else {
                    0
                }
        };
        let fd = open_at(parent, name, flags)?;
        let opened = fstat(fd.as_raw_fd())?;
        require(
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_uid,
                opened.st_gid,
            ) == (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_gid,
            ),
            "startup input changed during inspection",
        )?;
        acl(fd.as_raw_fd(), path, meta)?;
        if kind == libc::S_IFDIR {
            row["kind"] = json!("directory");
            self.rows.push(row);
            let mut names = Vec::new();
            for entry in fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))? {
                require(
                    names.len() < MAX_FILES,
                    "startup directory exceeds its entry limit",
                )?;
                names.push(
                    entry?
                        .file_name()
                        .into_string()
                        .map_err(|_| Error::new("non-Unicode startup filename"))?,
                );
            }
            names.sort();
            for child in names {
                self.visit(fd.as_raw_fd(), &child, &format!("{path}/{child}"))?;
            }
            return Ok(());
        }
        require(
            info.st_mode & 0o111 == 0,
            format!("executable in writable startup configuration: /{path}"),
        )?;
        if matches!(path, "etc/.pwd.lock" | "etc/.updated") {
            return Ok(());
        }
        if meta {
            row["kind"] = json!("account-or-credential-data");
            self.rows.push(row);
            return Ok(());
        }
        require(
            !FROZEN
                .iter()
                .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/"))),
            format!("startup hook must originate from verified usr: /{path}"),
        )?;
        require(
            !path.starts_with("etc/systemd/system/") || local_unit(path),
            format!(
                "only native VM or generated console drop-ins may be regular local units: /{path}"
            ),
        )?;
        require(
            info.st_size >= 0 && (info.st_size as u64) <= MAX_FILE as u64,
            format!("startup file exceeds its size limit: /{path}"),
        )?;
        let mut data = Vec::new();
        fd.take((MAX_FILE + 1) as u64).read_to_end(&mut data)?;
        require(
            data.len() <= MAX_FILE,
            format!("growing startup file: /{path}"),
        )?;
        self.total = self
            .total
            .checked_add(data.len())
            .ok_or_else(|| Error::new("startup byte limit overflow"))?;
        require(
            self.total <= MAX_BYTES,
            "startup inventory exceeds its byte limit",
        )?;
        require(
            data.len() as i64 == info.st_size,
            "startup input changed during inspection",
        )?;
        if path == "etc/ld.so.cache" {
            row["kind"] = json!("verified-usr-library-cache");
        } else {
            row["kind"] = json!("file");
            row["sha256"] = json!(common::hex(&Sha256::digest(data)));
        }
        self.rows.push(row);
        Ok(())
    }
}
fn rootfd(root: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?)
}
pub fn inventory(root: &Path) -> Result<Value> {
    let fd = rootfd(root)?;
    metadata(&fstat(fd.as_raw_fd())?, "")?;
    acl(fd.as_raw_fd(), "", false)?;
    for name in ["bin", "sbin", "lib", "lib64"] {
        let info = stat_at(fd.as_raw_fd(), name)?;
        metadata(&info, name)?;
        let target = link_at(fd.as_raw_fd(), name)?;
        require(
            info.st_mode & libc::S_IFMT == libc::S_IFLNK
                && (target == format!("usr/{name}") || target == format!("/usr/{name}")),
            format!("traditional code path is not an alias into verified usr: /{name}"),
        )?;
    }
    let mut inventory = Inventory {
        rows: Vec::new(),
        total: 0,
    };
    inventory.visit(fd.as_raw_fd(), "etc", "etc")?;
    library_cache(root)?;
    let mut result = json!({"schema":1,"inputs":inventory.rows});
    result["sha256"] = json!(digest(&result)?);
    Ok(result)
}
fn library_cache(root: &Path) -> Result<()> {
    let cache = root.join("etc/ld.so.cache");
    match fs::symlink_metadata(&cache) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let result = common::run(&[
        "/usr/bin/env",
        "LC_ALL=C",
        "/usr/sbin/ldconfig",
        "-p",
        "-C",
        cache
            .to_str()
            .ok_or_else(|| Error::new("non-Unicode root path"))?,
    ])?;
    require(
        result.stderr.trim().is_empty(),
        "library cache inspection produced diagnostics",
    )?;
    let mut lines = result.stdout.lines();
    let first = lines.next().unwrap_or("");
    require(
        regex::Regex::new(r"^[0-9]+ libs found in cache .+$")
            .expect("constant expression")
            .is_match(first),
        "invalid library cache",
    )?;
    for line in lines {
        if line.starts_with("Cache generated by: ldconfig ") {
            continue;
        }
        let (_, path) = line
            .rsplit_once(" => ")
            .ok_or_else(|| Error::new("unrecognized library cache entry"))?;
        require(
            normalize_link("", path) == path
                && ["/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/"]
                    .iter()
                    .any(|p| path.starts_with(p)),
            "library cache loads from writable state",
        )?;
    }
    Ok(())
}
fn commissioning(root: &Path) -> Result<Option<Value>> {
    let mut parent = rootfd(root)?;
    let mut path = String::new();
    for name in ["var", "lib", "particleve", "commissioned.json"] {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(name);
        let directory = name != "commissioned.json";
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if directory { libc::O_DIRECTORY } else { 0 };
        let fd = match open_at(parent.as_raw_fd(), name, flags) {
            Ok(fd) => fd,
            Err(e) => {
                if e.is_not_found() {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let info = fstat(fd.as_raw_fd())?;
        metadata(&info, &path)?;
        acl(fd.as_raw_fd(), &path, false)?;
        if !directory {
            require(
                info.st_mode & libc::S_IFMT == libc::S_IFREG
                    && info.st_size >= 0
                    && info.st_size <= 65536,
                "commissioning record is not a bounded regular file",
            )?;
            let mut bytes = Vec::new();
            fd.take(65537).read_to_end(&mut bytes)?;
            require(
                bytes.len() <= 65536,
                "commissioning record exceeds its size limit",
            )?;
            return Ok(Some(common::parse_json(&bytes)?));
        }
        parent = fd;
    }
    Ok(None)
}
pub fn check(root: &Path) -> Result<Value> {
    let observed = inventory(root)?;
    if let Some(approved) = commissioning(root)? {
        require(approved.is_object(), "invalid commissioning record")?;
        require(
            approved.get("startup_policy_sha256") == Some(field(&observed, "sha256")?),
            "persistent startup configuration changed or lacks approval; recovery/recommissioning required",
        )?;
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaping_links_cannot_be_mistaken_for_verified_usr() {
        assert_eq!(
            normalize_link("etc/escape", "/usr/../var/code"),
            "/var/code"
        );
        assert_eq!(normalize_link("etc/escape", "../../run/code"), "/run/code");
        assert_eq!(
            normalize_link("etc/pam.d/sshd", "../../usr/share/factory/etc/pam.d/sshd"),
            "/usr/share/factory/etc/pam.d/sshd"
        );
    }
    #[test]
    fn local_unit_policy_is_exact() {
        for p in [
            "etc/systemd/system/systemd-vmspawn@guest.service.d/80-approved.conf",
            "etc/systemd/system/getty.target.d/50-particleve-console.conf",
            "etc/systemd/system/serial-getty@ttyS1.service.d/50-particleve.conf",
        ] {
            assert!(local_unit(p));
        }
        for p in [
            "etc/systemd/system/injected.service",
            "etc/systemd/system/serial-getty@ttyS1.service.d/90-extra.conf",
            "etc/systemd/system/systemd-vmspawn@../bad.service.d/80.conf",
        ] {
            assert!(!local_unit(p));
        }
    }
    #[test]
    fn ordinary_credentials_are_metadata_only() {
        for p in [
            "etc/shadow",
            "etc/particleve/report-token",
            "etc/ssh/ssh_host_ed25519_key",
            "etc/ssh/ssh_host_rsa_key.pub",
        ] {
            assert!(metadata_only(p));
        }
        assert!(!metadata_only("etc/ssh/sshd_config"));
        assert!(!metadata_only("etc/ssh/ssh_host_ed25519_key.backup"));
    }
    #[test]
    fn metadata_rejects_other_owners_writers_hardlinks_and_devices() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut info = fstat(file.as_raw_fd()).unwrap();
        info.st_uid = 0;
        info.st_mode = libc::S_IFREG | 0o600;
        info.st_nlink = 1;
        assert!(metadata(&info, "etc/test").is_ok());
        info.st_uid = 1000;
        assert!(metadata(&info, "etc/test").is_err());
        info.st_uid = 0;
        info.st_mode = libc::S_IFREG | 0o622;
        assert!(metadata(&info, "etc/test").is_err());
        info.st_mode = libc::S_IFREG | 0o600;
        info.st_nlink = 2;
        assert!(metadata(&info, "etc/test").is_err());
        info.st_nlink = 1;
        info.st_mode = libc::S_IFIFO | 0o600;
        assert!(metadata(&info, "etc/test").is_err());
    }
    #[test]
    fn descriptor_open_never_follows_replaced_parent_or_input() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("safe")).unwrap();
        std::os::unix::fs::symlink("safe", root.path().join("alias")).unwrap();
        let fd = rootfd(root.path()).unwrap();
        assert!(
            open_at(
                fd.as_raw_fd(),
                "alias",
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC
            )
            .is_err()
        );
        assert!(rootfd(&root.path().join("alias")).is_err());
    }
}

#[cfg(test)]
mod native_cache_tests {
    use super::*;
    #[test]
    fn real_ldconfig_cache_cannot_select_a_writable_library_directory() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("etc")).unwrap();
        let foreign = root.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        let library = Path::new("/usr/lib64/libc.so.6");
        fs::copy(library, foreign.join("libc.so.6")).unwrap();
        let config = root.path().join("ld.so.conf");
        fs::write(&config, format!("{}\n", foreign.display())).unwrap();
        let cache = root.path().join("etc/ld.so.cache");
        // -X prevents writes to library symlinks; -C and -f name only this disposable fixture.
        common::run(&[
            "/usr/sbin/ldconfig",
            "-X",
            "-C",
            cache.to_str().unwrap(),
            "-f",
            config.to_str().unwrap(),
        ])
        .unwrap();
        let error = library_cache(root.path()).unwrap_err();
        assert!(error.message.contains("writable state"), "{error}");
    }
}
