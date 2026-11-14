//! The active image owns the allocator, including secure exec and early boot.
use crate::common::{Error, Result, read_bounded, require};
use crate::processes::Process;
use serde_json::{Value, json};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, symlink},
};
use std::path::Path;

pub const LIBRARY: &str = "/usr/lib64/libhardened_malloc.so";
pub const CONFIGURATION: &str = "/usr/lib/particleve/ld.so.preload";
const PRELOAD: &str = "/usr/lib64/libhardened_malloc.so\n";
// Fedora's file-context policy labels /etc/ld.so.preload as ordinary etc_t.
// The initrd creates this one link before installed PID 1 loads that policy.
const LINK_CONTEXT: &str = "system_u:object_r:etc_t:s0";

fn approved_link(target: &Path) -> bool {
    target == Path::new(CONFIGURATION)
        || target == Path::new("/usr/share/factory/etc/ld.so.preload")
        || target == Path::new("../usr/lib/particleve/ld.so.preload")
        || target == Path::new("../usr/share/factory/etc/ld.so.preload")
}

/// Materialize only the image-owned default before executing installed PID 1.
/// A retained image resolves this link through its own verified /usr.
pub fn prepare_root(root: &Path) -> Result<()> {
    prepare_root_with(root, label_link)
}

/// Keep ownership validation ahead of the independently testable labeling step.
pub fn prepare_root_with(root: &Path, label: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    let directory = root.join("etc");
    let metadata = fs::symlink_metadata(&directory)?;
    require(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "allocator configuration requires an owned root etc directory",
    )?;
    let path = directory.join("ld.so.preload");
    match fs::symlink_metadata(&path) {
        Ok(_) => owned_link(&path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Never replace owner data. The initrd has already admitted storage
            // and checked startup authority; root owns this directory exclusively.
            symlink(CONFIGURATION, &path)?;
        }
        Err(error) => return Err(error.into()),
    }
    // Label only the checked link, never its verified target or retained data.
    // A pre-policy creation otherwise leaves unlabeled_t after switch-root,
    // making the loader silently skip preload for confined daemon domains.
    label(&path)?;
    File::open(&directory)?.sync_all()?;
    Ok(())
}

fn owned_link(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_symlink() && metadata.uid() == 0 && approved_link(&fs::read_link(path)?),
        "allocator configuration must be the image-owned preload link",
    )
}

fn label_link(path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::new("invalid allocator preload path"))?;
    let context = CString::new(LINK_CONTEXT).expect("constant SELinux context");
    // SAFETY: both C strings live throughout the call, and the context size
    // includes its terminating NUL. lsetxattr never follows this root-owned
    // link; the validated parent excludes other-account writes during initrd.
    if unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            context.as_ptr().cast(),
            context.as_bytes_with_nul().len(),
            0,
        )
    } != 0
    {
        return Err(Error::new(format!(
            "cannot label allocator preload link: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn checked_link_context(context: &str) -> Result<()> {
    require(
        context.strip_suffix('\0').unwrap_or(context) == LINK_CONTEXT,
        "allocator preload link has an unexpected SELinux label",
    )
}

/// Boot health must establish loader access for confined services too.
pub fn host_policy() -> Result<Value> {
    let path = Path::new("/etc/ld.so.preload");
    owned_link(path)?;
    checked_link_context(&crate::confinement::label(path)?)?;
    current()
}

pub fn mapped(maps: &str) -> Result<()> {
    let mut executable = false;
    let mut count = 0;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(5).copied() != Some(LIBRARY) {
            continue;
        }
        require(
            fields.len() == 6 && fields[1].len() == 4,
            "allocator mapping is deleted or malformed",
        )?;
        let permissions = fields[1].as_bytes();
        require(
            !(permissions[1] == b'w' && permissions[2] == b'x'),
            "allocator mapping is writable and executable",
        )?;
        executable |= permissions[2] == b'x';
        count += 1;
    }
    require(
        count > 0 && executable,
        "global hardened_malloc is not loaded",
    )
}

pub fn process_policy(process: &Process) -> Result<()> {
    mapped(&process.text("maps", 8 * 1024 * 1024)?)
}

pub fn current() -> Result<Value> {
    for name in ["LD_PRELOAD", "LD_AUDIT"] {
        require(
            std::env::var_os(name).is_none(),
            format!("global allocator forbids the {name} loader override"),
        )?;
    }
    require(
        read_bounded(CONFIGURATION, 4096)? == PRELOAD.as_bytes(),
        "global allocator configuration differs from the image policy",
    )?;
    let config = fs::symlink_metadata(CONFIGURATION)?;
    let library = fs::symlink_metadata(LIBRARY)?;
    require(
        config.is_file() && config.uid() == 0 && config.mode() & 0o7777 == 0o644,
        "allocator preload configuration must be root-owned and publicly readable",
    )?;
    require(
        library.is_file() && library.uid() == 0 && library.mode() & 0o7777 == 0o755,
        "allocator library ownership or mode changed",
    )?;
    process_policy(&Process::open(
        std::process::id(),
        None,
        Path::new("/proc"),
    )?)?;
    Ok(
        json!({"implementation":"hardened_malloc","variant":"default","library":LIBRARY,"global_preload":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_live_executable_allocator_without_writable_code() {
        let maps = format!(
            "1000-2000 r--p 00000000 00:01 5 {LIBRARY}\n2000-3000 r-xp 00001000 00:01 5 {LIBRARY}\n"
        );
        assert!(mapped(&maps).is_ok());
        for invalid in [
            String::new(),
            maps.replace("r-xp", "rw-p"),
            maps.replace("r-xp", "rwxp"),
            maps.replace(LIBRARY, &format!("{LIBRARY} (deleted)")),
            maps.replace(LIBRARY, "/var/lib/libhardened_malloc.so"),
        ] {
            assert!(mapped(&invalid).is_err());
        }
    }
    #[test]
    fn root_preload_is_bound_to_the_active_image() {
        assert!(approved_link(Path::new(CONFIGURATION)));
        assert!(approved_link(Path::new(
            "/usr/share/factory/etc/ld.so.preload"
        )));
        assert!(!approved_link(Path::new("/var/lib/allocator.conf")));
        assert!(!approved_link(Path::new("/usr/lib/other-preload.conf")));
    }
    #[test]
    fn confined_loader_access_requires_the_standard_preload_link_label() {
        assert!(checked_link_context(LINK_CONTEXT).is_ok());
        assert!(checked_link_context(&format!("{LINK_CONTEXT}\0")).is_ok());
        for context in [
            "system_u:object_r:unlabeled_t:s0",
            "system_u:object_r:lib_t:s0",
            "system_u:object_r:etc_t:s0:c1",
            "system_u:object_r:etc_t:s0\0\0",
        ] {
            assert!(checked_link_context(context).is_err());
        }
    }
}
