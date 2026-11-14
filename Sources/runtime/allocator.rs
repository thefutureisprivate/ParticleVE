//! The active image owns the allocator, including secure exec and early boot.
use crate::common::{Result, read_bounded, require};
use crate::processes::Process;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;

pub const LIBRARY: &str = "/usr/lib64/libhardened_malloc.so";
pub const CONFIGURATION: &str = "/usr/lib/particleve/ld.so.preload";
const PRELOAD: &str = "/usr/lib64/libhardened_malloc.so\n";

fn approved_link(target: &Path) -> bool {
    target == Path::new(CONFIGURATION)
        || target == Path::new("/usr/share/factory/etc/ld.so.preload")
        || target == Path::new("../usr/lib/particleve/ld.so.preload")
        || target == Path::new("../usr/share/factory/etc/ld.so.preload")
}

/// Materialize only the image-owned default before executing installed PID 1.
/// A retained image resolves this link through its own verified /usr.
pub fn prepare_root(root: &Path) -> Result<()> {
    let directory = root.join("etc");
    let metadata = fs::symlink_metadata(&directory)?;
    require(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "allocator configuration requires an owned root etc directory",
    )?;
    let path = directory.join("ld.so.preload");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => require(
            metadata.is_symlink() && metadata.uid() == 0 && approved_link(&fs::read_link(path)?),
            "allocator configuration must be the image-owned preload link",
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Never replace owner data. The initrd has already admitted storage
            // and checked startup authority; root owns this directory exclusively.
            symlink(CONFIGURATION, &path)?;
            File::open(&directory)?.sync_all()?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
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
}
