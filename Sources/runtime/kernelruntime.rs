//! Read-only effective stock-kernel interface policy; no process memory is read.
use crate::common::{Error, Result, read_bounded, require};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
// PID 1 binds the original interface here before applying the report sandbox's
// /proc/kcore mask. Only metadata is inspected; CAP_SYS_RAWIO is never granted.
pub const REPORT_KCORE: &str = "/run/particleve-report/kcore";
pub fn kernel_support(values: &BTreeMap<String, String>) -> Result<Value> {
    require(
        values.get("SECURITY_YAMA").map(String::as_str) == Some("y"),
        "kernel Yama policy support is missing",
    )?;
    let mut entropy = Vec::new();
    for (name, expected) in [
        ("ARCH_MMAP_RND_BITS_MAX", 32u64),
        ("ARCH_MMAP_RND_COMPAT_BITS_MAX", 16),
    ] {
        let value = values
            .get(name)
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| Error::new(format!("kernel ASLR entropy support is missing: {name}")))?;
        require(
            value >= expected,
            format!("kernel ASLR entropy support is missing: {name}"),
        )?;
        entropy.push(value);
    }
    let devmem = values.get("DEVMEM").map(String::as_str) == Some("y");
    require(
        !devmem
            || ["STRICT_DEVMEM", "IO_STRICT_DEVMEM"]
                .iter()
                .all(|k| values.get(*k).map(String::as_str) == Some("y")),
        "raw physical memory lacks strict kernel restrictions",
    )?;
    require(
        values.get("DEVKMEM").map(String::as_str) != Some("y"),
        "legacy kernel memory device is enabled",
    )?;
    Ok(
        json!({"yama":true,"mmap_rnd_bits_max":entropy[0],"mmap_rnd_compat_bits_max":entropy[1],"strict_devmem":devmem,"legacy_kmem":false,"proc_kcore":values.get("PROC_KCORE").is_some_and(|s|s=="y")}),
    )
}
pub fn baseline(proc: &Path, dev: &Path, kcore: &Path) -> Result<Value> {
    let policy = crate::security::runtime_policy()?;
    for (name, expected) in &policy.sysctls {
        require(
            String::from_utf8(read_bounded(
                proc.join("sys").join(name.replace('.', "/")),
                65536,
            )?)?
            .trim()
                == expected,
            format!("kernel runtime policy drift: {name}"),
        )?;
    }
    require(
        match std::fs::symlink_metadata(dev.join("kmem")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => return Err(e.into()),
            Ok(_) => false,
        },
        "legacy kmem device exists",
    )?;
    let mut interfaces = BTreeMap::new();
    for name in ["mem", "userfaultfd"] {
        let info = match std::fs::symlink_metadata(dev.join(name)) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                interfaces.insert(name, false);
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        require(
            info.file_type().is_char_device()
                && info.mode() & 0o7777 == 0o600
                && info.uid() == 0
                && info.gid() == 0,
            format!("raw kernel interface is not a root-only character device: {name}"),
        )?;
        interfaces.insert(name, true);
    }
    let kcore = match std::fs::symlink_metadata(kcore) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
        Ok(info) => {
            require(
                info.is_file()
                    && info.mode() & 0o7777 == 0o400
                    && info.uid() == 0
                    && info.gid() == 0,
                "kernel core interface is not root-only read-only",
            )?;
            true
        }
    };
    Ok(json!({"sysctls":policy.sysctls,"root_only_devices":interfaces,"root_only_kcore":kcore}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    #[test]
    fn kernel_support_records_whether_kcore_metadata_must_be_present() {
        let mut values = BTreeMap::from([
            ("SECURITY_YAMA".into(), "y".into()),
            ("ARCH_MMAP_RND_BITS_MAX".into(), "32".into()),
            ("ARCH_MMAP_RND_COMPAT_BITS_MAX".into(), "16".into()),
        ]);
        assert_eq!(kernel_support(&values).unwrap()["proc_kcore"], false);
        values.insert("PROC_KCORE".into(), "y".into());
        assert_eq!(kernel_support(&values).unwrap()["proc_kcore"], true);
    }
    #[test]
    fn effective_sysctls_and_raw_device_shapes_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let proc = root.path().join("proc");
        let dev = root.path().join("dev");
        fs::create_dir(&dev).unwrap();
        let policy = crate::security::runtime_policy().unwrap();
        for (name, value) in &policy.sysctls {
            let path = proc.join("sys").join(name.replace('.', "/"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, format!("{value}\n")).unwrap();
        }
        let kcore = proc.join("kcore");
        let baseline = baseline(&proc, &dev, &kcore).unwrap();
        assert_eq!(baseline["root_only_kcore"], false);
        assert_eq!(
            baseline["root_only_devices"],
            json!({"mem":false,"userfaultfd":false})
        );
        let target = proc.join("sys/vm/memfd_noexec");
        fs::write(&target, "2").unwrap();
        assert!(super::baseline(&proc, &dev, &kcore).is_err());
        fs::write(&target, "1").unwrap();
        symlink("/dev/null", dev.join("mem")).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore).is_err());
        fs::remove_file(dev.join("mem")).unwrap();
        symlink("/missing", dev.join("kmem")).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore).is_err());
        fs::remove_file(dev.join("kmem")).unwrap();
        // A sandbox mask is not evidence of the original interface's mode.
        fs::write(&kcore, "").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&kcore, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore).is_err());
        fs::remove_file(&kcore).unwrap();
        symlink("/missing", &kcore).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore).is_err());
    }
}
