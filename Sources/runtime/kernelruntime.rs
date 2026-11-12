//! Read-only effective kernel interface policy; no process memory is read.
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
        json!({"yama":true,"mmap_rnd_bits_max":entropy[0],"mmap_rnd_compat_bits_max":entropy[1],"strict_devmem":devmem,"legacy_kmem":false,"proc_kcore":values.get("PROC_KCORE").is_some_and(|s|s=="y"),"kexec_core":values.get("KEXEC_CORE").is_some_and(|s|s=="y")}),
    )
}
pub fn baseline(proc: &Path, dev: &Path, kcore: &Path, kexec_core: bool) -> Result<Value> {
    let policy = crate::security::runtime_policy()?;
    let mut observed = BTreeMap::new();
    let mut compiled_out = Vec::new();
    for (name, expected) in &policy.sysctls {
        let path = proc.join("sys").join(name.replace('.', "/"));
        if name == "kernel.kexec_load_disabled" && !kexec_core {
            // KEXEC_CORE owns this sysctl. Its verified absence disables the
            // interface entirely; a missing knob must never excuse enabled kexec.
            require(
                match std::fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                    Err(e) => return Err(e.into()),
                    Ok(_) => false,
                },
                "kexec sysctl exists despite disabled kernel support",
            )?;
            compiled_out.push(name.clone());
            continue;
        }
        require(
            String::from_utf8(read_bounded(&path, 65536)?)?.trim() == expected,
            format!("kernel runtime policy drift: {name}"),
        )?;
        observed.insert(name.clone(), expected.clone());
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
    Ok(
        json!({"sysctls":observed,"compiled_out_sysctls":compiled_out,"root_only_devices":interfaces,"root_only_kcore":kcore}),
    )
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
        assert_eq!(kernel_support(&values).unwrap()["kexec_core"], false);
        values.insert("PROC_KCORE".into(), "y".into());
        assert_eq!(kernel_support(&values).unwrap()["proc_kcore"], true);
        values.insert("KEXEC_CORE".into(), "y".into());
        assert_eq!(kernel_support(&values).unwrap()["kexec_core"], true);
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
        let baseline = baseline(&proc, &dev, &kcore, true).unwrap();
        assert_eq!(baseline["root_only_kcore"], false);
        assert_eq!(
            baseline["root_only_devices"],
            json!({"mem":false,"userfaultfd":false})
        );
        let target = proc.join("sys/vm/memfd_noexec");
        fs::write(&target, "2").unwrap();
        assert!(super::baseline(&proc, &dev, &kcore, true).is_err());
        fs::write(&target, "1").unwrap();
        symlink("/dev/null", dev.join("mem")).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore, true).is_err());
        fs::remove_file(dev.join("mem")).unwrap();
        symlink("/missing", dev.join("kmem")).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore, true).is_err());
        fs::remove_file(dev.join("kmem")).unwrap();
        // A sandbox mask is not evidence of the original interface's mode.
        fs::write(&kcore, "").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&kcore, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore, true).is_err());
        fs::remove_file(&kcore).unwrap();
        symlink("/missing", &kcore).unwrap();
        assert!(super::baseline(&proc, &dev, &kcore, true).is_err());
    }
    #[test]
    fn compiled_out_kexec_requires_the_knob_absent_and_keeps_other_assertions() {
        let root = tempfile::tempdir().unwrap();
        let proc = root.path().join("proc");
        let dev = root.path().join("dev");
        fs::create_dir(&dev).unwrap();
        let policy = crate::security::runtime_policy().unwrap();
        for (name, value) in &policy.sysctls {
            if name == "kernel.kexec_load_disabled" {
                continue;
            }
            let path = proc.join("sys").join(name.replace('.', "/"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, value).unwrap();
        }
        let kcore = proc.join("kcore");
        let absent = baseline(&proc, &dev, &kcore, false).unwrap();
        assert_eq!(
            absent["compiled_out_sysctls"],
            json!(["kernel.kexec_load_disabled"])
        );
        assert!(
            absent["sysctls"]
                .get("kernel.kexec_load_disabled")
                .is_none()
        );
        assert!(baseline(&proc, &dev, &kcore, true).is_err());
        let knob = proc.join("sys/kernel/kexec_load_disabled");
        fs::write(&knob, "1").unwrap();
        assert!(baseline(&proc, &dev, &kcore, false).is_err());
        assert!(baseline(&proc, &dev, &kcore, true).is_ok());
        fs::write(&knob, "0").unwrap();
        assert!(baseline(&proc, &dev, &kcore, true).is_err());
        fs::remove_file(&knob).unwrap();
        symlink("/missing", &knob).unwrap();
        assert!(baseline(&proc, &dev, &kcore, false).is_err());
        fs::remove_file(&knob).unwrap();
        fs::remove_file(proc.join("sys/vm/memfd_noexec")).unwrap();
        assert!(baseline(&proc, &dev, &kcore, false).is_err());
    }
}
