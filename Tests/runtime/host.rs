//! Test-only host boundaries with explicit fixtures; never installed.
use particleve::common::{Result, boolean, field, text};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub fn evaluate(request: &Value) -> Option<Result<Value>> {
    let operation = request.get("operation")?.as_str()?;
    if !matches!(
        operation,
        "config-ssh-key"
            | "consoles-baseline"
            | "network-write"
            | "kernel-runtime-baseline"
            | "security-kernel-baseline"
            | "kernel-boot-policy"
            | "security-selinux-baseline"
            | "security-usr-backing-disks"
            | "security-firmware-evidence"
            | "compatibility-approved"
    ) {
        return None;
    }
    Some((|| match operation {
        "config-ssh-key" => Ok(json!(particleve::config::ssh_key(field(request, "key")?))),
        "consoles-baseline" => particleve::consoles::baseline(
            field(request, "config")?,
            Path::new(text(field(request, "proc")?)?),
            Path::new(text(field(request, "sys")?)?),
        ),
        "network-write" => {
            particleve::network::write(
                field(request, "config")?,
                Path::new(text(field(request, "root")?)?),
            )?;
            Ok(Value::Null)
        }
        "kernel-runtime-baseline" => particleve::kernelruntime::baseline(
            Path::new(text(field(request, "proc")?)?),
            Path::new(text(field(request, "dev")?)?),
            &Path::new(text(field(request, "proc")?)?).join("kcore"),
            boolean(field(request, "kexec_core")?)?,
        ),
        "security-selinux-baseline" => particleve::security::selinux_baseline(),
        "security-kernel-baseline" => {
            particleve::security::kernel_baseline(Path::new(text(field(request, "root")?)?))
        }
        "kernel-boot-policy" => {
            particleve::security::kernel_boot_policy(
                text(field(request, "cmdline")?)?,
                text(field(request, "enforcement")?)?,
            )?;
            Ok(Value::Null)
        }
        "security-usr-backing-disks" => Ok(json!(particleve::security::usr_backing_disks(
            text(field(request, "mapper")?)?,
            Path::new(text(field(request, "sysfs")?)?),
        )?)),
        "security-firmware-evidence" => particleve::security::firmware_evidence(),
        "compatibility-approved" => {
            let directory = PathBuf::from(text(field(request, "directory")?)?);
            let backend = particleve::linux::Linux {
                config: Value::Null,
                manifest: Value::Null,
                cache: directory.join("cache"),
                keyring: directory.join("keyring"),
                certificate: directory.join("certificate"),
                directory,
            };
            backend.compatibility_approved(field(request, "first")?, field(request, "second")?)?;
            Ok(Value::Null)
        }
        _ => unreachable!(),
    })())
}
