//! Test-only adapters exercise compiled runtime boundaries without a Python implementation.
use particleve::common::{self, Error, Result, field, list, text};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
fn strings(value: &Value) -> Result<Vec<String>> {
    list(value)?
        .iter()
        .map(|v| text(v).map(str::to_owned))
        .collect()
}
pub fn evaluate(operation: &str, request: &Value) -> Option<Result<Value>> {
    if !supports(operation) {
        return None;
    }
    Some((|| -> Result<Value> {
        match operation {
            "landlock-handoff-probe" => landlock_probe(request),
            "qemu-arguments" => Ok(json!(particleve::confinement::qemu_arguments(&strings(
                field(request, "arguments")?
            )?)?)),
            "vm-context" => Ok(json!(particleve::confinement::context(
                text(field(request, "context")?)?,
                text(field(request, "type")?)?
            )?)),
            "vm-unit-contract" => {
                let mut properties = BTreeMap::new();
                for (k, v) in common::object(field(request, "properties")?)? {
                    properties.insert(k.clone(), text(v)?.to_owned());
                }
                particleve::confinement::check_unit_values(&properties)?;
                Ok(Value::Null)
            }
            "vm-tpm-arguments" => {
                particleve::confinement::check_tpm_arguments(
                    text(field(request, "name")?)?,
                    &strings(field(request, "arguments")?)?,
                )?;
                Ok(Value::Null)
            }
            "vm-verify-processes" => {
                let processes: Vec<particleve::processes::Identity> =
                    serde_json::from_value(field(request, "processes")?.clone())?;
                particleve::confinement::verify_processes(
                    &processes,
                    Path::new(text(field(request, "proc")?)?),
                )?;
                Ok(Value::Null)
            }
            "memory-core-config" => {
                particleve::memoryprivacy::parse_coredump_config(text(field(request, "data")?)?)
            }
            "memory-baseline" => particleve::memoryprivacy::baseline(
                Path::new(text(field(request, "proc")?)?),
                Path::new(text(field(request, "sysfs")?)?),
            ),
            _ => Err(Error::new("unknown VM test operation")),
        }
    })())
}
fn supports(operation: &str) -> bool {
    matches!(
        operation,
        "landlock-handoff-probe"
            | "qemu-arguments"
            | "vm-context"
            | "vm-unit-contract"
            | "vm-tpm-arguments"
            | "vm-verify-processes"
            | "memory-core-config"
            | "memory-baseline"
    )
}

fn landlock_probe(request: &Value) -> Result<Value> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::MetadataExt;
    let directory = Path::new(text(field(request, "directory")?)?);
    let canonical = directory.canonicalize()?;
    let metadata = fs::symlink_metadata(directory)?;
    // This operation is test-only and refuses every path except the caller's
    // explicit private disposable directory. No installed-state path is touched.
    // SAFETY: geteuid reads only the calling task's scalar identity.
    let uid = unsafe { libc::geteuid() };
    common::require(
        metadata.is_dir()
            && !metadata.is_symlink()
            && metadata.mode() & 0o7777 == 0o700
            && metadata.uid() == uid
            && canonical == directory
            && canonical.starts_with(std::env::temp_dir())
            && canonical
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("particleve-landlock-probe-")),
        "use an owned private disposable Landlock directory",
    )?;
    let names = fs::read_dir(directory)?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    common::require(
        names == [std::ffi::OsString::from("inherited")],
        "Landlock fixture must contain only its inherited public input",
    )?;
    let inherited = i32::try_from(common::uint(field(request, "inherited_fd")?)?)
        .map_err(|_| Error::new("invalid inherited probe descriptor"))?;
    common::require(
        inherited > 2,
        "probe descriptor must be outside the stdin/diagnostic protocol",
    )?;
    // SAFETY: F_GETFD only observes the explicitly inherited descriptor. Rust
    // never constructs an owner for it because close_range must close it.
    common::require(
        unsafe { libc::fcntl(inherited, libc::F_GETFD) } >= 0,
        "probe descriptor was not inherited",
    )?;
    fs::write(directory.join("readable"), b"public fixture")?;
    fs::write(directory.join("existing-write"), b"unchanged")?;
    fs::write(directory.join("rename-from"), b"retained")?;
    fs::write(directory.join("unlink-target"), b"retained")?;
    fs::write(directory.join("preflight"), b"positive control")?;
    fs::rename(
        directory.join("preflight"),
        directory.join("preflight-renamed"),
    )?;
    fs::remove_file(directory.join("preflight-renamed"))?;
    // Close the positive-control File before the irreversible descriptor handoff.
    drop(
        OpenOptions::new()
            .write(true)
            .open(directory.join("existing-write"))?,
    );
    particleve::platform::no_new_privileges()?;
    let abi = particleve::landlock::confine_filesystem()?;
    // SAFETY: the inherited descriptor intentionally has no Rust owner. Query
    // after confinement proves that the actual close_range removed it.
    let descriptor_closed = unsafe { libc::fcntl(inherited, libc::F_GETFD) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    common::require(
        descriptor_closed,
        "inherited descriptor survived the handoff",
    )?;
    let read_permitted = fs::read(directory.join("readable"))? == b"public fixture";
    common::require(read_permitted, "read-only input became unavailable")?;
    fn denied<T>(result: std::io::Result<T>) -> Result<i32> {
        match result {
            Ok(_) => Err(Error::new(
                "Landlock allowed a forbidden filesystem operation",
            )),
            Err(error) => {
                let errno = error
                    .raw_os_error()
                    .ok_or_else(|| Error::new("filesystem denial has no errno"))?;
                common::require(
                    errno == libc::EACCES,
                    "filesystem operation failed without a Landlock access denial",
                )?;
                Ok(errno)
            }
        }
    }
    let write_open = denied(
        OpenOptions::new()
            .write(true)
            .open(directory.join("existing-write")),
    )?;
    let create = denied(fs::write(directory.join("new-file"), b"forbidden"))?;
    let rename = denied(fs::rename(
        directory.join("rename-from"),
        directory.join("renamed"),
    ))?;
    let unlink = denied(fs::remove_file(directory.join("unlink-target")))?;
    let mkdir = denied(fs::create_dir(directory.join("new-directory")))?;
    common::require(
        fs::read(directory.join("existing-write"))? == b"unchanged"
            && fs::read(directory.join("rename-from"))? == b"retained"
            && fs::read(directory.join("unlink-target"))? == b"retained",
        "denied operations changed retained fixture contents",
    )?;
    Ok(
        json!({"landlock_abi":abi,"descriptor_closed":descriptor_closed,"read_permitted":read_permitted,"denied":{"write_open":write_open,"create":create,"rename":rename,"unlink":unlink,"mkdir":mkdir},"retained_contents":true}),
    )
}
