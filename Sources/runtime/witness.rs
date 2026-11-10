//! The only runtime writer of the existing firmware authority variable.
use crate::common::{self, Result, canonical, require};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    path::Path,
    time::Duration,
};
pub fn command(variable: &Path) -> Vec<String> {
    [
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--ro-bind",
        "/proc/sys",
        "/proc/sys",
        "--bind",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        variable.to_string_lossy().into_owned(),
        variable.to_string_lossy().into_owned(),
    ])
    .chain(
        [
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CAP_LINUX_IMMUTABLE",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/usr/sbin",
            "/usr/libexec/particleve-witness-write",
        ]
        .into_iter()
        .map(str::to_owned),
    )
    .collect()
}
pub fn save(record: &Value) -> Result<()> {
    let variable = Path::new(crate::admission::VARIABLE);
    require(
        variable.is_file(),
        "missing firmware witness; owner recovery required",
    )?;
    common::command(
        &command(variable),
        Some(&canonical(&crate::admission::validate(record)?)?),
        Some(Duration::from_secs(120)),
        8 * 1024 * 1024,
        true,
    )?;
    require(
        crate::admission::load()? == *record,
        "isolated firmware witness write did not persist",
    )
}
pub fn check_sandbox(variable: &Path) -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    // SAFETY: geteuid has no pointer arguments or ownership requirements.
    check_process_authority(&status, unsafe { libc::geteuid() })?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    check_variable_mount(&mountinfo, variable)
}
fn check_process_authority(status: &str, euid: u32) -> Result<()> {
    let fields = status
        .lines()
        .filter_map(|l| l.split_once(':'))
        .collect::<std::collections::BTreeMap<_, _>>();
    require(
        euid == 0 && fields.get("NoNewPrivs").is_some_and(|s| s.trim() == "1"),
        "writer requires its isolated launcher",
    )?;
    for field in ["CapEff", "CapPrm", "CapInh", "CapAmb"] {
        require(
            fields
                .get(field)
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                == Some(1 << 9),
            "writer must retain only CAP_LINUX_IMMUTABLE",
        )?;
    }
    Ok(())
}
fn check_variable_mount(mountinfo: &str, variable: &Path) -> Result<()> {
    let mut writable = Vec::new();
    for line in mountinfo.lines() {
        let (before, after) = line
            .split_once(" - ")
            .ok_or_else(|| common::Error::new("invalid writer mount inventory"))?;
        let f = before.split_whitespace().collect::<Vec<_>>();
        require(f.len() >= 6, "invalid writer mount inventory")?;
        if after.split_whitespace().next() == Some("efivarfs") && f[5].split(',').any(|o| o == "rw")
        {
            writable.push((f[3].to_owned(), f[4].to_owned()));
        }
    }
    let name = variable
        .file_name()
        .ok_or_else(|| common::Error::new("invalid witness path"))?
        .to_string_lossy();
    require(
        writable == vec![(format!("/{name}"), variable.to_string_lossy().into_owned())],
        "only the existing witness may be writable",
    )
}
pub fn main() -> Result<()> {
    check_sandbox(Path::new(crate::admission::VARIABLE))?;
    let mut data = Vec::new();
    io::stdin().take(4097).read_to_end(&mut data)?;
    require(
        !data.is_empty() && data.len() <= 4096,
        "invalid witness request size",
    )?;
    crate::admission::write_existing(&crate::admission::validate(&common::parse_json(&data)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn status(capability: &str, replacement: &str) -> String {
        let mut value = String::from("NoNewPrivs:\t1\nCapBnd:\tffffffffffffffff\n");
        for field in ["CapEff", "CapPrm", "CapInh", "CapAmb"] {
            value.push_str(&format!(
                "{field}:\t{}\n",
                if field == capability {
                    replacement
                } else {
                    "0000000000000200"
                }
            ));
        }
        value
    }
    #[test]
    fn writer_possesses_only_immutable_capability_with_no_new_privileges() {
        let valid = status("", "");
        assert!(check_process_authority(&valid, 0).is_ok());
        assert!(check_process_authority(&valid, 1000).is_err());
        assert!(
            check_process_authority(&valid.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), 0).is_err()
        );
        for capability in ["CapEff", "CapPrm", "CapInh", "CapAmb"] {
            for value in ["0", "0201", "invalid"] {
                assert!(check_process_authority(&status(capability, value), 0).is_err());
            }
        }
    }
    #[test]
    fn writer_can_modify_only_the_existing_single_variable_mount() {
        let variable = Path::new("/sys/firmware/efi/efivars/ParticleVE-owned");
        let root = "1 0 0:1 / / ro - btrfs /dev/owned ro\n";
        let single = "2 1 0:2 /ParticleVE-owned /sys/firmware/efi/efivars/ParticleVE-owned rw - efivarfs efivarfs rw\n";
        assert!(check_variable_mount(&format!("{root}{single}"), variable).is_ok());
        for invalid in [
            root.to_owned(),
            format!("{single}{single}"),
            single.replace("/ParticleVE-owned ", "/ "),
            single.replace(" rw -", " ro -"),
            "malformed mount inventory".to_owned(),
        ] {
            assert!(check_variable_mount(&invalid, variable).is_err());
        }
    }
}
