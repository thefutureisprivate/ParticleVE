//! Read-only checks for dump handling and cross-VM memory privacy.
use crate::common::{Error, Result, command, read_bounded, require};
use crate::processes::Process;
use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
pub const MAX_SMAPS: usize = 16 * 1024 * 1024;
pub const CORE_PATTERN: &str = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F %I";
fn inspect(args: &[&str]) -> Result<String> {
    let output = command(
        &args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        None,
        Some(Duration::from_secs(5)),
        8 * 1024 * 1024,
        false,
    )?;
    require(
        output.code == 0 && output.stderr.is_empty(),
        "cannot inspect native core configuration",
    )?;
    Ok(output.stdout)
}
pub fn parse_coredump_config(input: &str) -> Result<Value> {
    let mut section = String::new();
    let mut values = BTreeMap::new();
    let mut present = false;
    // Native systemd keys are case-sensitive. No interpolation or DEFAULT inheritance.
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            require(
                line.ends_with(']') && line.len() > 2,
                "cannot parse effective coredump configuration",
            )?;
            section = line[1..line.len() - 1].to_owned();
            if section == "Coredump" {
                present = true;
            }
            continue;
        }
        require(
            !section.is_empty(),
            "cannot parse effective coredump configuration",
        )?;
        let (key, value) = line
            .split_once('=')
            .or_else(|| line.split_once(':'))
            .ok_or_else(|| Error::new("cannot parse effective coredump configuration"))?;
        if section == "Coredump" {
            values.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    require(
        present
            && [
                ("Storage", "none"),
                ("ProcessSizeMax", "0"),
                ("EnterNamespace", "no"),
            ]
            .iter()
            .all(|(k, v)| values.get(*k).map(String::as_str) == Some(*v)),
        "coredump payload handling is enabled",
    )?;
    Ok(json!({"storage":"none","processsizemax":"0","enternamespace":"no"}))
}
pub fn core_handling() -> Result<Value> {
    parse_coredump_config(&inspect(&[
        "systemd-analyze",
        "cat-config",
        "--tldr",
        "systemd/coredump.conf",
    ])?)
}
pub fn configuration() -> Result<Value> {
    let mut result = core_handling()?;
    let output = inspect(&[
        "systemctl",
        "show",
        "--property=DefaultLimitCORE",
        "--property=DefaultLimitCORESoft",
    ])?;
    let lines: std::collections::BTreeSet<_> = output.lines().collect();
    require(
        lines
            == ["DefaultLimitCORE=0", "DefaultLimitCORESoft=0"]
                .into_iter()
                .collect(),
        "system manager core limits changed",
    )?;
    result["manager_core_limit"] = json!(0);
    Ok(result)
}
pub fn check_ksm_activation() -> Result<()> {
    let response = command(
        &["systemctl", "is-enabled", "ksm.service", "ksmtuned.service"].map(str::to_owned),
        None,
        Some(Duration::from_secs(5)),
        8 * 1024 * 1024,
        false,
    )?;
    let states: Vec<_> = response.stdout.lines().collect();
    require(
        [0, 1].contains(&response.code)
            && response.stderr.is_empty()
            && states.len() == 2
            && states
                .iter()
                .all(|s| ["masked", "masked-runtime"].contains(s)),
        "KSM activation is not masked",
    )
}
pub fn baseline(proc: &Path, sysfs: &Path) -> Result<Value> {
    require(
        String::from_utf8(read_bounded(proc.join("sys/fs/suid_dumpable"), 65536)?)?.trim() == "0",
        "privileged core dumps are enabled",
    )?;
    require(
        String::from_utf8(read_bounded(proc.join("sys/kernel/core_pattern"), 65536)?)?.trim()
            == CORE_PATTERN,
        "core dump handler changed",
    )?;
    let ksm = sysfs.join("kernel/mm/ksm");
    let mut observed = json!({"available":ksm.is_dir()});
    if ksm.is_dir() {
        for name in ["run", "pages_shared", "pages_sharing", "ksm_zero_pages"] {
            require(
                String::from_utf8(read_bounded(ksm.join(name), 65536)?)?.trim() == "0",
                format!("KSM is active or merged pages remain: {name}"),
            )?;
            observed[name] = json!(0);
        }
    }
    check_ksm_activation()?;
    Ok(json!({"ksm":observed,"core_handling":configuration()?,"suid_dumpable":0}))
}
pub fn process_policy(process: &Process, qemu: bool) -> Result<()> {
    let limits = process.text("limits", 65536)?;
    let re = Regex::new(r"(?m)^Max core file size\s+(\S+)\s+(\S+)\s+bytes\s*$")
        .map_err(|e| Error::new(e.to_string()))?;
    let rows: Vec<_> = re
        .captures_iter(&limits)
        .map(|c| (c[1].to_owned(), c[2].to_owned()))
        .collect();
    require(
        rows == [("0".to_owned(), "0".to_owned())],
        "VM process core limits are not both zero",
    )?;
    let filter = process.text("coredump_filter", 64)?;
    let mask = filter.trim();
    require(
        !mask.is_empty() && mask.len() <= 16 && mask.bytes().all(|b| b == b'0'),
        "VM core filter is not empty",
    )?;
    if qemu {
        let maps = process.text("smaps", MAX_SMAPS)?;
        let mappings = Regex::new(r"(?m)^[0-9a-f]+-[0-9a-f]+ ")
            .map_err(|e| Error::new(e.to_string()))?
            .find_iter(&maps)
            .count();
        let re = Regex::new(r"(?m)^VmFlags:[ \t]*(.*)$").map_err(|e| Error::new(e.to_string()))?;
        let flags: Vec<_> = re.captures_iter(&maps).map(|c| c[1].to_owned()).collect();
        require(
            mappings > 0 && mappings == flags.len(),
            "QEMU mapping observation is incomplete",
        )?;
        require(
            flags
                .iter()
                .all(|s| !s.split_whitespace().any(|f| f == "mg")),
            "QEMU memory is registered for KSM merging",
        )?;
        let sharing_re =
            Regex::new(r"(?m)^KSM:[ \t]+(\d+) kB$").map_err(|e| Error::new(e.to_string()))?;
        let sharing: Vec<_> = sharing_re
            .captures_iter(&maps)
            .map(|c| c[1].to_owned())
            .collect();
        match process.text("ksm_stat", 65536) {
            Err(e) if e.is_not_found() => require(
                sharing.is_empty(),
                "QEMU KSM accounting interface is missing",
            )?,
            Err(e) => return Err(e),
            Ok(stats) => {
                require(
                    sharing.len() == mappings,
                    "QEMU KSM observation is incomplete",
                )?;
                require(
                    sharing.iter().all(|s| s == "0"),
                    "QEMU has merged memory pages",
                )?;
                let counts_re = Regex::new(r"(?m)^ksm_(zero_pages|merging_pages) (\d+)$")
                    .map_err(|e| Error::new(e.to_string()))?;
                let counts: Vec<_> = counts_re
                    .captures_iter(&stats)
                    .map(|c| (c[1].to_owned(), c[2].to_owned()))
                    .collect();
                require(
                    counts.len() == 2
                        && counts.iter().cloned().collect::<BTreeMap<_, _>>()
                            == [
                                ("zero_pages".to_owned(), "0".to_owned()),
                                ("merging_pages".to_owned(), "0".to_owned()),
                            ]
                            .into_iter()
                            .collect(),
                    "QEMU retains KSM-shared or KSM-zero pages",
                )?;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_default_inheritance() {
        assert!(
            parse_coredump_config(
                "[DEFAULT]\nStorage=none\nProcessSizeMax=0\nEnterNamespace=no\n[Coredump]\n"
            )
            .is_err()
        );
        assert!(
            parse_coredump_config(
                "[Coredump]\nStorage=none\nProcessSizeMax=0\nEnterNamespace=no\n"
            )
            .is_ok()
        );
        assert!(
            parse_coredump_config(
                "[Coredump]\nstorage=none\nProcessSizeMax=0\nEnterNamespace=no\n"
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use std::fs;
    #[test]
    fn every_mapping_must_be_unmergeable_and_all_core_routes_disabled() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("123");
        fs::create_dir(&directory).unwrap();
        let maps = "1000-2000 rw-p 00000000 00:00 0\nKSM: 0 kB\nVmFlags: rd wr dd\n";
        fs::write(directory.join("limits"), "Max core file size 0 0 bytes\n").unwrap();
        fs::write(directory.join("coredump_filter"), "00000000\n").unwrap();
        fs::write(directory.join("smaps"), maps).unwrap();
        fs::write(
            directory.join("ksm_stat"),
            "ksm_zero_pages 0\nksm_merging_pages 0\n",
        )
        .unwrap();
        let process = Process::open(123, None, root.path()).unwrap();
        process_policy(&process, true).unwrap();
        for changed in [
            maps.replace("rd wr", "rd wr mg"),
            maps.replace("KSM: 0", "KSM: 4"),
            maps.replace("VmFlags: rd wr dd\n", ""),
            maps.replace("KSM: 0 kB\n", ""),
            String::new(),
        ] {
            fs::write(directory.join("smaps"), changed).unwrap();
            assert!(process_policy(&process, true).is_err());
        }
        fs::write(directory.join("smaps"), maps).unwrap();
        for stats in [
            "",
            "ksm_zero_pages 1\nksm_merging_pages 0\n",
            "ksm_zero_pages 0\nksm_merging_pages 1\n",
        ] {
            fs::write(directory.join("ksm_stat"), stats).unwrap();
            assert!(process_policy(&process, true).is_err());
        }
        fs::remove_file(directory.join("ksm_stat")).unwrap();
        fs::write(directory.join("smaps"), maps.replace("KSM: 0 kB\n", "")).unwrap();
        process_policy(&process, true).unwrap();
        fs::write(
            directory.join("limits"),
            "Max core file size 0 unlimited bytes\n",
        )
        .unwrap();
        assert!(process_policy(&process, false).is_err());
        fs::write(directory.join("limits"), "Max core file size 0 0 bytes\n").unwrap();
        fs::write(directory.join("coredump_filter"), "00000033\n").unwrap();
        assert!(process_policy(&process, false).is_err());
    }
}

#[cfg(test)]
mod observation_bounds_tests {
    use super::*;
    use std::fs;
    #[test]
    fn incomplete_filters_nonzero_soft_limits_and_excessive_maps_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("123");
        fs::create_dir(&directory).unwrap();
        let process = Process::open(123, None, root.path()).unwrap();
        fs::write(directory.join("limits"), "Max core file size 1 0 bytes\n").unwrap();
        fs::write(directory.join("coredump_filter"), "00000000").unwrap();
        assert!(process_policy(&process, false).is_err());
        fs::write(directory.join("limits"), "Max core file size 0 0 bytes\n").unwrap();
        fs::write(directory.join("coredump_filter"), "").unwrap();
        assert!(process_policy(&process, false).is_err());
        fs::write(directory.join("coredump_filter"), "00000000").unwrap();
        let maps = fs::File::create(directory.join("smaps")).unwrap();
        maps.set_len((MAX_SMAPS + 1) as u64).unwrap();
        assert!(
            process_policy(&process, true)
                .unwrap_err()
                .message
                .contains("bound")
        );
    }
}
