//! Native encrypted Btrfs mirror and separately encrypted md swap observations.
use crate::common::{self, Error, Result, field, list, read_json, require, run, text, uint};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Duration};
pub fn array_uuid(name: &str) -> Result<String> {
    let out = run(&["mdadm", "--detail", "--export", &format!("/dev/md/{name}")])?;
    let value = out
        .stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| *k == "MD_UUID")
        .map(|(_, v)| v)
        .ok_or_else(|| Error::new(format!("array UUID unavailable: {name}")))?;
    require(!value.is_empty(), format!("array UUID unavailable: {name}"))?;
    Ok(value.into())
}
pub fn profiles(input: &str) -> Result<Vec<Value>> {
    let re =
        regex::Regex::new(r"^(Data|Metadata|System), ([A-Za-z0-9]+): total=(\d+), used=(\d+)$")
            .expect("constant expression");
    let mut rows = Vec::new();
    for line in input.lines() {
        if let Some(m) = re.captures(line.trim()) {
            rows.push(json!({"kind":m[1].to_lowercase(),"profile":m[2].to_lowercase(),"total":m[3].parse::<u64>().map_err(|_|Error::new("invalid Btrfs allocation size"))?,"used":m[4].parse::<u64>().map_err(|_|Error::new("invalid Btrfs allocation size"))?}));
        }
    }
    require(
        ["data", "metadata"]
            .iter()
            .all(|k| rows.iter().any(|r| r["kind"] == *k)),
        "Btrfs allocation profiles unavailable",
    )?;
    Ok(rows)
}
pub fn members(input: &str) -> Result<Vec<Value>> {
    let re = regex::Regex::new(r"^\s*devid\s+(\d+)\s+size\s+(\d+)\s+used\s+(\d+)\s+path\s+(.+)$")
        .expect("constant expression");
    let mut rows = Vec::new();
    for line in input.lines() {
        if let Some(m) = re.captures(line) {
            rows.push(json!({"devid":m[1].parse::<u64>().map_err(|_|Error::new("invalid Btrfs devid"))?,"size":m[2].parse::<u64>().map_err(|_|Error::new("invalid Btrfs member size"))?,"used":m[3].parse::<u64>().map_err(|_|Error::new("invalid Btrfs member size"))?,"path":&m[4]}));
        }
    }
    Ok(rows)
}
pub fn present_members(
    manifest: &Value,
    devices: &[Value],
    admitted: Option<&[String]>,
) -> Result<Vec<Value>> {
    require(
        (1..=2).contains(&devices.len()),
        "Btrfs device inventory is ambiguous",
    )?;
    let mut ids = std::collections::BTreeSet::new();
    for d in devices {
        require(
            ids.insert(uint(field(d, "devid")?)?),
            "duplicate Btrfs device identity",
        )?;
    }
    let mut present = Vec::new();
    let device_expression =
        regex::Regex::new(r"(?m)^\s*device:\s*(.+)$").expect("constant expression");
    for member in devices {
        let matches = list(field(manifest, "devices")?)?
            .iter()
            .filter(|d| d.get("btrfs_devid") == member.get("devid"))
            .collect::<Vec<_>>();
        require(matches.len() == 1, "unrecorded Btrfs device")?;
        let disk = matches[0];
        let role = text(field(disk, "role")?)?;
        let mapper = format!("particleve-state-{role}");
        let part = list(field(disk, "partitions")?)?
            .iter()
            .find(|p| p["role"] == "state")
            .ok_or_else(|| Error::new("missing state partition"))?;
        let underlying = Path::new("/dev/disk/by-partuuid").join(text(field(part, "uuid")?)?);
        if text(field(member, "path")?)? == "MISSING" {
            require(
                uint(field(member, "size")?)? == 0
                    && uint(field(member, "used")?)? == 0
                    && (admitted.is_some_and(|a| !a.iter().any(|r| r == role))
                        || (!Path::new(text(field(disk, "path")?)?).exists()
                            && !underlying.exists()))
                    && !Path::new("/dev/mapper").join(&mapper).exists(),
                "Btrfs missing member conflicts with an available recorded device",
            )?;
            continue;
        }
        require(
            admitted.is_none_or(|a| a.iter().any(|r| r == role)),
            "quarantined Btrfs member was assembled",
        )?;
        require(
            fs::canonicalize(text(field(member, "path")?)?)?
                == fs::canonicalize(Path::new("/dev/mapper").join(&mapper))?,
            "Btrfs device mapping changed",
        )?;
        require(
            run(&[
                "cryptsetup",
                "luksUUID",
                underlying
                    .to_str()
                    .ok_or_else(|| Error::new("invalid partition path"))?,
            ])?
            .stdout
            .trim()
                == text(field(disk, "state_luks_uuid")?)?,
            "state LUKS identity changed",
        )?;
        let detail = run(&["cryptsetup", "status", &mapper])?.stdout;
        let path = device_expression
            .captures(&detail)
            .and_then(|m| m.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| Error::new("state mapper uses an unexpected partition"))?;
        require(
            fs::canonicalize(path)? == fs::canonicalize(underlying)?,
            "state mapper uses an unexpected partition",
        )?;
        present.push(member.clone());
    }
    require(!present.is_empty(), "no recorded Btrfs member is available")?;
    Ok(present)
}
fn observe(args: &[&str]) -> Result<common::Output> {
    common::command(
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        None,
        Some(Duration::from_secs(120)),
        8 * 1024 * 1024,
        false,
    )
}
pub fn status(manifest: &Value, config: &Value, healthy: bool) -> Result<Value> {
    let journal = Path::new("/var/lib/particleve/replacement.json");
    let replacement = if journal.exists() {
        Some(text(field(&read_json(journal)?, "role")?)?.to_owned())
    } else {
        None
    };
    let witness = crate::admission::verify_manifest(manifest, replacement.as_deref())?;
    let mut admitted = list(field(&witness, "allowed")?)?
        .iter()
        .map(|v| text(v).map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    if let Some(role) = replacement {
        admitted.push(role);
    }
    let fsid = text(field(field(manifest, "btrfs")?, "uuid")?)?;
    require(
        Path::new("/sys/fs/btrfs").join(fsid).exists(),
        "recorded Btrfs root is not mounted",
    )?;
    let allocation = profiles(&run(&["btrfs", "filesystem", "df", "--raw", "/"])?.stdout)?;
    let devices = present_members(
        manifest,
        &members(&run(&["btrfs", "filesystem", "show", "--raw", "/"])?.stdout)?,
        Some(&admitted),
    )?;
    let md = Path::new("/dev/md/particleve-swap");
    require(
        md.exists()
            && array_uuid("particleve-swap")? == text(field(field(manifest, "swap")?, "md_uuid")?)?,
        "swap array identity changed",
    )?;
    require(
        run(&["cryptsetup", "luksUUID", "/dev/md/particleve-swap"])?
            .stdout
            .trim()
            == text(field(field(manifest, "swap")?, "luks_uuid")?)?,
        "swap LUKS identity changed",
    )?;
    let detail = run(&["cryptsetup", "status", "particleve-swap"])?.stdout;
    let path = regex::Regex::new(r"(?m)^\s*device:\s*(.+)$")
        .expect("constant expression")
        .captures(&detail)
        .and_then(|m| m.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| Error::new("swap mapper uses an unexpected device"))?;
    let resolved = fs::canonicalize(md)?;
    require(
        fs::canonicalize(path)? == resolved,
        "swap mapper uses an unexpected device",
    )?;
    let sys = Path::new("/sys/class/block")
        .join(
            resolved
                .file_name()
                .ok_or_else(|| Error::new("invalid swap device"))?,
        )
        .join("md");
    let degraded = fs::read_to_string(sys.join("degraded"))?
        .trim()
        .parse::<u64>()
        .map_err(|_| Error::new("invalid swap redundancy observation"))?;
    let sync = fs::read_to_string(sys.join("sync_action"))?
        .trim()
        .to_owned();
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the constant path is NUL terminated and the kernel writes a full statvfs record on success.
    if unsafe { libc::statvfs(c"/".as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful statvfs initialized the record.
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| Error::new("filesystem capacity overflow"))?;
    let total = stat
        .f_blocks
        .checked_mul(stat.f_frsize)
        .ok_or_else(|| Error::new("filesystem capacity overflow"))?;
    let storage = field(config, "storage")?;
    let reserve = uint(field(storage, "reserve_mib")?)?
        .checked_mul(1024 * 1024)
        .ok_or_else(|| Error::new("reserve capacity overflow"))?
        .max(
            total
                .checked_mul(uint(field(storage, "reserve_percent")?)?)
                .ok_or_else(|| Error::new("reserve capacity overflow"))?
                / 100,
        );
    let errors = observe(&["btrfs", "device", "stats", "--check", "/"])?;
    require(
        matches!(errors.code, 0 | 64),
        "cannot read Btrfs device error counters",
    )?;
    let scrub = observe(&["btrfs", "scrub", "status", "/"])?;
    if healthy {
        if devices.len() != 2 || degraded != 0 || sync != "idle" {
            return Err(Error::deferred(
                "Btrfs or swap redundancy is degraded or rebuilding",
            ));
        }
        if allocation.iter().any(|r| r["profile"] != "raid1") {
            return Err(Error::deferred(
                "allocated Btrfs data/metadata/system profiles have not returned to RAID1",
            ));
        }
        require(
            errors.code == 0,
            "Btrfs reports device errors; inspect scrub and device health",
        )?;
        let re = regex::Regex::new(r"(?i)Uncorrectable:\s*(\d+)").expect("constant expression");
        require(
            re.captures(&scrub.stdout)
                .is_none_or(|m| m[1].parse::<u64>() == Ok(0)),
            "Btrfs scrub reports uncorrectable errors",
        )?;
        require(free >= reserve, "shared Btrfs free-space reserve exhausted")?;
        for row in &allocation {
            if row["kind"] == "metadata" {
                require(
                    (uint(field(row, "used")?)? as u128) * 100
                        <= (uint(field(row, "total")?)? as u128)
                            * (uint(field(storage, "metadata_max_percent")?)? as u128),
                    "Btrfs metadata allocation exceeds the maintenance threshold",
                )?;
            }
        }
        require(
            observe(&["btrfs", "balance", "status", "/"])?
                .stdout
                .to_lowercase()
                .contains("no balance found"),
            "Btrfs balance is active or cannot be excluded",
        )?;
        let replacing = observe(&["btrfs", "replace", "status", "-1", "/"])?
            .stdout
            .to_lowercase();
        require(
            replacing.contains("never started") || replacing.contains("finished"),
            "Btrfs replacement is active or cannot be excluded",
        )?;
        if journal.exists() {
            return Err(Error::deferred(
                "disk replacement has not been finalized and commissioned",
            ));
        }
    }
    let allowed = list(field(&witness, "allowed")?)?;
    let quarantined = ["a", "b"]
        .iter()
        .filter(|r| !allowed.contains(&json!(r)))
        .collect::<Vec<_>>();
    Ok(
        json!({"uuid":fsid,"devices":devices,"allocation":allocation,"free_bytes":free,"reserve_bytes":reserve,"swap_degraded":degraded,"swap_sync_action":sync,"device_errors":errors.stdout,"scrub":scrub.stdout,"nocow_payload_checksums":false,"admitted_roles":allowed,"quarantined_roles":quarantined}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_allocated_profiles_including_system_are_preserved() {
        let rows=profiles("Data, RAID1: total=1000, used=20\nMetadata, RAID1: total=300, used=10\nSystem, single: total=10, used=0\n").unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2]["profile"], "single");
        assert!(profiles("Data, RAID1: total=10, used=1").is_err());
    }
    #[test]
    fn quarantined_present_mapping_is_rejected_before_open() {
        let manifest = json!({"devices":[{"role":"a","path":"/dev/returned","btrfs_devid":1,"partitions":[{"role":"state","uuid":"old"}]}]});
        let row = json!({"devid":1,"size":100,"used":0,"path":"/dev/mapper/particleve-state-a"});
        let error = present_members(&manifest, &[row], Some(&["b".into()])).unwrap_err();
        assert!(error.to_string().contains("quarantined"));
    }
    #[test]
    fn duplicate_and_unknown_device_identity_fail_closed() {
        let manifest = json!({"devices":[]});
        let row = json!({"devid":1,"size":100,"used":0,"path":"/dev/something"});
        assert!(
            present_members(&manifest, &[row.clone(), row.clone()], None)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(
            present_members(&manifest, &[row], None)
                .unwrap_err()
                .to_string()
                .contains("unrecorded")
        );
    }
}
