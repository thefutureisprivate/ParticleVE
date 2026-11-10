//! Checked byte geometry shared by planning and destructive installation.
use crate::common::{Error, Result, digest, field, list, object, require, text, uint};
use serde_json::{Value, json};
use uuid::Uuid;
pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * 1024 * 1024;
pub fn kind_type(kind: &str) -> Result<&'static str> {
    match kind {
        "esp" => Ok("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
        "usr" => Ok("8484680c-9521-48c6-9c11-b0720656f69e"),
        "verity" => Ok("77ff5f63-e7b6-4633-acf4-1565b864c0e6"),
        "verity_sig" => Ok("e7bb33fb-06cf-4e81-8273-e543b413e2e2"),
        "raid" => Ok("a19d880f-05fc-4d3b-a006-743f0f84911e"),
        "root" => Ok("4f68bce3-e8cd-4db1-96e7-fbcaf984b709"),
        _ => Err(Error::new("unknown partition kind")),
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| Error::new("layout arithmetic overflow"))
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| Error::new("layout arithmetic overflow"))
}
fn sub(a: u64, b: u64) -> Result<u64> {
    a.checked_sub(b)
        .ok_or_else(|| Error::new("selected disks cannot fit required partitions"))
}
pub fn os_label(version: &str) -> Result<String> {
    crate::config::version_key(version)?;
    Ok(format!("PVE_{version}"))
}
pub fn align(value: u64) -> Result<u64> {
    mul(add(value, MIB - 1)? / MIB, MIB)
}
fn number(v: &Value, k: &str) -> Result<u64> {
    uint(field(v, k)?)
}
pub fn calculate(config: &Value, devices: &[Value], release: &Value) -> Result<Value> {
    require(
        devices.len() == 2,
        "layout requires exactly two observed disks",
    )?;
    require(
        field(&devices[0], "identity")? != field(&devices[1], "identity")?,
        "selected paths alias the same physical disk",
    )?;
    for d in devices {
        require(
            matches!(number(d, "logical_sector")?, 512 | 4096),
            "only 512-byte and 4Kn logical sectors supported",
        )?;
        require(
            matches!(number(d, "physical_sector")?, 512 | 4096),
            "unsupported physical sector size",
        )?;
        require(number(d, "size")? > 0, "disk capacity is unavailable")?;
    }
    let storage = field(config, "storage")?;
    let artifacts = field(release, "artifacts")?;
    let mut working = 0;
    for k in ["usr", "verity", "verity_sig", "uki"] {
        working = add(working, number(field(artifacts, k)?, "size")?)?;
    }
    working = mul(3, working)?;
    let esp = mul(number(storage, "esp_mib")?, MIB)?;
    let boot = add(
        number(field(artifacts, "uki")?, "size")?,
        number(field(artifacts, "bootloader")?, "size")?,
    )?;
    require(
        esp >= align(add(
            mul(3, boot)?,
            mul(number(storage, "firmware_staging_mib")?, MIB)?,
        )?)?,
        "ESP cannot retain boot artifacts, staging space, and growth margin",
    )?;
    let mut sizes = std::collections::BTreeMap::new();
    for k in ["usr", "verity", "verity_sig"] {
        sizes.insert(
            k,
            align(
                mul(
                    number(field(artifacts, k)?, "size")?,
                    add(100, number(storage, "usr_growth_percent")?)?,
                )? / 100,
            )?,
        );
    }
    require(
        number(field(artifacts, "verity_sig")?, "size")? == MIB,
        "signature payload must completely cover its fixed partition",
    )?;
    sizes.insert("verity_sig", MIB);
    let swap = mul(add(number(storage, "swap_mib")?, 160)?, MIB)?;
    let slots = sizes.values().try_fold(0, |a, b| add(a, *b))?;
    let fixed = add(add(add(MIB, esp)?, mul(2, slots)?)?, swap)?;
    let end = mul(
        sub(
            number(&devices[0], "size")?.min(number(&devices[1], "size")?) / MIB,
            1,
        )?,
        MIB,
    )?;
    let state = sub(end, fixed)?;
    let usable = sub(state, 32 * MIB)?;
    let reserve = mul(number(storage, "reserve_mib")?, MIB)?
        .max(mul(usable, number(storage, "reserve_percent")?)? / 100);
    require(
        usable >= mul(number(storage, "minimum_state_mib")?, MIB)?
            && sub(usable, reserve)? >= add(working, 2048 * MIB)?,
        "selected disks cannot fit state, update working space and shared filesystem headroom",
    )?;
    let selected = list(field(config, "disks")?)?;
    require(
        selected.len() == devices.len(),
        "layout requires exactly two selected disks",
    )?;
    let mut disks = Vec::new();
    for (selected, observed) in selected.iter().zip(devices) {
        let mut offset = MIB;
        let mut partitions = Vec::new();
        let mut append = |role: String,
                          size: u64,
                          kind: &str,
                          label: String,
                          part_uuid: Option<&Value>|
         -> Result<()> {
            partitions.push(json!({"number":partitions.len()+1,"role":role,"offset":offset,"size":size,"type":kind_type(kind)?,"label":label,"uuid":part_uuid.cloned().unwrap_or_else(||json!(Uuid::new_v4().to_string()))}));
            offset = add(offset, size)?;
            Ok(())
        };
        append(
            "esp".into(),
            esp,
            "esp",
            format!("ParticleVE-esp-{}", text(field(selected, "role")?)?),
            None,
        )?;
        for slot in ["a", "b"] {
            for k in ["verity_sig", "verity", "usr"] {
                append(
                    format!("{slot}_{k}"),
                    sizes[k],
                    k,
                    if slot == "a" {
                        os_label(text(field(release, "version")?)?)?
                    } else {
                        "_empty".into()
                    },
                    if slot == "a" {
                        Some(field(field(artifacts, k)?, "partition_uuid")?)
                    } else {
                        None
                    },
                )?;
            }
        }
        append(
            "state".into(),
            state,
            "root",
            format!("ParticleVE-state-{}", text(field(selected, "role")?)?),
            None,
        )?;
        append("swap".into(), swap, "raid", "ParticleVE-swap".into(), None)?;
        require(offset == end, "internal layout accounting error")?;
        let mut disk = object(selected)?.clone();
        disk.insert("observed".into(), observed.clone());
        disk.insert("disk_uuid".into(), json!(Uuid::new_v4().to_string()));
        disk.insert("partitions".into(), json!(partitions));
        disks.push(Value::Object(disk));
    }
    let mut result = json!({"schema":1,"storage_admission":"uefi-witness-v1","installation_uuid":Uuid::new_v4().to_string(),"config_sha256":digest(config)?,"release":field(release,"version")?,"release_sha256":digest(release)?,"devices":disks,"state_usable_bytes":usable,"state_reserve_bytes":reserve,"storage_policy":{"filesystem":"btrfs","data":"raid1","metadata":"raid1","factory_reset":false,"subvolumes":["/var"]}});
    result["confirmation"] = json!(digest(&result)?);
    Ok(result)
}
pub fn sfdisk_script(device: &Value) -> Result<String> {
    let sector = number(field(device, "observed")?, "logical_sector")?;
    require(matches!(sector, 512 | 4096), "invalid logical sector size")?;
    let mut result = format!(
        "label: gpt\nlabel-id: {}\nunit: sectors\n",
        text(field(device, "disk_uuid")?)?
    );
    for p in list(field(device, "partitions")?)? {
        let label = text(field(p, "label")?)?;
        require(
            label.encode_utf16().count() <= 36,
            "GPT label exceeds 36 UTF-16 code units",
        )?;
        result.push_str(&format!(
            "start={}, size={}, type={}, uuid={}, name=\"{}\"\n",
            number(p, "offset")? / sector,
            number(p, "size")? / sector,
            text(field(p, "type")?)?,
            text(field(p, "uuid")?)?,
            label
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_geometry_never_wraps() {
        assert_eq!(align(MIB + 1).unwrap(), 2 * MIB);
        assert!(align(u64::MAX).is_err());
        assert!(sub(0, 1).is_err());
        assert!(mul(u64::MAX, 2).is_err());
    }
    #[test]
    fn gpt_labels_count_utf16_not_utf8() {
        let device = json!({"observed":{"logical_sector":4096},"disk_uuid":Uuid::new_v4().to_string(),"partitions":[{"offset":MIB,"size":MIB,"type":kind_type("esp").unwrap(),"uuid":Uuid::new_v4().to_string(),"label":"😀".repeat(18)}]});
        assert!(sfdisk_script(&device).is_ok());
        let mut oversized = device;
        oversized["partitions"][0]["label"] = json!("😀".repeat(19));
        assert!(sfdisk_script(&oversized).is_err());
    }
}
