//! Firmware-backed mirror authority, evaluated before unlocking or scanning state.
use crate::common::{
    self, Error, Result, boolean, canonical, field, list, object, read_json, require, run, text,
    uint, write_json,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;
pub const VARIABLE: &str =
    "/sys/firmware/efi/efivars/ParticleVEStorage-59a481c6-fbbc-4d82-8617-37eae6ebdf21";
pub const RUNTIME: &str = "/run/particleve-admission";
pub const SESSION: &str = "/run/particleve-admission/session.json";
fn uuid(value: &Value) -> Result<()> {
    let s = text(value)?;
    require(
        Uuid::parse_str(s).is_ok_and(|v| v.to_string() == s),
        "invalid witness UUID",
    )
}
fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let actual = object(value)?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    require(
        actual == expected.iter().copied().collect(),
        "incomplete or unknown storage witness fields",
    )
}
pub fn validate(record: &Value) -> Result<Value> {
    require(
        field(record, "schema")?.as_u64() == Some(1),
        "unsupported storage witness",
    )?;
    keys(
        record,
        &[
            "schema",
            "installation_uuid",
            "btrfs_uuid",
            "members",
            "allowed",
            "active",
            "nonce",
            "wait_seconds",
        ],
    )?;
    for k in ["installation_uuid", "btrfs_uuid", "nonce"] {
        uuid(field(record, k)?)?;
    }
    require(
        (5..=120).contains(&uint(field(record, "wait_seconds")?)?),
        "invalid storage wait",
    )?;
    keys(field(record, "members")?, &["a", "b"])?;
    boolean(field(record, "active")?)?;
    let allowed = list(field(record, "allowed")?)?;
    let mut seen = BTreeSet::new();
    for role in allowed {
        let r = text(role)?;
        require(
            matches!(r, "a" | "b") && seen.insert(r),
            "invalid authoritative storage members",
        )?;
    }
    for member in object(field(record, "members")?)?.values() {
        keys(member, &["state", "swap", "esp", "luks"])?;
        for v in object(member)?.values() {
            uuid(v)?;
        }
    }
    Ok(record.clone())
}
pub fn load() -> Result<Value> {
    (|| {
        let data = common::read_bounded(VARIABLE, 4096)?;
        require(
            data.starts_with(&[7, 0, 0, 0]),
            "unexpected storage witness attributes",
        )?;
        validate(&common::parse_json(&data[4..])?)
    })()
    .map_err(|_: Error| {
        Error::new("storage admission witness unavailable; owner recovery is required")
    })
}
fn ioctl(fd: i32, request: libc::c_ulong, data: *mut libc::c_void) -> Result<()> {
    // SAFETY: callers provide the exact Linux UAPI buffer and hold the fd throughout this synchronous ioctl.
    let result = unsafe { libc::ioctl(fd, request, data) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub fn write_existing(record: &Value) -> Result<()> {
    let mut data = vec![7, 0, 0, 0];
    data.extend(canonical(&validate(record)?)?);
    require(
        data.len() <= 4096,
        "storage witness exceeds firmware variable limit",
    )?;
    let reader = File::open(VARIABLE)?;
    let mut flags: libc::c_ulong = 0;
    ioctl(
        reader.as_raw_fd(),
        0x80086601,
        (&mut flags as *mut libc::c_ulong).cast(),
    )?;
    let operation = (|| {
        if flags & 0x10 != 0 {
            let mut writable = flags & !0x10;
            ioctl(
                reader.as_raw_fd(),
                0x40086602,
                (&mut writable as *mut libc::c_ulong).cast(),
            )?;
        }
        let mut writer = OpenOptions::new().write(true).open(VARIABLE)?;
        let count = writer.write(&data)?;
        require(count == data.len(), "short storage witness write")
    })();
    let cleanup = if flags & 0x10 != 0 {
        ioctl(
            reader.as_raw_fd(),
            0x40086602,
            (&mut flags as *mut libc::c_ulong).cast(),
        )
    } else {
        Ok(())
    };
    operation?;
    cleanup?;
    require(load()? == *record, "storage witness write did not persist")
}
pub fn save(record: &Value) -> Result<()> {
    crate::witness::save(record)
}
pub fn bindings(manifest: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for disk in list(field(manifest, "devices")?)? {
        let mut member = serde_json::Map::new();
        for p in list(field(disk, "partitions")?)? {
            let role = text(field(p, "role")?)?;
            if matches!(role, "state" | "swap" | "esp") {
                member.insert(role.into(), field(p, "uuid")?.clone());
            }
        }
        member.insert("luks".into(), field(disk, "state_luks_uuid")?.clone());
        result.insert(text(field(disk, "role")?)?.into(), Value::Object(member));
    }
    Ok(Value::Object(result))
}
pub fn initialize(manifest: &Value) -> Result<()> {
    require(
        !Path::new(VARIABLE).exists(),
        "existing storage witness requires owner review before reinstall",
    )?;
    let record = json!({"schema":1,"installation_uuid":field(manifest,"installation_uuid")?,"btrfs_uuid":field(field(manifest,"btrfs")?,"uuid")?,"members":bindings(manifest)?,"allowed":["a","b"],"active":false,"nonce":Uuid::new_v4().to_string(),"wait_seconds":field(manifest,"storage_wait_seconds")?});
    let _created = OpenOptions::new()
        .read(true)
        .create_new(true)
        .mode(0o600)
        .open(VARIABLE)?;
    write_existing(&record)
}
pub fn choose(record: &Value, present: &[String]) -> Result<Value> {
    validate(record)?;
    require(
        !boolean(field(record, "active")?)?,
        "unclean storage session; select an authoritative survivor in owner recovery",
    )?;
    let allowed = list(field(record, "allowed")?)?
        .iter()
        .filter(|r| r.as_str().is_some_and(|s| present.iter().any(|p| p == s)))
        .cloned()
        .collect::<Vec<_>>();
    require(
        !allowed.is_empty(),
        "only quarantined or no storage members are present; rebuild from the authoritative survivor",
    )?;
    let mut selected = record.clone();
    selected["allowed"] = json!(allowed);
    selected["active"] = json!(true);
    selected["nonce"] = json!(Uuid::new_v4().to_string());
    Ok(selected)
}
pub fn disk_sequence(state_uuid: &str) -> Result<String> {
    let partition = fs::canonicalize(Path::new("/dev/disk/by-partuuid").join(state_uuid))?;
    let sys = fs::canonicalize(
        Path::new("/sys/class/block").join(
            partition
                .file_name()
                .ok_or_else(|| Error::new("invalid state partition"))?,
        ),
    )?;
    require(
        sys.join("partition").exists(),
        "state must be a physical disk partition",
    )?;
    Ok(fs::read_to_string(
        sys.parent()
            .ok_or_else(|| Error::new("invalid partition sysfs path"))?
            .join("diskseq"),
    )?
    .trim()
    .into())
}
pub fn begin() -> Result<()> {
    let record = load()?;
    let deadline = Instant::now() + Duration::from_secs(uint(field(&record, "wait_seconds")?)?);
    let present = loop {
        let mut p = Vec::new();
        for role in list(field(&record, "allowed")?)? {
            let role = text(role)?;
            let state = text(field(field(field(&record, "members")?, role)?, "state")?)?;
            if Path::new("/dev/disk/by-partuuid").join(state).exists() {
                p.push(role.to_owned());
            }
        }
        if p.len() == list(field(&record, "allowed")?)?.len() || Instant::now() >= deadline {
            break p;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let selected = choose(&record, &present)?;
    let mut sequences = serde_json::Map::new();
    for role in list(field(&selected, "allowed")?)? {
        let role = text(role)?;
        sequences.insert(
            role.into(),
            json!(disk_sequence(text(field(
                field(field(&selected, "members")?, role)?,
                "state"
            )?)?)?),
        );
    }
    write_existing(&selected)?;
    write_json(SESSION, &json!({"witness":selected,"diskseq":sequences}))
}
pub fn verify_manifest(manifest: &Value, replacing: Option<&str>) -> Result<Value> {
    let record = load()?;
    let actual = bindings(manifest)?;
    let mut expected = field(&record, "members")?.clone();
    if let Some(role) = replacing
        && actual != expected
    {
        require(
            !list(field(&record, "allowed")?)?.contains(&json!(role))
                && list(field(&record, "allowed")?)?.len() == 1,
            "replacement target was not quarantined",
        )?;
        expected[role] = field(&actual, role)?.clone();
    }
    require(
        manifest.get("storage_admission") == Some(&json!("uefi-witness-v1"))
            && manifest.get("installation_uuid") == record.get("installation_uuid")
            && field(field(manifest, "btrfs")?, "uuid")? == field(&record, "btrfs_uuid")?
            && actual == expected,
        "encrypted installation and firmware storage witness disagree",
    )?;
    Ok(record)
}
fn directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?)
}
fn fs_info(fd: i32) -> Result<[u8; 1024]> {
    let mut data = [0; 1024];
    ioctl(fd, 0x8400941F, data.as_mut_ptr().cast())?;
    Ok(data)
}
fn fs_uuid(data: &[u8; 1024]) -> String {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&data[16..32]);
    Uuid::from_bytes(bytes).to_string()
}
pub fn mounted_uuid(target: &Path) -> Result<String> {
    let fd = directory(target)?;
    Ok(fs_uuid(&fs_info(fd.as_raw_fd())?))
}
fn resolve(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        Ok(fs::canonicalize(path)?)
    } else {
        Ok(path.to_owned())
    }
}
pub fn mounts(record: &Value) -> Result<Vec<Value>> {
    let table = common::parse_json(
        run(&[
            "findmnt",
            "--json",
            "--list",
            "--types",
            "btrfs",
            "--output",
            "SOURCE,OPTIONS,TARGET",
        ])?
        .stdout
        .as_bytes(),
    )?;
    let mut sources = Vec::new();
    for role in object(field(record, "members")?)?.keys() {
        sources.push(resolve(
            &Path::new("/dev/mapper").join(format!("particleve-state-{role}")),
        )?);
    }
    let mut selected = Vec::new();
    if let Some(filesystems) = table.get("filesystems") {
        for mounted in list(filesystems)? {
            let source = text(field(mounted, "source")?)?
                .split('[')
                .next()
                .ok_or_else(|| Error::new("invalid mount source"))?;
            if !sources.contains(&resolve(Path::new(source))?) {
                continue;
            }
            require(
                mounted_uuid(Path::new(text(field(mounted, "target")?)?))?
                    == text(field(record, "btrfs_uuid")?)?,
                "mounted state filesystem identity changed",
            )?;
            selected.push(mounted.clone());
        }
    }
    require(
        !selected.is_empty(),
        "authoritative Btrfs filesystem is not mounted",
    )?;
    selected.sort_by_key(|m| m["target"].as_str().map_or(usize::MAX, str::len));
    Ok(selected)
}
fn get64(data: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        data[offset..offset + 8]
            .try_into()
            .expect("fixed UAPI slice"),
    )
}
fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}
fn validate_member_fsid(info: &[u8; 1024], expected: &str) -> Result<()> {
    require(fs_uuid(info) == expected, "storage filesystem changed")
}
fn validate_inventory_count(count: usize) -> Result<()> {
    require(
        (1..=3).contains(&count),
        "unexpected Btrfs device inventory",
    )
}
fn canonical_device_id(name: &str) -> Result<u64> {
    let id = name
        .parse::<u64>()
        .map_err(|_| Error::new("invalid Btrfs device ID"))?;
    require(
        !name.is_empty() && name.len() <= 20 && id.to_string() == name,
        "invalid Btrfs device ID",
    )?;
    Ok(id)
}
fn member_device_path(device: &[u8; 4096], id: u64) -> Result<Option<&str>> {
    require(get64(device, 0) == id, "Btrfs device identity changed")?;
    let path = &device[3072..];
    let end = path
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::new("unterminated Btrfs device path"))?;
    let path =
        std::str::from_utf8(&path[..end]).map_err(|_| Error::new("invalid Btrfs device path"))?;
    if path.is_empty() {
        return Ok(None);
    }
    require(Path::new(path).is_absolute(), "invalid Btrfs device path")?;
    Ok(Some(path))
}
fn member_counters(stats: &[u8; 1032], id: u64) -> Result<[u64; 5]> {
    require(
        get64(stats, 0) == id && get64(stats, 8) == 5 && get64(stats, 16) == 0,
        "incomplete Btrfs member error inventory",
    )?;
    Ok(std::array::from_fn(|i| get64(stats, 24 + i * 8)))
}
pub fn member_errors(record: &Value, target: &Path, mapper: &Path) -> Result<[u64; 5]> {
    let expected = fs::canonicalize(mapper)?;
    require(
        expected.metadata()?.file_type().is_block_device(),
        "storage member is not a block device",
    )?;
    let fd = directory(target)?;
    validate_member_fsid(
        &fs_info(fd.as_raw_fd())?,
        text(field(record, "btrfs_uuid")?)?,
    )?;
    let entries = fs::read_dir(
        Path::new("/sys/fs/btrfs")
            .join(text(field(record, "btrfs_uuid")?)?)
            .join("devinfo"),
    )?
    .take(4)
    .collect::<std::io::Result<Vec<_>>>()?;
    validate_inventory_count(entries.len())?;
    let mut ids = BTreeSet::new();
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::new("invalid Btrfs device ID"))?;
        let id = canonical_device_id(&name)?;
        if id != 0 {
            require(ids.insert(id), "duplicate Btrfs device ID")?;
        }
    }
    let mut matches = Vec::new();
    for id in ids {
        let mut device = [0; 4096];
        put64(&mut device, 0, id);
        if let Err(err) = ioctl(fd.as_raw_fd(), 0xD000941E, device.as_mut_ptr().cast()) {
            if err.is_errno(libc::ENODEV) {
                continue;
            }
            return Err(err);
        }
        if let Some(path) = member_device_path(&device, id)?
            && resolve(Path::new(path))? == expected
        {
            matches.push(id);
        }
    }
    require(
        matches.len() == 1,
        "admitted Btrfs mapping is unavailable or ambiguous",
    )?;
    let mut stats = [0; 1032];
    put64(&mut stats, 0, matches[0]);
    put64(&mut stats, 8, 5);
    put64(&mut stats, 16, 0);
    ioctl(fd.as_raw_fd(), 0xC4089434, stats.as_mut_ptr().cast())?;
    member_counters(&stats, matches[0])
}

pub fn watch() -> Result<Value> {
    let _lock = common::lock(RUNTIME)?;
    let session = read_json(SESSION)?;
    let record = load()?;
    require(
        record == *field(&session, "witness")? && boolean(field(&record, "active")?)?,
        "storage session witness changed",
    )?;
    let allowed = list(field(&record, "allowed")?)?;
    require(
        !allowed.is_empty(),
        "no authoritative storage members remain; owner recovery required",
    )?;
    let mounted = mounts(&record)?;
    let target = Path::new(text(field(&mounted[0], "target")?)?);
    let mut failed = BTreeSet::new();
    for role in allowed {
        let role = text(role)?;
        let sequence = disk_sequence(text(field(
            field(field(&record, "members")?, role)?,
            "state",
        )?)?);
        if !sequence
            .as_ref()
            .is_ok_and(|s| Some(s.as_str()) == session["diskseq"][role].as_str())
        {
            failed.insert(role.to_owned());
            continue;
        }
        if member_errors(
            &record,
            target,
            &Path::new("/dev/mapper").join(format!("particleve-state-{role}")),
        )?
        .iter()
        .any(|v| *v != 0)
        {
            failed.insert(role.to_owned());
        }
    }
    if failed.is_empty() {
        return Ok(json!({"storage_admission":allowed}));
    }
    let mut new = record.clone();
    new["allowed"] = json!(
        allowed
            .iter()
            .filter(|r| !failed.contains(r.as_str().unwrap_or("")))
            .collect::<Vec<_>>()
    );
    new["nonce"] = json!(Uuid::new_v4().to_string());
    let persistence = save(&new);
    for role in failed {
        fence_mapper(&format!("particleve-state-{role}"), &mut |args| run(args))?;
    }
    if let Err(err) = persistence {
        return Err(Error::new(format!(
            "failed mappings fenced; quarantine persistence failed: {err}"
        )));
    }
    let mut sequences = serde_json::Map::new();
    for role in list(field(&new, "allowed")?)? {
        let role = text(role)?;
        sequences.insert(
            role.into(),
            field(field(&session, "diskseq")?, role)?.clone(),
        );
    }
    write_json(SESSION, &json!({"witness":new,"diskseq":sequences}))?;
    Err(Error::new(
        "failed storage members fenced and quarantined; stop guests and rebuild in owner maintenance",
    ))
}
fn fence_mapper(
    mapper: &str,
    command: &mut impl FnMut(&[&str]) -> Result<common::Output>,
) -> Result<()> {
    let sectors = command(&["blockdev", "--getsz", &format!("/dev/mapper/{mapper}")])?
        .stdout
        .trim()
        .to_owned();
    require(
        !sectors.is_empty()
            && sectors.bytes().all(|b| b.is_ascii_digit())
            && sectors.parse::<u64>().is_ok_and(|v| v > 0),
        "invalid failed mapper geometry",
    )?;
    command(&["dmsetup", "suspend", "--noflush", "--nolockfs", mapper])?;
    // A reload error returns while the mapping remains suspended. Never resume the stale crypt table.
    command(&[
        "dmsetup",
        "reload",
        mapper,
        "--table",
        &format!("0 {sectors} error"),
    ])?;
    command(&["dmsetup", "resume", mapper])?;
    Ok(())
}
fn readonly_mounts(mounted: &[Value]) -> Result<()> {
    require(
        !mounted.is_empty()
            && mounted.iter().all(|m| {
                m["options"]
                    .as_str()
                    .is_some_and(|s| s.split(',').any(|o| o == "ro"))
            }),
        "Btrfs is still writable; retaining unclean storage witness",
    )
}
pub fn finish() -> Result<()> {
    let session = read_json(SESSION)?;
    let record = load()?;
    require(
        record == *field(&session, "witness")?,
        "storage admission changed during this session",
    )?;
    let mounted = mounts(&record)?;
    readonly_mounts(&mounted)?;
    run(&[
        "btrfs",
        "device",
        "stats",
        "--check",
        text(field(&mounted[0], "target")?)?,
    ])?;
    for role in list(field(&record, "allowed")?)? {
        let role = text(role)?;
        require(
            disk_sequence(text(field(
                field(field(&record, "members")?, role)?,
                "state",
            )?)?)?
                == text(field(field(&session, "diskseq")?, role)?)?,
            "storage member disappeared or returned during this session",
        )?;
    }
    let mut clean = record;
    clean["active"] = json!(false);
    save(&clean)
}
fn owner_selection(record: &Value, role: &str, confirmation: &str, mounted: bool) -> Result<Value> {
    require(
        confirmation == text(field(record, "installation_uuid")?)?,
        "confirm the installation UUID from the reviewed recovery record",
    )?;
    require(
        list(field(record, "allowed")?)?.contains(&json!(role)),
        "a quarantined member cannot authorize itself",
    )?;
    require(
        !mounted,
        "unmount the installed Btrfs filesystem before selecting a survivor",
    )?;
    let mut selected = record.clone();
    selected["allowed"] = json!([role]);
    selected["active"] = json!(false);
    selected["nonce"] = json!(Uuid::new_v4().to_string());
    Ok(selected)
}
pub fn recover(role: &str, confirmation: &str) -> Result<()> {
    let record = load()?;
    let selected = owner_selection(
        &record,
        role,
        confirmation,
        Path::new("/sys/fs/btrfs")
            .join(text(field(&record, "btrfs_uuid")?)?)
            .exists(),
    )?;
    disk_sequence(text(field(
        field(field(&record, "members")?, role)?,
        "state",
    )?)?)?;
    write_existing(&selected)
}
fn readmission(record: &Value, manifest: &Value, role: &str) -> Result<Value> {
    let allowed = list(field(record, "allowed")?)?;
    let updated = bindings(manifest)?;
    require(
        !allowed.contains(&json!(role)) && allowed.len() == 1,
        "replacement requires a quarantined target and one authority",
    )?;
    require(
        field(manifest, "installation_uuid")? == field(record, "installation_uuid")?,
        "replacement installation changed",
    )?;
    let peer = text(&allowed[0])?;
    require(
        updated[peer] == record["members"][peer]
            && ["state", "swap", "esp", "luks"]
                .iter()
                .all(|k| updated[role][*k] != record["members"][role][*k]),
        "replacement must preserve the survivor and erase the quarantined member",
    )?;
    let mut new = record.clone();
    new["members"] = updated;
    new["allowed"] = json!(["a", "b"]);
    new["active"] = json!(true);
    new["nonce"] = json!(Uuid::new_v4().to_string());
    Ok(new)
}
pub fn readmit(manifest: &Value, role: &str) -> Result<()> {
    let _lock = common::lock(RUNTIME)?;
    let record = load()?;
    let updated = bindings(manifest)?;
    let allowed = list(field(&record, "allowed")?)?;
    if allowed.contains(&json!(role)) && updated == *field(&record, "members")? {
        return require(
            read_json(SESSION)?["witness"] == record,
            "completed replacement session changed",
        );
    }
    let new = readmission(&record, manifest, role)?;
    save(&new)?;
    let mut sequences = serde_json::Map::new();
    for r in ["a", "b"] {
        sequences.insert(
            r.into(),
            json!(disk_sequence(text(field(
                field(field(&new, "members")?, r)?,
                "state"
            )?)?)?),
        );
    }
    write_json(SESSION, &json!({"witness":new,"diskseq":sequences}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn witness() -> Value {
        let mut members = serde_json::Map::new();
        for role in ["a", "b"] {
            members.insert(role.into(),json!({"state":Uuid::new_v4().to_string(),"swap":Uuid::new_v4().to_string(),"esp":Uuid::new_v4().to_string(),"luks":Uuid::new_v4().to_string()}));
        }
        json!({"schema":1,"installation_uuid":Uuid::new_v4().to_string(),"btrfs_uuid":Uuid::new_v4().to_string(),"members":members,"allowed":["a","b"],"active":false,"nonce":Uuid::new_v4().to_string(),"wait_seconds":5})
    }
    #[test]
    fn stale_member_cannot_readmit_itself() {
        let clean = witness();
        let mut degraded = choose(&clean, &["b".into()]).unwrap();
        assert_eq!(degraded["allowed"], json!(["b"]));
        degraded["active"] = json!(false);
        let returned = choose(&degraded, &["a".into(), "b".into()]).unwrap();
        assert_eq!(returned["allowed"], json!(["b"]));
        assert!(
            choose(&degraded, &["a".into()])
                .unwrap_err()
                .to_string()
                .contains("quarantined")
        );
    }
    #[test]
    fn every_unclean_session_needs_owner_review() {
        for members in [
            vec!["a".into(), "b".into()],
            vec!["a".into()],
            vec!["b".into()],
        ] {
            let active = choose(&witness(), &members).unwrap();
            for present in [
                vec!["a".into(), "b".into()],
                vec!["a".into()],
                vec!["b".into()],
            ] {
                assert!(
                    choose(&active, &present)
                        .unwrap_err()
                        .to_string()
                        .contains("unclean")
                );
            }
        }
    }
    #[test]
    fn witness_schema_and_authority_fail_closed() {
        let original = witness();
        for (key, bad) in [
            ("schema", json!(true)),
            ("wait_seconds", json!(4)),
            ("wait_seconds", json!(121)),
            ("active", json!(1)),
            ("allowed", json!(["a", "a"])),
            ("allowed", json!(["c"])),
            ("installation_uuid", json!("BAD")),
        ] {
            let mut record = original.clone();
            record[key] = bad;
            assert!(validate(&record).is_err(), "accepted {key}");
        }
        let mut unknown = original.clone();
        unknown["extra"] = json!(1);
        assert!(validate(&unknown).is_err());
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove("nonce");
        assert!(validate(&missing).is_err());
        let mut malformed = original;
        malformed["members"]["a"]["unexpected"] = json!("x");
        assert!(validate(&malformed).is_err());
    }
    #[test]
    fn canonical_device_ids_and_stats_preserve_full_u64() {
        let mut data = [0u8; 1032];
        put64(&mut data, 0, 2);
        put64(&mut data, 8, 5);
        let values = [0, 1, u64::MAX, 2, 3];
        for (i, v) in values.iter().enumerate() {
            put64(&mut data, 24 + i * 8, *v);
        }
        assert_eq!(member_counters(&data, 2).unwrap(), values);
        for (offset, invalid) in [(0, 3), (8, 4), (16, 1)] {
            let mut changed = data;
            put64(&mut changed, offset, invalid);
            assert!(member_counters(&changed, 2).is_err());
        }
        for name in ["", "02", "-1", "+1", "x", "18446744073709551616"] {
            assert!(canonical_device_id(name).is_err());
        }
        assert_eq!(canonical_device_id("0").unwrap(), 0);
        assert_eq!(
            canonical_device_id(&u64::MAX.to_string()).unwrap(),
            u64::MAX
        );
        for count in [0, 4] {
            assert!(validate_inventory_count(count).is_err());
        }
        for count in 1..=3 {
            assert!(validate_inventory_count(count).is_ok());
        }
    }
    #[test]
    fn counter_device_identity_and_path_are_validated_before_stats() {
        let mut device = [0; 4096];
        put64(&mut device, 0, 2);
        assert_eq!(member_device_path(&device, 2).unwrap(), None);
        let path = b"/dev/mapper/particleve-state-a";
        device[3072..3072 + path.len()].copy_from_slice(path);
        assert_eq!(
            member_device_path(&device, 2).unwrap(),
            Some(std::str::from_utf8(path).unwrap())
        );
        assert!(member_device_path(&device, 3).is_err());
        for invalid in [b"relative".as_slice(), &[255]] {
            device[3072..].fill(0);
            device[3072..3072 + invalid.len()].copy_from_slice(invalid);
            assert!(member_device_path(&device, 2).is_err());
        }
        device[3072..].fill(b'a');
        assert!(member_device_path(&device, 2).is_err());
        let mut info = [0; 1024];
        let uuid = Uuid::new_v4();
        info[16..32].copy_from_slice(uuid.as_bytes());
        assert!(validate_member_fsid(&info, &uuid.to_string()).is_ok());
        assert!(validate_member_fsid(&info, &Uuid::new_v4().to_string()).is_err());
    }
    #[test]
    fn owner_recovery_only_reduces_previously_admitted_authority() {
        let mut record = choose(&witness(), &["b".into()]).unwrap();
        let confirmation = record["installation_uuid"].as_str().unwrap();
        assert!(
            owner_selection(&record, "a", confirmation, false)
                .unwrap_err()
                .to_string()
                .contains("cannot authorize itself")
        );
        assert!(owner_selection(&record, "b", confirmation, true).is_err());
        assert!(owner_selection(&record, "b", "wrong", false).is_err());
        let selected = owner_selection(&record, "b", confirmation, false).unwrap();
        assert_eq!(selected["allowed"], json!(["b"]));
        assert_eq!(selected["active"], false);
        record["active"] = json!(false);
        assert_eq!(
            choose(&record, &["a".into(), "b".into()]).unwrap()["allowed"],
            json!(["b"])
        );
    }
    fn manifest(record: &Value) -> Value {
        json!({"installation_uuid":record["installation_uuid"],"devices":(["a","b"].iter().map(|role|json!({"role":role,"state_luks_uuid":record["members"][*role]["luks"],"partitions":(["state","swap","esp"].iter().map(|kind|json!({"role":kind,"uuid":record["members"][*role][*kind]})).collect::<Vec<_>>())})).collect::<Vec<_>>())})
    }
    #[test]
    fn readmission_requires_every_target_identity_to_be_erased_and_survivor_unchanged() {
        let record = choose(&witness(), &["b".into()]).unwrap();
        let original = manifest(&record);
        assert!(
            readmission(&record, &original, "a")
                .unwrap_err()
                .to_string()
                .contains("erase")
        );
        let mut replacement = original.clone();
        replacement["devices"][0]["state_luks_uuid"] = json!(Uuid::new_v4().to_string());
        for part in replacement["devices"][0]["partitions"]
            .as_array_mut()
            .unwrap()
        {
            part["uuid"] = json!(Uuid::new_v4().to_string());
        }
        let admitted = readmission(&record, &replacement, "a").unwrap();
        assert_eq!(admitted["allowed"], json!(["a", "b"]));
        assert_eq!(admitted["members"]["b"], record["members"]["b"]);
        assert_eq!(admitted["active"], true);
        replacement["devices"][1]["state_luks_uuid"] = json!(Uuid::new_v4().to_string());
        assert!(readmission(&record, &replacement, "a").is_err());
    }
    #[test]
    fn shutdown_cannot_clear_active_while_any_subvolume_is_writable() {
        assert!(
            readonly_mounts(&[
                json!({"options":"ro","target":"/"}),
                json!({"options":"rw,subvol=var","target":"/var"})
            ])
            .is_err()
        );
        assert!(
            readonly_mounts(&[
                json!({"options":"ro","target":"/"}),
                json!({"options":"ro,subvol=var","target":"/var"})
            ])
            .is_ok()
        );
        assert!(readonly_mounts(&[]).is_err());
    }
    #[test]
    fn failed_target_reload_leaves_mapping_suspended_and_geometry_is_checked() {
        for failed_reload in [false, true] {
            let mut commands = Vec::new();
            let result = fence_mapper("owned-probe", &mut |args| {
                commands.push(args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
                if failed_reload && args.starts_with(&["dmsetup", "reload"]) {
                    return Err(Error::new("reload failed"));
                }
                Ok(common::Output {
                    code: 0,
                    stdout: "2048".into(),
                    stderr: String::new(),
                })
            });
            assert_eq!(result.is_err(), failed_reload);
            assert!(commands.iter().any(|c| c
                == &[
                    "dmsetup",
                    "suspend",
                    "--noflush",
                    "--nolockfs",
                    "owned-probe"
                ]));
            assert_eq!(
                commands
                    .iter()
                    .any(|c| c == &["dmsetup", "resume", "owned-probe"]),
                !failed_reload
            );
        }
        for geometry in ["0", "-1", "NaN", "18446744073709551616"] {
            let mut calls = 0;
            assert!(
                fence_mapper("owned-probe", &mut |_| {
                    calls += 1;
                    Ok(common::Output {
                        code: 0,
                        stdout: geometry.into(),
                        stderr: String::new(),
                    })
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
    }
}
