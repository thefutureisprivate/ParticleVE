//! Explicitly confirmed installation and erased-member replacement.
use crate::{
    common::{
        self, Error, Result, atomic_write, digest, field, hash_file, list, object, read_json,
        require, run, text, uint, write_json,
    },
    inventory,
    layout::{self, MIB},
    linux::Linux,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    time::Duration,
};
use uuid::Uuid;
pub const TPM_PUBLIC_KEY: &str = "/usr/lib/particleve/trust/pcr-public-key.pem";
fn execute(args: &[String], input: Option<&[u8]>, timeout: Option<u64>) -> Result<common::Output> {
    common::command(
        args,
        input,
        timeout.map(Duration::from_secs),
        8 * 1024 * 1024,
        true,
    )
}
fn timed(args: &[&str], seconds: u64) -> Result<common::Output> {
    execute(
        &args.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
        None,
        Some(seconds),
    )
}
fn pathstr(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::new("non-Unicode installation path"))
}
fn valid_uuid(value: &Value) -> Result<()> {
    let value = text(value)?;
    require(
        Uuid::parse_str(value).is_ok_and(|u| u.to_string() == value),
        "invalid partition UUID",
    )
}
pub fn plan(config: &Value, release: &Value) -> Result<Value> {
    let report = inventory::collect(config)?;
    let failures = list(field(&report, "checks")?)?
        .iter()
        .filter(|c| c["ok"] != true)
        .map(|c| {
            format!(
                "{}: {}",
                c["name"].as_str().unwrap_or("unknown"),
                c["detail"].as_str().unwrap_or("invalid check")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    require(
        field(&report, "ok")? == &json!(true),
        format!("preflight failed: {failures}"),
    )?;
    layout::calculate(config, list(field(&report, "devices")?)?, release)
}
pub fn validate_plan(
    config: &Value,
    release: &Value,
    proposed: &Value,
    confirmation: &str,
) -> Result<()> {
    let mut original = object(proposed)?.clone();
    original.remove("confirmation");
    require(
        confirmation == text(field(proposed, "confirmation")?)?
            && confirmation == digest(&Value::Object(original))?,
        "plan confirmation hash does not match",
    )?;
    require(
        text(field(proposed, "config_sha256")?)? == digest(config)?,
        "configuration differs from reviewed plan",
    )?;
    require(
        text(field(proposed, "release_sha256")?)? == digest(release)?,
        "release differs from reviewed plan",
    )?;
    let disks = list(field(proposed, "devices")?)?;
    let selected = list(field(config, "disks")?)?;
    require(
        disks.len() == selected.len()
            && disks
                .iter()
                .zip(selected)
                .all(|(a, b)| a.get("path") == b.get("path")),
        "disk selection changed",
    )?;
    require(
        proposed.get("storage_admission") == Some(&json!("uefi-witness-v1")),
        "review a fresh installation plan with storage admission",
    )?;
    valid_uuid(field(proposed, "installation_uuid")?)?;
    let current = plan(config, release)?;
    let calculated = list(field(&current, "devices")?)?;
    require(disks.len() == calculated.len(), "disk selection changed")?;
    let mut unique = std::collections::BTreeSet::new();
    for (expected, actual) in disks.iter().zip(calculated) {
        require(
            field(expected, "observed")? == field(actual, "observed")?,
            "disk identity, geometry or capacity changed after planning",
        )?;
        for key in ["path", "role", "serial"] {
            require(
                field(expected, key)? == field(actual, key)?,
                format!("disk {key} changed"),
            )?;
        }
        let partitions = list(field(expected, "partitions")?)?;
        let calculated = list(field(actual, "partitions")?)?;
        require(
            partitions.len() == calculated.len(),
            "partition count differs from calculated layout",
        )?;
        for (partition, calculated) in partitions.iter().zip(calculated) {
            for key in ["number", "role", "offset", "size", "type", "label"] {
                require(
                    field(partition, key)? == field(calculated, key)?,
                    format!("partition {key} differs from calculated layout"),
                )?;
            }
            valid_uuid(field(partition, "uuid")?)?;
            let uuid = text(field(partition, "uuid")?)?;
            if text(field(partition, "role")?)?.starts_with("a_") {
                require(
                    field(partition, "uuid")? == field(calculated, "uuid")?,
                    "verified OS partition UUID changed",
                )?;
            } else {
                require(
                    unique.insert(uuid.to_owned()),
                    "ESP/writable partition UUID must be unique",
                )?;
            }
        }
        valid_uuid(field(expected, "disk_uuid")?)?;
        require(
            unique.insert(text(field(expected, "disk_uuid")?)?.to_owned()),
            "disk UUID must be unique",
        )?;
        refuse_existing_labels(&inventory::walk(&inventory::block_tree(Some(text(
            field(expected, "path")?,
        )?))?)?)?;
    }
    Ok(())
}
fn refuse_existing_labels(nodes: &[Value]) -> Result<()> {
    require(
        !nodes.iter().any(|n| {
            n["partlabel"]
                .as_str()
                .is_some_and(|label| label.starts_with("ParticleVE") || label.starts_with("PVE_"))
        }),
        "fresh install refuses existing/partial ParticleVE storage; use owner recovery or replacement",
    )
}
pub fn partition(device: &Value) -> Result<()> {
    execute(
        &[
            "sfdisk",
            "--lock=yes",
            "--wipe=always",
            "--wipe-partitions=always",
            text(field(device, "path")?)?,
        ]
        .map(str::to_owned),
        Some(layout::sfdisk_script(device)?.as_bytes()),
        Some(120),
    )?;
    run(&["udevadm", "settle"])?;
    Ok(())
}
pub fn member(device: &Value, role: &str) -> Result<String> {
    let part = list(field(device, "partitions")?)?
        .iter()
        .find(|p| p["role"] == role)
        .ok_or_else(|| Error::new("missing selected partition role"))?;
    inventory::partition_path(text(field(device, "path")?)?, uint(field(part, "number")?)?)
}
pub fn write_os(device: &Value, release: &Value, directory: &Path) -> Result<()> {
    for kind in ["verity_sig", "verity", "usr"] {
        let item = field(field(release, "artifacts")?, kind)?;
        let target = member(device, &format!("a_{kind}"))?;
        timed(
            &[
                "dd",
                &format!(
                    "if={}",
                    directory.join(text(field(item, "file")?)?).display()
                ),
                &format!("of={target}"),
                "bs=4M",
                "conv=fsync,notrunc",
                "status=none",
            ],
            3600,
        )?;
        require(
            hash_file(&target, Some(uint(field(item, "size")?)?))? == text(field(item, "sha256")?)?,
            format!("installed {kind} failed readback"),
        )?;
    }
    Ok(())
}
pub fn luks_uuid(name: &str) -> Result<String> {
    Ok(
        run(&["cryptsetup", "luksUUID", &format!("/dev/md/{name}")])?
            .stdout
            .trim()
            .to_owned(),
    )
}
pub fn validate_keyfile(path: &Path) -> Result<()> {
    let info = path.metadata()?;
    require(
        info.is_file()
            && !fs::symlink_metadata(path)?.file_type().is_symlink()
            && info.uid() == 0
            && info.mode() & 0o7777 == 0o600,
        "recovery key must be a root-owned regular file with mode 0600",
    )?;
    require(
        fs::canonicalize(path)?.starts_with("/run"),
        "keep the independent recovery key in /run, outside installed storage",
    )?;
    require(
        (16..=4096).contains(&info.len()),
        "recovery key must be 16..4096 bytes",
    )?;
    require(
        common::read_bounded(path, 4096)?
            .iter()
            .all(|b| (32..=126).contains(b)),
        "recovery passphrase must be printable ASCII without a trailing newline for console unlock",
    )
}
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let a = chunk[0] as usize;
        let b = chunk.get(1).copied().unwrap_or(0) as usize;
        let c = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(ALPHABET[a >> 2] as char);
        out.push(ALPHABET[((a & 3) << 4) | (b >> 4)] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((b & 15) << 2) | (c >> 6)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[c & 63] as char
        } else {
            '='
        });
    }
    out
}
fn tpm_enrollment_arguments(source: &str, keyfile: &Path) -> Vec<String> {
    [
        "systemd-cryptenroll",
        &format!("--unlock-key-file={}", keyfile.display()),
        "--tpm2-device=auto",
        "--tpm2-pcrs=7",
        "--tpm2-pcrlock=",
        &format!("--tpm2-public-key={TPM_PUBLIC_KEY}"),
        "--tpm2-public-key-pcrs=11",
        source,
    ]
    .map(str::to_owned)
    .to_vec()
}
pub fn enroll_source(source: &str, keyfile: &Path) -> Result<()> {
    inventory::measured_boot(true)?;
    execute(&tpm_enrollment_arguments(source, keyfile), None, Some(300))?;
    verify_tpm_policy(source)
}
pub fn verify_tpm_policy(source: &str) -> Result<()> {
    let public = base64(&common::read_bounded(TPM_PUBLIC_KEY, 65536)?);
    let dump = common::parse_json(
        run(&["cryptsetup", "luksDump", "--dump-json-metadata", source])?
            .stdout
            .as_bytes(),
    )?;
    validate_tpm_tokens(field(&dump, "tokens")?, &public)
}
fn validate_tpm_tokens(tokens: &Value, public: &str) -> Result<()> {
    require(
        object(tokens)?.values().any(|token| {
            token["type"] == "systemd-tpm2"
                && token["tpm2-pcrs"] == json!([7])
                && token["tpm2-pcr-bank"] == "sha256"
                && token["tpm2_pubkey_pcrs"] == json!([11])
                && token["tpm2_pubkey"] == public
                && token
                    .get("keyslots")
                    .and_then(Value::as_array)
                    .is_some_and(|s| !s.is_empty())
                && token.get("tpm2_pcrlock").is_none_or(|v| v == false)
                && token.get("tpm2-pin").is_none_or(|v| v == false)
        }),
        "TPM enrollment does not match PCR7 plus signed-PCR11 without pcrlock or PIN",
    )
}
pub fn format_encrypted(source: &str, name: &str, keyfile: &Path, enroll: bool) -> Result<String> {
    timed(
        &[
            "cryptsetup",
            "luksFormat",
            "--type=luks2",
            "--batch-mode",
            "--label",
            name,
            "--key-file",
            pathstr(keyfile)?,
            source,
        ],
        300,
    )?;
    timed(
        &[
            "cryptsetup",
            "open",
            "--key-file",
            pathstr(keyfile)?,
            source,
            name,
        ],
        300,
    )?;
    if enroll {
        enroll_source(source, keyfile)?;
    }
    Ok(run(&["cryptsetup", "luksUUID", source])?
        .stdout
        .trim()
        .to_owned())
}
pub fn block_uuid(path: &str, key: Option<&str>) -> Result<String> {
    Ok(
        run(&["blkid", "-s", key.unwrap_or("UUID"), "-o", "value", path])?
            .stdout
            .trim()
            .to_owned(),
    )
}
pub fn enrollment_uuids(manifest: &Value) -> Result<Vec<String>> {
    let mut result = list(field(manifest, "devices")?)?
        .iter()
        .map(|d| text(field(d, "state_luks_uuid")?).map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    result.push(text(field(field(manifest, "swap")?, "luks_uuid")?)?.into());
    result.sort();
    Ok(result)
}
pub fn crypttab(manifest: &Value) -> Result<String> {
    let mut textout = String::new();
    for d in list(field(manifest, "devices")?)? {
        textout.push_str(&format!("particleve-state-{} UUID={} - noauto,tpm2-device=auto,x-initrd.attach,nofail,x-systemd.device-timeout=30s\n",text(field(d,"role")?)?,text(field(d,"state_luks_uuid")?)?));
    }
    textout.push_str(&format!(
        "particleve-swap UUID={} - tpm2-device=auto\n",
        text(field(field(manifest, "swap")?, "luks_uuid")?)?
    ));
    Ok(textout)
}
pub fn replace_btrfs(devid: u64, mapper: &str) -> Result<()> {
    execute(
        &[
            "btrfs",
            "replace",
            "start",
            "-B",
            &devid.to_string(),
            mapper,
            "/",
        ]
        .map(str::to_owned),
        None,
        None,
    )?;
    Ok(())
}
pub fn enroll_tpm(backend: &Linux, keyfile: &Path, state: &Value) -> Result<Value> {
    validate_keyfile(keyfile)?;
    require(
        field(state, "pending")?.is_null(),
        "finish or cancel the pending OS transaction before TPM enrollment",
    )?;
    require(
        !backend.directory.join("commissioned.json").exists()
            || !field(state, "maintenance")?.is_null(),
        "enter persistent maintenance before changing a commissioned host's TPM policy",
    )?;
    require(
        inventory::secure_boot(),
        "TPM enrollment requires the normal Secure Boot chain",
    )?;
    backend.check_storage(true)?;
    backend.check_firmware_clear()?;
    let version = backend.current_version()?;
    let release = backend.release(Some(&version))?;
    for role in ["a", "b"] {
        require(
            backend.verify_disk(role, &release, true)?,
            "verify both current boot paths before enrollment",
        )?;
    }
    for device in list(field(&backend.manifest, "devices")?)? {
        enroll_source(&member(device, "state")?, keyfile)?;
    }
    enroll_source("/dev/md/particleve-swap", keyfile)?;
    write_json(
        backend.directory.join("tpm-enrollment.json"),
        &json!({"schema":1,"policy":field(&backend.config,"tpm_policy")?,"luks_uuids":enrollment_uuids(&backend.manifest)?,"image_version":version,"boot_id":backend.boot_id()?,"recorded_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros,false)}),
    )?;
    Ok(
        json!({"action":"tpm-enrolled","policy":field(&backend.config,"tpm_policy")?,"next":"test unattended unlock from both boot disks before commissioning"}),
    )
}
pub fn create_writable(proposed: &mut Value, keyfile: &Path) -> Result<Value> {
    let devices = proposed
        .get_mut("devices")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::new("invalid installation devices"))?;
    for device in devices.iter_mut() {
        let role = text(field(device, "role")?)?.to_owned();
        device["state_luks_uuid"] = json!(format_encrypted(
            &member(device, "state")?,
            &format!("particleve-state-{role}"),
            keyfile,
            false
        )?);
    }
    let state_paths = devices
        .iter()
        .map(|d| {
            Ok(format!(
                "/dev/mapper/particleve-state-{}",
                text(field(d, "role")?)?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut args = [
        "mkfs.btrfs",
        "--data=raid1",
        "--metadata=raid1",
        "--label=ParticleVE-root",
    ]
    .map(str::to_owned)
    .to_vec();
    args.extend(state_paths.clone());
    execute(&args, None, Some(600))?;
    require(
        state_paths.len() == 2,
        "new Btrfs mirror requires exactly two state members",
    )?;
    let observed = crate::storage::members(
        &run(&["btrfs", "filesystem", "show", "--raw", &state_paths[0]])?.stdout,
    )?;
    require(
        observed.len() == 2,
        "new Btrfs mirror does not report two devices",
    )?;
    for device in devices.iter_mut() {
        let mapper = format!(
            "/dev/mapper/particleve-state-{}",
            text(field(device, "role")?)?
        );
        let resolved = fs::canonicalize(&mapper)?;
        let mut matching = Vec::new();
        for item in &observed {
            if fs::canonicalize(text(field(item, "path")?)?)? == resolved {
                matching.push(item);
            }
        }
        require(matching.len() == 1, "cannot identify new Btrfs device")?;
        device["btrfs_devid"] = field(matching[0], "devid")?.clone();
        device["btrfs_device_uuid"] = json!(block_uuid(&mapper, Some("UUID_SUB"))?);
    }
    let mut args = [
        "mdadm",
        "--create",
        "/dev/md/particleve-swap",
        "--metadata=1.2",
        "--level=1",
        "--raid-devices=2",
        "--bitmap=internal",
        "--homehost=any",
        "--name=particleve-swap",
    ]
    .map(str::to_owned)
    .to_vec();
    for d in devices.iter() {
        args.push(member(d, "swap")?);
    }
    execute(&args, None, Some(300))?;
    let swap_luks = format_encrypted("/dev/md/particleve-swap", "particleve-swap", keyfile, false)?;
    run(&[
        "mkswap",
        "-L",
        "ParticleVE-swap",
        "/dev/mapper/particleve-swap",
    ])?;
    Ok(
        json!({"btrfs":{"uuid":block_uuid(&state_paths[0],None)?,"data":"raid1","metadata":"raid1","factory_reset":false,"var_subvolume":"var"},"swap":{"md_uuid":crate::storage::array_uuid("particleve-swap")?,"luks_uuid":swap_luks,"uuid":block_uuid("/dev/mapper/particleve-swap",None)?}}),
    )
}
fn with_mount<T>(
    args: &[String],
    target: &Path,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    execute(args, None, Some(120))?;
    let result = operation();
    let cleanup = run(&["umount", pathstr(target)?]);
    match (result, cleanup) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(mut error)) => {
            error.message = format!(
                "failed to unmount {}: {}; retain the mountpoint for owner recovery",
                target.display(),
                error.message
            );
            Err(error)
        }
        (Err(mut error), Err(cleanup)) => {
            error.message = format!(
                "{}; failed to unmount {}: {}; retain the mountpoint for owner recovery",
                error.message,
                target.display(),
                cleanup
            );
            Err(error)
        }
    }
}
struct MountDirectory {
    path: std::path::PathBuf,
}
impl MountDirectory {
    fn new(prefix: &str) -> Result<Self> {
        Ok(Self {
            path: tempfile::Builder::new()
                .prefix(prefix)
                .tempdir_in("/run")?
                .keep(),
        })
    }
    fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for MountDirectory {
    fn drop(&mut self) {
        // A failed unmount must never trigger recursive traversal into user storage.
        // rmdir is safe for an empty, detached mountpoint and fails on a live mount.
        let _ = fs::remove_dir(&self.path);
    }
}
fn mkdir(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let dest = target.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}
pub fn install(
    config: &Value,
    release_directory: &Path,
    proposed: &mut Value,
    confirmation: &str,
    keyfile: &Path,
    keyring: &Path,
    certificate: &Path,
) -> Result<Value> {
    // SAFETY: geteuid has no pointer arguments or ownership requirements.
    require(
        unsafe { libc::geteuid() } == 0,
        "installation requires root in the owner recovery environment",
    )?;
    require(
        !Path::new(crate::admission::VARIABLE).exists(),
        "existing firmware storage witness requires owner recovery before reinstall",
    )?;
    validate_keyfile(keyfile)?;
    let release = crate::release::verify_directory(release_directory, keyring, certificate, true)?;
    validate_plan(config, &release, proposed, confirmation)?;
    require(
        !["a", "b"].iter().any(|r| {
            Path::new("/dev/mapper")
                .join(format!("particleve-state-{r}"))
                .exists()
        }),
        "state storage is already active",
    )?;
    {
        let _lock = common::lock("/run/particleve-installer")?;
        write_json("/run/particleve-installer/plan.json", proposed)?;
        for device in list(field(proposed, "devices")?)? {
            require(
                inventory::observe_disk(device, true)? == *field(device, "observed")?,
                "disk changed before write",
            )?;
            partition(device)?;
            run(&[
                "mkfs.vfat",
                "-F",
                "32",
                "-n",
                "PARTICLEVE",
                &member(device, "esp")?,
            ])?;
            write_os(device, &release, release_directory)?;
        }
        let storage = create_writable(proposed, keyfile)?;
        let rootdir = MountDirectory::new("particleve-root-")?;
        let root = rootdir.path();
        let mut recorded = object(proposed)?.clone();
        recorded.remove("confirmation");
        recorded.extend(object(&storage)?.clone());
        recorded.insert(
            "storage_wait_seconds".into(),
            field(field(config, "storage")?, "degraded_wait_seconds")?.clone(),
        );
        let record = Value::Object(recorded);
        with_mount(
            &[
                "mount",
                "-t",
                "btrfs",
                "-o",
                "compress=zstd:1",
                "/dev/mapper/particleve-state-a",
                pathstr(root)?,
            ]
            .map(str::to_owned),
            root,
            || {
                run(&["btrfs", "subvolume", "create", pathstr(&root.join("var"))?])?;
                let usrdir = MountDirectory::new("particleve-usr-")?;
                let usr = usrdir.path();
                let raw = release_directory.join(text(field(
                    field(field(&release, "artifacts")?, "usr")?,
                    "file",
                )?)?);
                let verity = release_directory.join(text(field(
                    field(field(&release, "artifacts")?, "verity")?,
                    "file",
                )?)?);
                timed(
                    &[
                        "veritysetup",
                        "verify",
                        pathstr(&raw)?,
                        pathstr(&verity)?,
                        text(field(&release, "usr_root_hash")?)?,
                    ],
                    3600,
                )?;
                with_mount(
                    &[
                        "mount",
                        "-t",
                        "erofs",
                        "-o",
                        "ro,loop",
                        pathstr(&raw)?,
                        pathstr(usr)?,
                    ]
                    .map(str::to_owned),
                    usr,
                    || {
                        let factory = usr.join("share/factory/etc");
                        mkdir(&root.join("etc"), 0o755)?;
                        for name in [
                            "usr", "root", "run", "proc", "sys", "dev", "efi", "tmp", "home",
                        ] {
                            mkdir(&root.join(name), 0o755)?;
                        }
                        for name in ["bin", "sbin", "lib", "lib64"] {
                            symlink(format!("usr/{name}"), root.join(name))?;
                        }
                        fs::set_permissions(root.join("root"), fs::Permissions::from_mode(0o700))?;
                        fs::set_permissions(root.join("tmp"), fs::Permissions::from_mode(0o1777))?;
                        mkdir(&root.join("var/lib"), 0o755)?;
                        run(&[
                            "btrfs",
                            "subvolume",
                            "create",
                            pathstr(&root.join("var/lib/machines"))?,
                        ])?;
                        fs::set_permissions(
                            root.join("var/lib/machines"),
                            fs::Permissions::from_mode(0o700),
                        )?;
                        with_mount(
                            &[
                                "mount",
                                "--bind",
                                pathstr(usr)?,
                                pathstr(&root.join("usr"))?,
                            ]
                            .map(str::to_owned),
                            &root.join("usr"),
                            || {
                                let rootarg = format!("--root={}", root.display());
                                run(&["systemd-sysusers", &rootarg])?;
                                timed(&["systemd-tmpfiles", &rootarg, "--create"], 300)?;
                                run(&[
                                    "systemd-firstboot",
                                    &rootarg,
                                    "--setup-machine-id",
                                    "--root-password-hashed=!",
                                    "--root-shell=/bin/bash",
                                    "--force",
                                ])?;
                                run(&["systemctl", &rootarg, "preset-all"])?;
                                run(&["systemctl", &rootarg, "set-default", "multi-user.target"])?;
                                Ok(())
                            },
                        )?;
                        crate::network::write(config, root)?;
                        let fsid = text(field(field(&storage, "btrfs")?, "uuid")?)?;
                        atomic_write(root.join("etc/fstab"),format!("UUID={fsid} / btrfs defaults,compress=zstd:1 0 0\nUUID={fsid} /var btrfs defaults,subvol=var,compress=zstd:1 0 0\n/dev/mapper/particleve-swap none swap defaults,x-systemd.device-timeout=45s 0 0\n").as_bytes(),0o644)?;
                        atomic_write(
                            root.join("etc/crypttab"),
                            crypttab(&record)?.as_bytes(),
                            0o600,
                        )?;
                        atomic_write(root.join("etc/mdadm.conf"),format!("HOMEHOST <ignore>\nAUTO -all\nARRAY /dev/md/particleve-swap UUID={}\n",text(field(field(&storage,"swap")?,"md_uuid")?)?).as_bytes(),0o644)?;
                        let keys = list(field(config, "admin_ssh_keys")?)?
                            .iter()
                            .map(|v| text(v).map(str::to_owned))
                            .collect::<Result<Vec<_>>>()?;
                        atomic_write(
                            root.join("root/.ssh/authorized_keys"),
                            (keys.join("\n") + "\n").as_bytes(),
                            0o600,
                        )?;
                        let directory = root.join("var/lib/particleve");
                        write_json(directory.join("installation.json"), &record)?;
                        write_json(root.join("etc/particleve/host.json"), config)?;
                        let cache = directory.join("releases");
                        fs::create_dir_all(&cache)?;
                        copy_tree(
                            release_directory,
                            &cache.join(text(field(&release, "version")?)?),
                        )?;
                        let contexts =
                            factory.join("selinux/targeted/contexts/files/file_contexts");
                        require(
                            contexts.exists(),
                            "SELinux file contexts missing from image",
                        )?;
                        let mut policies = Vec::new();
                        for entry in fs::read_dir(factory.join("selinux/targeted/policy"))? {
                            let entry = entry?;
                            let name = entry.file_name();
                            let name = name.to_string_lossy();
                            if name.strip_prefix("policy.").is_some_and(|n| {
                                !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                            }) {
                                policies.push(entry.path());
                            }
                        }
                        require(
                            policies.len() == 1
                                && policies[0].is_file()
                                && !policies[0].is_symlink(),
                            "image must supply one regular compiled SELinux policy",
                        )?;
                        timed(
                            &[
                                "setfiles",
                                "-c",
                                pathstr(&policies[0])?,
                                "-r",
                                pathstr(root)?,
                                pathstr(&contexts)?,
                                pathstr(root)?,
                            ],
                            600,
                        )?;
                        Ok(())
                    },
                )?;
                let backend = Linux::new(config.clone(), &root.join("var/lib/particleve"), false)?;
                crate::bootloaders::Loaders::new(&backend).seed(&release)?;
                for device in list(field(proposed, "devices")?)? {
                    let role = text(field(device, "role")?)?;
                    backend.expose_boot(role, &release)?;
                    backend.with_esp(role, |esp| {
                        backend.default(esp, Some(text(field(&release, "version")?)?))
                    })?;
                    run(&[
                        "efibootmgr",
                        "--create",
                        "--disk",
                        text(field(device, "path")?)?,
                        "--part",
                        "1",
                        "--label",
                        &format!("ParticleVE {role}"),
                        "--loader",
                        "\\EFI\\systemd\\systemd-bootx64.efi",
                    ])?;
                }
                Ok(())
            },
        )?;
        crate::admission::initialize(&record)?;
    }
    Ok(
        json!({"action":"installed","version":field(&release,"version")?,"automatic_updates":false,"tpm_enrollment":"required from the first verified normal boot","next":"validate independent/degraded boots and owner recovery, then commission"}),
    )
}
fn require_absent_mapper(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(_) => {
            return Err(Error::new(
                "old state mapper is still present; reboot degraded before planning replacement",
            ));
        }
    }
    Ok(())
}
pub fn replace(
    config: &Value,
    backend: &mut Linux,
    role: &str,
    replacement: &Value,
    confirmation: Option<&str>,
    keyfile: Option<&Path>,
    rebuild_quarantined: bool,
) -> Result<Value> {
    require(matches!(role, "a" | "b"), "replacement role must be a or b")?;
    let state = read_json(backend.directory.join("state.json"))?;
    require(
        !field(&state, "maintenance")?.is_null() && field(&state, "pending")?.is_null(),
        "maintenance and no pending OS transaction are required",
    )?;
    require(
        !backend.directory.join("replacement.json").exists(),
        "reconcile the interrupted replacement first",
    )?;
    let old = backend.disk(role)?;
    let peer = backend.disk(if role == "a" { "b" } else { "a" })?;
    let mapper = format!("particleve-state-{role}");
    require_absent_mapper(&Path::new("/dev/mapper").join(&mapper))?;
    let witness = crate::admission::verify_manifest(&backend.manifest, None)?;
    let allowed = list(field(&witness, "allowed")?)?;
    require(
        !allowed.contains(&json!(role)) && allowed.len() == 1,
        "boot from the authoritative survivor with the target quarantined before replacement",
    )?;
    if rebuild_quarantined {
        require(
            field(replacement, "path")? == field(&old, "path")?
                && field(replacement, "serial")? == field(&old, "serial")?,
            "rebuild must select the exact quarantined disk",
        )?;
    } else {
        require(
            !Path::new(text(field(&old, "path")?)?).exists(),
            "disconnect the failed disk before replacement",
        )?;
    }
    let observed = inventory::observe_disk(replacement, true)?;
    require(
        field(&observed, "identity")?
            != field(&inventory::observe_disk(&peer, false)?, "identity")?,
        "replacement aliases survivor",
    )?;
    require(
        field(&observed, "logical_sector")? == field(field(&old, "observed")?, "logical_sector")?,
        "replacement sector geometry differs",
    )?;
    let last = list(field(&old, "partitions")?)?
        .last()
        .ok_or_else(|| Error::new("missing replacement geometry"))?;
    let needed = uint(field(last, "offset")?)?
        .checked_add(uint(field(last, "size")?)?)
        .and_then(|s| s.checked_add(MIB))
        .ok_or_else(|| Error::new("replacement geometry overflow"))?;
    require(
        uint(field(&observed, "size")?)? >= needed,
        "replacement is too small",
    )?;
    let version = backend.current_version()?;
    let release = backend.release(Some(&version))?;
    let mut new_config = config.clone();
    new_config["disks"] = json!(
        list(field(config, "disks")?)?
            .iter()
            .map(|d| if d["role"] == role {
                replacement.clone()
            } else {
                d.clone()
            })
            .collect::<Vec<_>>()
    );
    crate::config::validate(new_config.clone(), false)?;
    let basis = json!({"role":role,"replacement":replacement,"erase_quarantined_member":rebuild_quarantined,"observed":observed,"release_sha256":digest(&release)?,"installation_sha256":digest(&backend.manifest)?});
    let seed = digest(&basis)?;
    let mut device = old.clone();
    object(&device)?;
    for (k, v) in object(replacement)? {
        device[k] = v.clone();
    }
    device["observed"] = observed;
    device["disk_uuid"] =
        json!(Uuid::new_v5(&Uuid::NAMESPACE_URL, format!("{seed}:disk").as_bytes()).to_string());
    for part in device["partitions"]
        .as_array_mut()
        .ok_or_else(|| Error::new("invalid replacement partitions"))?
    {
        let part_role = text(field(part, "role")?)?.to_owned();
        part["uuid"] = json!(
            Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("{seed}:{part_role}").as_bytes()
            )
            .to_string()
        );
        if let Some(kind) = part_role.strip_prefix("a_") {
            let item = field(field(&release, "artifacts")?, kind)?;
            part["uuid"] = field(item, "partition_uuid")?.clone();
            part["label"] = json!(layout::os_label(text(field(&release, "version")?)?)?);
            require(
                uint(field(part, "size")?)? >= uint(field(item, "size")?)?,
                "current OS does not fit",
            )?;
        } else if part_role.starts_with("b_") {
            part["label"] = json!("_empty");
        }
    }
    let mut proposed = basis;
    proposed["device"] = device.clone();
    let Some(confirmation) = confirmation else {
        let sha = digest(&proposed)?;
        proposed["confirmation"] = json!(sha);
        return Ok(proposed);
    };
    require(
        confirmation == digest(&proposed)?,
        "replacement plan changed",
    )?;
    // SAFETY: geteuid has no pointer arguments or ownership requirements.
    require(
        unsafe { libc::geteuid() } == 0 && keyfile.is_some(),
        "root and an independent recovery key file are required",
    )?;
    let keyfile = keyfile.ok_or_else(|| Error::new("independent recovery key file is required"))?;
    validate_keyfile(keyfile)?;
    write_json(backend.directory.join("replacement.json"), &proposed)?;
    let commissioned = backend.directory.join("commissioned.json");
    match fs::remove_file(commissioned) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
        Ok(()) => {}
    }
    backend.freeze_vms()?;
    backend.stop_vms()?;
    backend.assert_no_vms()?;
    partition(&device)?;
    run(&["mkfs.vfat", "-F", "32", &member(&device, "esp")?])?;
    write_os(
        &device,
        &release,
        &backend.cache.join(text(field(&release, "version")?)?),
    )?;
    device["state_luks_uuid"] = json!(format_encrypted(
        &member(&device, "state")?,
        &mapper,
        keyfile,
        true
    )?);
    device["btrfs_device_uuid"] = Value::Null;
    let mut record = backend.manifest.clone();
    record["devices"] = json!(
        list(field(&record, "devices")?)?
            .iter()
            .map(|d| if d["role"] == role {
                device.clone()
            } else {
                d.clone()
            })
            .collect::<Vec<_>>()
    );
    record["config_sha256"] = json!(digest(&new_config)?);
    write_json(backend.directory.join("installation.json"), &record)?;
    write_json("/etc/particleve/host.json", &new_config)?;
    atomic_write("/etc/crypttab", crypttab(&record)?.as_bytes(), 0o600)?;
    backend.manifest = record;
    backend.config = new_config;
    replace_btrfs(
        uint(field(&old, "btrfs_devid")?)?,
        &format!("/dev/mapper/{mapper}"),
    )?;
    run(&[
        "mdadm",
        "--manage",
        "/dev/md/particleve-swap",
        "--add",
        &member(&device, "swap")?,
    ])?;
    complete_replacement_boot(&NativeReplacementBoot {
        backend,
        role,
        release: &release,
        device: &device,
    })?;
    Ok(
        json!({"action":"replacement-started","next":"wait for Btrfs replace and swap sync; restore RAID1 profiles, then finalize"}),
    )
}
/// Boot provisioning must finish before replacement readmission discards its journal.
pub trait ReplacementBoot {
    fn verify_os(&self) -> Result<bool>;
    fn copy_os(&self) -> Result<()>;
    fn expose_uki(&self) -> Result<()>;
    fn restore_loaders(&self) -> Result<()>;
    fn set_default(&self) -> Result<()>;
    fn verify_boot(&self) -> Result<()>;
    fn ensure_firmware_entry(&self) -> Result<()>;
}
pub fn complete_replacement_boot(boot: &impl ReplacementBoot) -> Result<()> {
    if !boot.verify_os()? {
        boot.copy_os()?;
        require(boot.verify_os()?, "replacement OS failed readback")?;
    }
    boot.expose_uki()?;
    boot.restore_loaders()?;
    boot.set_default()?;
    boot.verify_boot()?;
    boot.ensure_firmware_entry()
}
struct NativeReplacementBoot<'a> {
    backend: &'a Linux,
    role: &'a str,
    release: &'a Value,
    device: &'a Value,
}
impl ReplacementBoot for NativeReplacementBoot<'_> {
    fn verify_os(&self) -> Result<bool> {
        self.backend.verify_disk(self.role, self.release, false)
    }
    fn copy_os(&self) -> Result<()> {
        write_os(
            self.device,
            self.release,
            &self
                .backend
                .cache
                .join(text(field(self.release, "version")?)?),
        )
    }
    fn expose_uki(&self) -> Result<()> {
        self.backend.with_esp(self.role, |esp| {
            let version = text(field(self.release, "version")?)?;
            let entries = Linux::boot_entries(esp, version)?;
            require(entries.len() <= 1, "ambiguous replacement UKIs")?;
            if let Some((path, count)) = entries.first() {
                require(
                    count.is_none_or(|n| n > 0),
                    "replacement boot attempts exhausted; owner review required",
                )?;
                let item = &self.release["artifacts"]["uki"];
                if hash_file(path, None)? != text(field(item, "sha256")?)? {
                    // Only the transaction-owned replacement ESP is repaired;
                    // preserve the existing entry name and remaining boot count.
                    atomic_write(
                        path,
                        &fs::read(
                            self.backend
                                .cache
                                .join(version)
                                .join(text(field(item, "file")?)?),
                        )?,
                        0o600,
                    )?;
                }
            }
            Ok(())
        })?;
        self.backend.expose_boot(self.role, self.release)
    }
    fn restore_loaders(&self) -> Result<()> {
        crate::bootloaders::Loaders::new(self.backend).restore(self.role)
    }
    fn set_default(&self) -> Result<()> {
        self.backend.with_esp(self.role, |esp| {
            self.backend
                .default(esp, Some(text(field(self.release, "version")?)?))
        })
    }
    fn verify_boot(&self) -> Result<()> {
        require(
            self.backend.verify_disk(self.role, self.release, true)?,
            "replacement boot artifacts failed readback",
        )?;
        self.backend.with_esp(self.role, |esp| {
            self.backend
                .verify_default(esp, text(field(self.release, "version")?)?)
        })
    }
    fn ensure_firmware_entry(&self) -> Result<()> {
        crate::bootloaders::Loaders::new(self.backend).ensure_fixed_entry(self.role)
    }
}
pub fn replacement_version(record: &Value, device: &Value) -> Result<String> {
    require(
        matches!(text(field(record, "role")?)?, "a" | "b"),
        "invalid replacement role",
    )?;
    let proposed = field(record, "device")?;
    for name in ["role", "path", "serial", "disk_uuid", "partitions"] {
        require(
            field(proposed, name)? == field(device, name)?,
            "replacement identity differs from its journal",
        )?;
    }
    let partitions = list(field(proposed, "partitions")?)?;
    let system = partitions
        .iter()
        .filter(|p| p["role"] == "a_usr")
        .collect::<Vec<_>>();
    require(system.len() == 1, "replacement journal lacks one OS slot")?;
    let version = text(field(system[0], "label")?)?
        .strip_prefix("PVE_")
        .ok_or_else(|| Error::new("replacement journal has no release identity"))?;
    crate::config::version_key(version)?;
    Ok(version.into())
}
pub fn finalize_replacement(backend: &mut Linux) -> Result<Value> {
    let record = read_json(backend.directory.join("replacement.json"))?;
    let report = crate::storage::status(&backend.manifest, &backend.config, false)?;
    require(
        list(field(&report, "devices")?)?.len() == 2
            && uint(field(&report, "swap_degraded")?)? == 0
            && report["swap_sync_action"] == "idle",
        "replacement or swap resynchronization is incomplete",
    )?;
    require(
        list(field(&report, "allocation")?)?
            .iter()
            .all(|p| p["profile"] == "raid1"),
        "restore all allocated data/metadata profiles to RAID1 before finalization",
    )?;
    require(
        run(&["btrfs", "replace", "status", "-1", "/"])?
            .stdout
            .to_lowercase()
            .contains("finished"),
        "Btrfs replacement has not completed",
    )?;
    let checked = common::command(
        &["btrfs", "device", "stats", "--check", "/"].map(str::to_owned),
        None,
        Some(Duration::from_secs(120)),
        8 * 1024 * 1024,
        false,
    )?;
    require(checked.code == 0, "replacement has device errors")?;
    let role = text(field(&record, "role")?)?;
    let device = backend.disk(role)?;
    let version = replacement_version(&record, &device)?;
    require(
        backend.current_esp_role()? != role,
        "boot the admitted survivor before repairing replacement boot artifacts",
    )?;
    backend.check_usr_boot_disk()?;
    let release = crate::release::verify_directory(
        &backend.cache.join(&version),
        &backend.keyring,
        &backend.certificate,
        true,
    )?;
    require(
        release["version"] == version && digest(&release)? == record["release_sha256"],
        "replacement release differs from its transaction",
    )?;
    complete_replacement_boot(&NativeReplacementBoot {
        backend,
        role,
        release: &release,
        device: &device,
    })?;
    let uuid = block_uuid(
        &format!("/dev/mapper/particleve-state-{role}"),
        Some("UUID_SUB"),
    )?;
    let devices = backend.manifest["devices"]
        .as_array_mut()
        .ok_or_else(|| Error::new("invalid installed device inventory"))?;
    let device = devices
        .iter_mut()
        .find(|d| d["role"] == role)
        .ok_or_else(|| Error::new("missing replacement device"))?;
    device["btrfs_device_uuid"] = json!(uuid);
    write_json(
        backend.directory.join("installation.json"),
        &backend.manifest,
    )?;
    crate::admission::readmit(&backend.manifest, role)?;
    fs::remove_file(backend.directory.join("replacement.json"))?;
    fs::File::open(&backend.directory)?.sync_all()?;
    let restoration = backend.restore_vms()?;
    Ok(
        json!({"action":"replacement-finalized","vm_restoration":restoration,"next":"validate both boot paths and recommission"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[derive(Default)]
    struct BootFixture {
        os: Cell<bool>,
        fail: Cell<Option<&'static str>>,
        calls: RefCell<Vec<&'static str>>,
    }
    impl BootFixture {
        fn step(&self, name: &'static str) -> Result<()> {
            self.calls.borrow_mut().push(name);
            require(self.fail.get() != Some(name), format!("interrupted {name}"))
        }
    }
    impl ReplacementBoot for BootFixture {
        fn verify_os(&self) -> Result<bool> {
            self.step("verify-os")?;
            Ok(self.os.get())
        }
        fn copy_os(&self) -> Result<()> {
            self.step("copy-os")?;
            self.os.set(true);
            Ok(())
        }
        fn expose_uki(&self) -> Result<()> {
            self.step("uki")
        }
        fn restore_loaders(&self) -> Result<()> {
            self.step("loaders")
        }
        fn set_default(&self) -> Result<()> {
            self.step("default")
        }
        fn verify_boot(&self) -> Result<()> {
            self.step("verify-boot")
        }
        fn ensure_firmware_entry(&self) -> Result<()> {
            self.step("firmware")
        }
    }
    #[test]
    fn replacement_boot_repairs_resume_after_data_copy_without_skipping_boot_readback() {
        for boundary in ["uki", "loaders", "default", "verify-boot", "firmware"] {
            let fixture = BootFixture::default();
            fixture.os.set(true);
            fixture.fail.set(Some(boundary));
            assert!(complete_replacement_boot(&fixture).is_err(), "{boundary}");
            assert_eq!(fixture.calls.borrow().last(), Some(&boundary));
            fixture.fail.set(None);
            fixture.calls.borrow_mut().clear();
            complete_replacement_boot(&fixture).expect("resume missing boot work");
            assert_eq!(
                *fixture.calls.borrow(),
                [
                    "verify-os",
                    "uki",
                    "loaders",
                    "default",
                    "verify-boot",
                    "firmware"
                ]
            );
        }
        let fixture = BootFixture::default();
        complete_replacement_boot(&fixture).expect("repair OS too");
        assert_eq!(
            &fixture.calls.borrow()[..3],
            ["verify-os", "copy-os", "verify-os"]
        );
    }
    #[test]
    fn replacement_version_and_device_remain_bound_to_the_existing_journal() {
        let device = json!({"role":"b","path":"/dev/disk/by-id/new","serial":"NEW","disk_uuid":Uuid::new_v4().to_string(),"partitions":[{"role":"a_usr","label":"PVE_45.0.3.4-1.4"}]});
        let record = json!({"role":"b","device":device});
        assert_eq!(
            replacement_version(&record, &device).unwrap(),
            "45.0.3.4-1.4"
        );
        for field in ["role", "path", "serial", "disk_uuid", "partitions"] {
            let mut other = device.clone();
            other[field] = Value::Null;
            assert!(replacement_version(&record, &other).is_err(), "{field}");
        }
        let mut malformed = record;
        malformed["device"]["partitions"][0]["label"] = json!("PVE_../../latest");
        assert!(replacement_version(&malformed, &malformed["device"]).is_err());
    }
    #[test]
    fn tpm_policy_requires_signed_pcr11_and_preserves_owner_slots() {
        let token = json!({"type":"systemd-tpm2","tpm2-pcrs":[7],"tpm2-pcr-bank":"sha256","tpm2_pubkey_pcrs":[11],"tpm2_pubkey":"expected-public-key","keyslots":["1"]});
        let tokens = json!({"0":{"type":"systemd-recovery","keyslots":["0"]},"1":token});
        assert!(validate_tpm_tokens(&tokens, "expected-public-key").is_ok());
        for (key, value) in [
            ("type", json!("systemd-recovery")),
            ("tpm2-pcrs", json!([7, 11])),
            ("tpm2-pcr-bank", json!("sha1")),
            ("tpm2_pubkey_pcrs", json!([])),
            ("tpm2_pubkey", json!("different-key")),
            ("keyslots", json!([])),
            ("tpm2_pcrlock", json!(true)),
            ("tpm2-pin", json!(true)),
        ] {
            let mut invalid = tokens.clone();
            invalid["1"][key] = value;
            assert!(
                validate_tpm_tokens(&invalid, "expected-public-key").is_err(),
                "accepted {key}"
            );
        }
        assert!(validate_tpm_tokens(&json!([]), "expected-public-key").is_err());
        let mut explicit = tokens.clone();
        explicit["1"]["tpm2_pcrlock"] = json!(false);
        explicit["1"]["tpm2-pin"] = json!(false);
        assert!(validate_tpm_tokens(&explicit, "expected-public-key").is_ok());
        let arguments = tpm_enrollment_arguments("/dev/owned", Path::new("/run/recovery"));
        assert_eq!(
            arguments,
            [
                "systemd-cryptenroll",
                "--unlock-key-file=/run/recovery",
                "--tpm2-device=auto",
                "--tpm2-pcrs=7",
                "--tpm2-pcrlock=",
                &format!("--tpm2-public-key={TPM_PUBLIC_KEY}"),
                "--tpm2-public-key-pcrs=11",
                "/dev/owned"
            ]
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("--wipe-slot"))
        );
    }
    #[test]
    fn replacement_rejects_retained_mapping_including_broken_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let mapping = temporary.path().join("particleve-state-a");
        assert!(require_absent_mapper(&mapping).is_ok());
        fs::write(&mapping, b"retained authority").unwrap();
        assert!(require_absent_mapper(&mapping).is_err());
        fs::remove_file(&mapping).unwrap();
        std::os::unix::fs::symlink("missing-device", &mapping).unwrap();
        assert!(require_absent_mapper(&mapping).is_err());
    }
    #[test]
    fn fresh_install_refuses_partial_storage_before_destructive_commands() {
        for label in ["ParticleVE", "ParticleVE state a", "PVE_45.0.2.0"] {
            assert!(refuse_existing_labels(&[json!({"partlabel":label})]).is_err());
        }
        assert!(refuse_existing_labels(&[json!({"partlabel":"data"}), json!({})]).is_ok());
    }
    #[test]
    fn recovery_passphrase_encoding_matches_luks_token_encoding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
        assert_eq!(base64(&[255, 254, 0]), "//4A");
    }
    #[test]
    fn crypttab_never_automatically_assembles_state() {
        let manifest = json!({"devices":[{"role":"a","state_luks_uuid":"state-a"},{"role":"b","state_luks_uuid":"state-b"}],"swap":{"luks_uuid":"swap"}});
        let contents = crypttab(&manifest).unwrap();
        for line in contents
            .lines()
            .filter(|l| l.starts_with("particleve-state-"))
        {
            assert!(line.contains(
                "noauto,tpm2-device=auto,x-initrd.attach,nofail,x-systemd.device-timeout=30s"
            ));
        }
        assert!(contents.ends_with("particleve-swap UUID=swap - tpm2-device=auto\n"));
    }
    #[test]
    fn independently_enrolled_devices_have_stable_sorted_identity() {
        let manifest = json!({"devices":[{"state_luks_uuid":"z"},{"state_luks_uuid":"a"}],"swap":{"luks_uuid":"m"}});
        assert_eq!(enrollment_uuids(&manifest).unwrap(), vec!["a", "m", "z"]);
    }
    #[test]
    fn failed_mount_cleanup_never_recursively_deletes_storage_contents() {
        let temporary = tempfile::tempdir().unwrap().keep();
        let marker = temporary.join("retained-user-data");
        fs::write(&marker, b"must survive uncertain unmount").unwrap();
        drop(MountDirectory {
            path: temporary.clone(),
        });
        assert_eq!(
            fs::read(&marker).unwrap(),
            b"must survive uncertain unmount"
        );
        fs::remove_file(marker).unwrap();
        fs::remove_dir(temporary).unwrap();
        let empty = tempfile::tempdir().unwrap().keep();
        drop(MountDirectory {
            path: empty.clone(),
        });
        assert!(!empty.exists());
    }
}
