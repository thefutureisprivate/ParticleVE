//! Linux operations bind every selected disk to the encrypted installation manifest.
use crate::bootloaders::Loaders;
use crate::common::{
    Error, Result, atomic_write, command, digest, field, hash_file, list, object, read_json,
    require, run, text, uint, write_json,
};
use crate::vms::{LinuxVMs, Shutdown};
use regex::Regex;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
fn firmware_pending(v: &Value) -> Result<bool> {
    match v {
        Value::Object(map) => {
            if let Some(state) = map.get("UpdateState") {
                let state = uint(state)?;
                require(state < 6, "unknown fwupd update state")?;
                if state == 1 || state == 4 {
                    return Ok(true);
                }
            }
            for value in map.values() {
                if firmware_pending(value)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Value::Array(values) => {
            for value in values {
                if firmware_pending(value)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

pub struct Linux {
    pub config: Value,
    pub manifest: Value,
    pub directory: PathBuf,
    pub cache: PathBuf,
    pub keyring: PathBuf,
    pub certificate: PathBuf,
}
pub fn image_version() -> Result<String> {
    let data = fs::read_to_string("/usr/lib/os-release")?;
    let values = data
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    require(
        values
            .get("IMAGE_ID")
            .is_some_and(|v| v.trim_matches('"') == "ParticleVE"),
        "this is not a ParticleVE OS",
    )?;
    let version = values
        .get("IMAGE_VERSION")
        .ok_or_else(|| Error::new("OS image version missing"))?
        .trim_matches('"');
    crate::config::version_key(version)?;
    Ok(version.into())
}
fn active(units: &[&str]) -> Result<()> {
    for unit in units {
        run(&["systemctl", "is-active", "--quiet", unit])?;
    }
    Ok(())
}
fn invoke(args: Vec<String>, timeout: u64, check: bool) -> Result<crate::common::Output> {
    command(
        &args,
        None,
        Some(Duration::from_secs(timeout)),
        8 * 1024 * 1024,
        check,
    )
}
// A native mount client may fail after the kernel has attached storage. Never
// retain recursive TempDir ownership across that authority boundary.
struct MountDirectory {
    path: PathBuf,
}
impl MountDirectory {
    fn new(parent: &Path, prefix: &str) -> Result<Self> {
        Ok(Self {
            path: tempfile::Builder::new()
                .prefix(prefix)
                .tempdir_in(parent)?
                .keep(),
        })
    }
    fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for MountDirectory {
    fn drop(&mut self) {
        // rmdir removes only an empty detached directory. EBUSY/ENOTEMPTY leave
        // a live mount or unexpected contents for owner recovery, without traversal.
        let _ = fs::remove_dir(&self.path);
    }
}
fn with_mounted_directory<T>(
    directory: MountDirectory,
    mount: impl FnOnce(&Path) -> Result<()>,
    operation: impl FnOnce(&Path) -> Result<T>,
    unmount: impl FnOnce(&Path) -> Result<()>,
) -> Result<T> {
    if let Err(mut error) = mount(directory.path()) {
        error.message = format!(
            "{}; inspect ESP mountpoint {} for owner recovery if still mounted",
            error.message,
            directory.path().display()
        );
        return Err(error);
    }
    let result = operation(directory.path());
    let cleanup = unmount(directory.path());
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(mut error)) => {
            error.message = format!(
                "{}; inspect ESP mountpoint {} for owner recovery if still mounted",
                error.message,
                directory.path().display()
            );
            Err(error)
        }
        (Err(mut error), Err(cleanup)) => {
            error.message = format!(
                "{}; ESP cleanup failed: {}; inspect mountpoint {} for owner recovery if still mounted",
                error.message,
                cleanup,
                directory.path().display()
            );
            Err(error)
        }
    }
}
fn commissioning_bindings(record: &Value, manifest: &Value, config: &Value) -> Result<()> {
    require(
        record["installation_sha256"] == digest(manifest)?,
        "commissioning evidence does not match this host",
    )?;
    require(
        record["config_sha256"] == digest(config)?,
        "configuration has not been commissioned",
    )?;
    require(
        record["acceptance_requirements_sha256"] == crate::commission::requirements_digest()?,
        "commissioning acceptance requirements changed or lack approval; review and recommission",
    )?;
    require(
        record
            .get("reporting_policy_sha256")
            .is_some_and(|v| v.as_str().is_some_and(|v| !v.is_empty())),
        "commissioning record lacks external reporting evidence; review and recommission",
    )?;
    Ok(())
}
impl Linux {
    pub fn new(config: Value, directory: &Path, allow_unbound: bool) -> Result<Self> {
        let manifest = read_json(directory.join("installation.json"))?;
        require(
            manifest["schema"] == 1,
            "unknown installation manifest schema",
        )?;
        require(
            !directory.join("reconfiguration.json").exists(),
            "reconfiguration interrupted; resume the exact reviewed operation",
        )?;
        require(
            allow_unbound || manifest["config_sha256"] == digest(&config)?,
            "host configuration changed; recommission explicitly",
        )?;
        Ok(Self {
            config,
            manifest,
            directory: directory.into(),
            cache: directory.join("releases"),
            keyring: "/usr/lib/particleve/trust/releases.gpg".into(),
            certificate: "/usr/lib/particleve/trust/secure-boot.crt".into(),
        })
    }
    pub fn current_version(&self) -> Result<String> {
        image_version()
    }
    pub fn boot_id(&self) -> Result<String> {
        Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into())
    }
    pub fn disk(&self, role: &str) -> Result<Value> {
        list(field(&self.manifest, "devices")?)?
            .iter()
            .find(|d| d["role"] == role)
            .cloned()
            .ok_or_else(|| Error::new("unknown installation disk role"))
    }
    pub fn check_resources(&self, healthy: bool) -> Result<Value> {
        crate::resources::status(
            &self.config,
            list(field(&self.manifest, "devices")?)?,
            healthy,
        )
    }
    pub fn check_storage(&self, healthy: bool) -> Result<Value> {
        if healthy {
            for disk in list(field(&self.manifest, "devices")?)? {
                let actual = crate::inventory::observe_disk(disk, false)?;
                require(
                    actual["serial"] == disk["observed"]["serial"]
                        && actual["size"] == disk["observed"]["size"],
                    "selected physical disk identity changed",
                )?;
            }
        }
        crate::storage::status(&self.manifest, &self.config, healthy)
    }
    pub fn check_time(&self, anchor: Option<&Value>) -> Result<Value> {
        (move || {
            crate::timesync::check_configuration(field(&self.config, "time")?, Path::new("/"))?;
            crate::timesync::probe(field(&self.config, "time")?, anchor)
        })()
        .map_err(|e| Error::deferred(format!("authenticated time unavailable: {e}")))
    }
    pub fn check_dns(&self) -> Result<Value> {
        crate::dns::probe(field(&self.config, "network")?)
    }
    pub fn startup_policy(&self) -> Result<String> {
        Ok(text(field(
            &crate::startup::inventory(Path::new("/"))?,
            "sha256",
        )?)?
        .into())
    }
    pub fn reporting_policy(&self) -> Result<String> {
        let binding = crate::reporting::policy_binding()?;
        active(&["particleve-report.timer"])?;
        Ok(binding)
    }
    pub fn check_commissioned(&self) -> Result<()> {
        let path = self.directory.join("commissioned.json");
        if !path.exists() {
            return Err(Error::deferred(
                "not commissioned; automatic OS work is disabled",
            ));
        }
        let record = read_json(path)?;
        commissioning_bindings(&record, &self.manifest, &self.config)?;
        require(
            record["reporting_policy_sha256"] == self.reporting_policy()?,
            "external reporting policy changed; review and recommission",
        )?;
        require(
            record["startup_policy_sha256"] == self.startup_policy()?,
            "persistent startup policy changed or lacks owner approval; review and recommission",
        )
    }
    pub fn release(&self, version: Option<&str>) -> Result<Value> {
        if let Some(version) = version
            && self.cache.join(version).exists()
        {
            return crate::release::verify_directory(
                &self.cache.join(version),
                &self.keyring,
                &self.certificate,
                true,
            );
        }
        let receipt = self.directory.join("release-check.json");
        let previous = if receipt.exists() {
            Some(read_json(&receipt)?)
        } else {
            None
        };
        require(
            previous
                .as_ref()
                .is_none_or(|v| v.is_object() && v["schema"] == 1),
            "unknown release-check observation",
        )?;
        let mut observation = json!({"schema":1,"attempted_at":timestamp(),"last_success_at":previous.as_ref().and_then(|v|v.get("last_success_at")),"result":"fail","version":previous.as_ref().and_then(|v|v.get("version"))});
        match crate::release::fetch(
            text(field(&self.config, "feed")?)?,
            &self.cache,
            &self.keyring,
            &self.certificate,
            version,
        ) {
            Ok((_, manifest)) => {
                observation["result"] = "pass".into();
                observation["last_success_at"] = timestamp().into();
                observation["version"] = manifest["version"].clone();
                write_json(receipt, &observation)?;
                Ok(manifest)
            }
            Err(e) => {
                write_json(receipt, &observation)?;
                Err(e)
            }
        }
    }
    pub fn local_release(&self, version: &str) -> Result<Value> {
        crate::release::verify_directory(
            &self.cache.join(version),
            &self.keyring,
            &self.certificate,
            false,
        )
    }
    pub fn compatibility_approved(&self, first: &Value, second: &Value) -> Result<()> {
        if first["persistent_state"] == second["persistent_state"] {
            return Ok(());
        }
        for (field_name, message) in [
            (
                "host_state",
                "Host-state contract has no migration; provision a new installation",
            ),
            (
                "boot_console",
                "Boot-console contract has no migration; provision a new installation",
            ),
        ] {
            if first["persistent_state"][field_name] != second["persistent_state"][field_name] {
                return Err(Error::deferred(message));
            }
        }
        let path = self.directory.join("compatibility.json");
        let approvals = if path.exists() {
            read_json(path)?
        } else {
            json!([])
        };
        let pair = BTreeSet::from([digest(first)?, digest(second)?]);
        for approval in list(&approvals)? {
            let approved = list(field(approval, "release_sha256")?)?
                .iter()
                .map(|v| text(v).map(String::from))
                .collect::<Result<BTreeSet<_>>>()?;
            if approved == pair && approval["retained_os_safe"] == true {
                let evidence = Path::new(text(field(approval, "evidence")?)?);
                require(
                    approval
                        .get("approved_by")
                        .is_some_and(|v| v.as_str().is_some_and(|v| !v.is_empty()))
                        && evidence.is_file(),
                    "compatibility approval lacks evidence",
                )?;
                require(
                    hash_file(evidence, None)? == text(field(approval, "evidence_sha256")?)?,
                    "compatibility evidence changed",
                )?;
                return Ok(());
            }
        }
        Err(Error::deferred(
            "Persistent-state change needs explicit, tested retained-OS compatibility approval",
        ))
    }
    pub fn check_compatibility(&self, current: &str, release: &Value) -> Result<()> {
        self.compatibility_approved(&self.local_release(current)?, release)
    }
    pub fn check_runtime_state(&self) -> Result<()> {
        let current = self.local_release(&self.current_version()?)?;
        let ledger = self.directory.join("runtime-last-started.json");
        if ledger.exists() {
            let previous =
                self.local_release(text(field(&read_json(&ledger)?, "image_version")?)?)?;
            self.compatibility_approved(&previous, &current)?;
        }
        write_json(
            ledger,
            &json!({"image_version":current["version"],"persistent_state":current["persistent_state"]}),
        )
    }
    pub fn current_esp_role(&self) -> Result<String> {
        let bytes = fs::read(
            "/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f",
        )?;
        require(
            bytes.len() >= 4 && (bytes.len() - 4) % 2 == 0,
            "invalid booted ESP firmware identity",
        )?;
        let units = bytes[4..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect::<Vec<_>>();
        let selected = String::from_utf16(&units).map_err(|e| Error::new(e.to_string()))?;
        let selected = uuid::Uuid::parse_str(selected.trim_end_matches('\0'))
            .map_err(|e| Error::new(e.to_string()))?
            .to_string();
        let mut roles = Vec::new();
        for disk in list(field(&self.manifest, "devices")?)? {
            if list(field(disk, "partitions")?)?
                .iter()
                .any(|p| p["role"] == "esp" && p["uuid"] == selected)
            {
                roles.push(text(field(disk, "role")?)?.to_owned());
            }
        }
        require(
            roles.len() == 1,
            "booted ESP is outside the selected disk pair",
        )?;
        Ok(roles.remove(0))
    }
    pub fn with_esp<T>(&self, role: &str, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
        let device = self.disk(role)?;
        let esp = list(field(&device, "partitions")?)?
            .iter()
            .find(|p| p["role"] == "esp")
            .ok_or_else(|| Error::new("installation lacks ESP partition"))?;
        let source = Path::new("/dev/disk/by-partuuid").join(text(field(esp, "uuid")?)?);
        require(source.exists(), format!("ESP {role} is missing"))?;
        let temporary = MountDirectory::new(Path::new("/run"), &format!("particleve-esp-{role}-"))?;
        with_mounted_directory(
            temporary,
            |target| {
                invoke(
                vec![
                    "mount".into(), "-t".into(), "vfat".into(), "-o".into(),
                    "rw,nosuid,nodev,noexec,noatime,umask=0077,context=system_u:object_r:boot_t:s0".into(),
                    source.display().to_string(), target.display().to_string(),
                ], 120, true,
            ).map(|_| ())
            },
            operation,
            |target| {
                invoke(
                    vec!["umount".into(), target.display().to_string()],
                    120,
                    true,
                )
                .map(|_| ())
            },
        )
    }

    pub fn boot_entries(esp: &Path, version: &str) -> Result<Vec<(PathBuf, Option<u64>)>> {
        let pattern = Regex::new(&format!(
            r"^ParticleVE_{}_x86-64(?:\+(\d+)(?:-\d+)?)?\.efi$",
            regex::escape(version)
        ))
        .map_err(|e| Error::new(e.to_string()))?;
        let directory = esp.join("EFI/Linux");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(captures) = name.to_str().and_then(|name| pattern.captures(name)) {
                let count = captures
                    .get(1)
                    .map(|m| {
                        m.as_str()
                            .parse::<u64>()
                            .map_err(|_| Error::new("invalid boot counter"))
                    })
                    .transpose()?;
                entries.push((entry.path(), count));
            }
        }
        Ok(entries)
    }
    pub fn bless_current(&self) -> Result<Value> {
        let current = self.current_version()?;
        let role = self.current_esp_role()?;
        let release = self.local_release(&current)?;
        self.with_esp(&role, |esp| {
            let entries = Self::boot_entries(esp, &current)?;
            require(
                entries.len() == 1
                    && hash_file(&entries[0].0, None)?
                        == text(&release["artifacts"]["uki"]["sha256"])?,
                "booted ESP does not hold the authenticated running UKI",
            )?;
            if entries[0].1.is_some() {
                invoke(
                    vec![
                        "/usr/lib/systemd/systemd-bless-boot".into(),
                        format!("--path={}", esp.display()),
                        "good".into(),
                    ],
                    120,
                    true,
                )?;
            }
            Ok(())
        })?;
        let mut result = Loaders::new(self).bless()?;
        let map = result
            .as_object_mut()
            .ok_or_else(|| Error::new("invalid loader blessing result"))?;
        map.insert("boot_blessed".into(), current.into());
        map.insert("esp_role".into(), role.into());
        Ok(result)
    }
    pub fn check_usr_boot_disk(&self) -> Result<()> {
        crate::security::verified_usr_mount()?;
        let boot_disk = fs::canonicalize(text(field(
            &self.disk(&self.current_esp_role()?)?,
            "path",
        )?)?)?;
        let boot_disk = boot_disk
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::new("invalid boot disk path"))?;
        let mapper = fs::canonicalize("/dev/mapper/usr")?;
        let mapper = mapper
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::new("invalid usr mapper"))?;
        require(
            crate::security::usr_backing_disks(mapper, Path::new("/sys"))?
                == BTreeSet::from([boot_disk.into()]),
            "verified usr is not on the selected EFI boot disk",
        )?;
        let native = run(&[
            "udevadm",
            "info",
            "--query=property",
            &format!("--path=/sys/class/block/{boot_disk}"),
        ])?;
        require(
            native.stderr.trim().is_empty(),
            format!("boot disk inspection diagnostics: {}", native.stderr.trim()),
        )?;
        require(
            native
                .stdout
                .lines()
                .any(|line| line == "PARTICLEVE_BOOT_DISK=1"),
            "EFI boot-disk selection did not survive the initrd transition",
        )
    }
    pub fn check_firmware_clear(&self) -> Result<()> {
        if fs::read_dir("/sys/firmware/efi/efivars")?
            .filter_map(std::result::Result::ok)
            .any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("BootNext-"))
            })
            || Path::new("/system-update").exists()
        {
            return Err(Error::deferred(
                "UEFI BootNext or an offline update is staged",
            ));
        }
        let result = invoke(
            vec!["fwupdmgr".into(), "get-history".into(), "--json".into()],
            120,
            false,
        )?;
        require(
            matches!(result.code, 0 | 2),
            "fwupd history unavailable; cannot exclude staged firmware",
        )?;
        let history = if result.stdout.trim().is_empty() {
            json!({})
        } else {
            crate::common::parse_json(result.stdout.as_bytes())?
        };
        if firmware_pending(&history)? {
            return Err(Error::deferred("fwupd reports staged firmware"));
        }
        fn capsules(path: &Path) -> Result<bool> {
            if !path.exists() {
                return Ok(false);
            }
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if entry.file_type()?.is_dir() {
                    if name == "UpdateCapsule" && fs::read_dir(entry.path())?.next().is_some() {
                        return Ok(true);
                    }
                    if capsules(&entry.path())? {
                        return Ok(true);
                    }
                } else if name.starts_with("fwupd") && name.ends_with(".cap") {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        for role in ["a", "b"] {
            self.with_esp(role, |esp| {
                if capsules(&esp.join("EFI"))? {
                    Err(Error::deferred(format!(
                        "ESP {role} contains staged firmware"
                    )))
                } else {
                    Ok(())
                }
            })?;
        }
        Ok(())
    }
    pub fn matching_partition(
        &self,
        role: &str,
        release: &Value,
        kind: &str,
    ) -> Result<Option<String>> {
        let label = crate::layout::os_label(text(field(release, "version")?)?)?;
        let item = &release["artifacts"][kind];
        let disk = self.disk(role)?;
        let nodes = crate::inventory::walk(&crate::inventory::block_tree(Some(text(field(
            &disk, "path",
        )?)?))?)?;
        let parttype = crate::layout::kind_type(kind)?;
        let matches = nodes
            .iter()
            .filter(|n| {
                n["type"] == "part"
                    && n["partlabel"] == label
                    && n["parttype"] == parttype
                    && n["partuuid"] == item["partition_uuid"]
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 || uint(field(matches[0], "size")?)? < uint(field(item, "size")?)? {
            return Ok(None);
        }
        Ok(Some(text(field(matches[0], "name")?)?.into()))
    }
    pub fn verify_disk(&self, role: &str, release: &Value, boot: bool) -> Result<bool> {
        for kind in ["usr", "verity", "verity_sig"] {
            let Some(path) = self.matching_partition(role, release, kind)? else {
                return Ok(false);
            };
            if hash_file(path, Some(uint(&release["artifacts"][kind]["size"])?))?
                != text(&release["artifacts"][kind]["sha256"])?
            {
                return Ok(false);
            }
        }
        if boot {
            return self.with_esp(role, |esp| {
                let entries = Self::boot_entries(esp, text(field(release, "version")?)?)?;
                if entries.len() != 1
                    || entries[0].1 == Some(0)
                    || hash_file(&entries[0].0, None)?
                        != text(&release["artifacts"]["uki"]["sha256"])?
                {
                    return Ok(false);
                }
                let path = esp.join(crate::bootloaders::loader_path(text(
                    &release["artifacts"]["bootloader"]["sha256"],
                )?)?);
                if !path.is_file()
                    || hash_file(path, None)?
                        != text(&release["artifacts"]["bootloader"]["sha256"])?
                {
                    return Ok(false);
                }
                Loaders::new(self).prove(esp)?;
                Ok(true)
            });
        }
        Ok(true)
    }
    pub fn transfer(&self, role: &str, release: &Value, current: &str) -> Result<()> {
        let source = self.cache.join(text(field(release, "version")?)?);
        let temporary = tempfile::Builder::new()
            .prefix("particleve-transfer-")
            .tempdir_in("/run")?;
        let disk = self.disk(role)?;
        for (name, content) in
            crate::release::transfers(release, text(field(&disk, "path")?)?, &source, current)?
        {
            atomic_write(temporary.path().join(name), content.as_bytes(), 0o600)?;
        }
        let definitions = format!("--definitions={}", temporary.path().display());
        run(&["/usr/lib/systemd/systemd-sysupdate", &definitions, "vacuum"])?;
        invoke(
            vec![
                "/usr/lib/systemd/systemd-sysupdate".into(),
                definitions,
                "update".into(),
                text(field(release, "version")?)?.into(),
            ],
            3600,
            true,
        )?;
        invoke(
            vec!["udevadm".into(), "settle".into(), "--timeout=120".into()],
            130,
            true,
        )?;
        Ok(())
    }
    pub fn expose_boot(&self, role: &str, release: &Value) -> Result<()> {
        self.with_esp(role, |esp| {
            let version = text(field(release, "version")?)?;
            let entries = Self::boot_entries(esp, version)?;
            require(entries.len() <= 1, "ambiguous boot entries")?;
            if let Some((path, count)) = entries.first() {
                require(
                    count.is_none_or(|n| n > 0),
                    "boot attempts exhausted; release requires review",
                )?;
                require(
                    hash_file(path, None)? == text(&release["artifacts"]["uki"]["sha256"])?,
                    "existing UKI mismatch",
                )?;
            } else {
                atomic_write(
                    esp.join(format!("EFI/Linux/ParticleVE_{version}_x86-64+3.efi")),
                    &fs::read(
                        self.cache
                            .join(version)
                            .join(text(&release["artifacts"]["uki"]["file"])?),
                    )?,
                    0o600,
                )?;
            }
            let item = &release["artifacts"]["bootloader"];
            atomic_write(
                esp.join(crate::bootloaders::loader_path(text(field(
                    item, "sha256",
                )?)?)?),
                &fs::read(self.cache.join(version).join(text(field(item, "file")?)?))?,
                0o600,
            )
        })
    }
    pub fn default(&self, esp: &Path, version: Option<&str>) -> Result<()> {
        let path = esp.join("loader/loader.conf");
        let old = if path.exists() {
            fs::read_to_string(&path)?
        } else {
            "timeout 5\neditor no\nauto-entries no\n".into()
        };
        let re = Regex::new(r"^\s*default\s").map_err(|e| Error::new(e.to_string()))?;
        let mut lines = old
            .lines()
            .filter(|line| !re.is_match(line))
            .map(String::from)
            .collect::<Vec<_>>();
        let suffix =
            crate::consoles::profile(&self.config)?.map_or(String::new(), |p| format!("@{p}"));
        lines.push(format!(
            "default ParticleVE_{}_x86-64*.efi{suffix}",
            version.unwrap_or("*")
        ));
        atomic_write(path, (lines.join("\n") + "\n").as_bytes(), 0o600)
    }
    pub fn pin_current(&self, current: &str) -> Result<()> {
        for role in ["a", "b"] {
            self.with_esp(role, |esp| {
                require(
                    !Self::boot_entries(esp, current)?.is_empty(),
                    format!("disk {role} has no current fallback entry"),
                )?;
                self.default(esp, Some(current))
            })?;
        }
        Ok(())
    }
    pub fn protect_current(&self, current: &str, candidate: Option<&str>) -> Result<()> {
        self.pin_current(current)?;
        for role in ["a", "b"] {
            self.with_esp(role, |esp| {
                let mut retained = Self::boot_entries(esp, current)?
                    .into_iter()
                    .map(|v| v.0)
                    .collect::<BTreeSet<_>>();
                if let Some(candidate) = candidate {
                    retained.extend(Self::boot_entries(esp, candidate)?.into_iter().map(|v| v.0));
                }
                let directory = esp.join("EFI/Linux");
                for entry in fs::read_dir(&directory)? {
                    let entry = entry?;
                    let name = entry.file_name();
                    if name
                        .to_str()
                        .is_some_and(|n| n.starts_with("ParticleVE_") && n.ends_with(".efi"))
                        && !retained.contains(&entry.path())
                    {
                        fs::remove_file(entry.path())?;
                    }
                }
                fs::File::open(directory)?.sync_all()?;
                Ok(())
            })?;
        }
        Ok(())
    }
    pub fn prove_fallback(&self, current: &str) -> Result<()> {
        active(&["boot-complete.target", "systemd-bless-boot.service"])?;
        let release = self.local_release(current)?;
        for role in ["a", "b"] {
            for kind in ["usr", "verity", "verity_sig"] {
                let path = self
                    .matching_partition(role, &release, kind)?
                    .ok_or_else(|| {
                        Error::new(format!("disk {role} no longer has a coherent fallback"))
                    })?;
                require(
                    hash_file(path, Some(uint(&release["artifacts"][kind]["size"])?))?
                        == text(&release["artifacts"][kind]["sha256"])?,
                    format!("disk {role} no longer has a coherent fallback"),
                )?;
            }
            self.with_esp(role, |esp| {
                Loaders::new(self).prove(esp)?;
                let entries = Self::boot_entries(esp, current)?;
                require(
                    entries.len() == 1
                        && entries[0].1.is_none_or(|n| n > 0)
                        && hash_file(&entries[0].0, None)?
                            == text(&release["artifacts"]["uki"]["sha256"])?,
                    format!("disk {role} fallback UKI is unavailable"),
                )
            })?;
        }
        Ok(())
    }
    pub fn select(&self, version: &str) -> Result<()> {
        for role in ["a", "b"] {
            self.with_esp(role, |esp| {
                let entries = Self::boot_entries(esp, version)?;
                require(
                    entries.len() == 1 && entries[0].1.is_none_or(|n| n > 0),
                    format!("disk {role} has no eligible candidate boot entry"),
                )?;
                self.default(esp, None)
            })?;
        }
        Ok(())
    }
    pub fn conditional_reboot(&self, version: &str) -> Result<bool> {
        let disk = self.disk(&self.current_esp_role()?)?;
        let release = self.local_release(version)?;
        let temporary = tempfile::Builder::new()
            .prefix("particleve-reboot-")
            .tempdir_in("/run")?;
        for (name, content) in crate::release::transfers(
            &release,
            text(field(&disk, "path")?)?,
            &self.cache.join(version),
            &self.current_version()?,
        )? {
            atomic_write(temporary.path().join(name), content.as_bytes(), 0o600)?;
        }
        let definitions = format!("--definitions={}", temporary.path().display());
        if invoke(
            vec![
                "/usr/lib/systemd/systemd-sysupdate".into(),
                definitions.clone(),
                "pending".into(),
            ],
            120,
            false,
        )?
        .code
            != 0
        {
            return Ok(false);
        }
        let loaders = Loaders::new(self);
        let result = (|| {
            loaders.queue(&release)?;
            run(&["/usr/lib/systemd/systemd-sysupdate", &definitions, "reboot"])?;
            let jobs = invoke(
                vec![
                    "systemctl".into(),
                    "list-jobs".into(),
                    "--no-legend".into(),
                    "--no-pager".into(),
                ],
                10,
                true,
            )?
            .stdout;
            let state = invoke(
                vec!["systemctl".into(), "is-system-running".into()],
                10,
                false,
            )?
            .stdout;
            let queued = jobs.contains("reboot.target") || state.trim() == "stopping";
            if !queued {
                loaders.cancel()?;
            }
            Ok(queued)
        })();
        if result.is_err() {
            loaders.cancel()?;
        }
        result
    }
    pub fn reject(&self, version: &str, current: &str) -> Result<()> {
        Loaders::new(self).cancel()?;
        for role in ["a", "b"] {
            let _ = self.with_esp(role, |esp| {
                self.default(esp, Some(current))?;
                for (path, _) in Self::boot_entries(esp, version)? {
                    fs::rename(&path, path.with_extension("rejected"))?;
                }
                Ok(())
            });
        }
        Ok(())
    }
    pub fn health(&self) -> Result<()> {
        self.check_storage(false)?;
        crate::consoles::baseline(&self.config, Path::new("/proc"), Path::new("/sys"))?;
        crate::accounts::check()?;
        require(crate::inventory::kvm_available(), "KVM is unavailable")?;
        require(
            crate::inventory::secure_boot(),
            "Secure Boot is not enabled",
        )?;
        crate::inventory::measured_boot(true)?;
        crate::security::live_baseline(Path::new("/"), false)?;
        crate::security::ssh_baseline()?;
        crate::security::selinux_baseline()?;
        crate::security::selinux_access()?;
        self.check_usr_boot_disk()?;
        crate::startup::check(Path::new("/"))?;
        require(
            fs::read_to_string("/sys/fs/selinux/enforce")?.trim() == "1",
            "SELinux is not enforcing",
        )?;
        active(&[
            "systemd-networkd.service",
            "systemd-resolved.service",
            "chronyd-restricted.service",
            "particleve-firewall.service",
            "sshd.socket",
            "systemd-homed.service",
            "auditd.service",
            "particleve-storage-watch.timer",
        ])?;
        crate::timesync::check_configuration(&self.config["time"], Path::new("/"))?;
        crate::radio::baseline(
            &self.config["physical"]["radios"],
            Path::new("/sys"),
            Path::new("/proc"),
            Path::new("/dev/rfkill"),
            Path::new("/etc/particleve/radio-policy.json"),
        )?;
        self.check_dns()?;
        let management = text(&self.config["network"]["management"])?;
        let network = crate::common::parse_json(
            run(&["ip", "--json", "address", "show", "dev", management])?
                .stdout
                .as_bytes(),
        )?;
        let mut actual = BTreeSet::new();
        for dev in list(&network)? {
            if let Some(addresses) = dev.get("addr_info") {
                for address in list(addresses)? {
                    actual.insert(
                        text(field(address, "local")?)?
                            .parse::<std::net::IpAddr>()
                            .map_err(|e| Error::new(e.to_string()))?,
                    );
                }
            }
        }
        for expected in list(&self.config["network"]["addresses"])? {
            require(
                actual.contains(&crate::config::ip_interface(text(expected)?, false)?.0),
                "management addresses missing",
            )?;
        }
        run(&["systemctl", "is-active", "systemd-machined.service"])?;
        run(&["systemd-vmspawn", "--version"])?;
        require(
            Path::new("/usr/lib/systemd/system/systemd-vmspawn@.service").exists(),
            "vmspawn template missing",
        )?;
        require(
            fs::read_to_string("/sys/module/zswap/parameters/enabled")?.trim() == "Y",
            "zswap is disabled",
        )?;
        let swaps = fs::read_to_string("/proc/swaps")?;
        let swaps = swaps.lines().skip(1).collect::<Vec<_>>();
        require(
            !swaps.is_empty() && swaps.iter().all(|s| !s.contains("zram")),
            "encrypted block swap is missing or zram is active",
        )?;
        let expected = fs::canonicalize("/dev/mapper/particleve-swap")?;
        for line in swaps {
            let source = line
                .split_whitespace()
                .next()
                .ok_or_else(|| Error::new("invalid swap observation"))?;
            require(
                fs::canonicalize(source)? == expected,
                "unexpected swap outside the encrypted swap mirror",
            )?;
        }
        let source = run(&[
            "findmnt",
            "--noheadings",
            "--output=SOURCE",
            "--target",
            "/usr",
        ])?
        .stdout;
        require(
            run(&["dmsetup", "table", source.trim()])?
                .stdout
                .contains(" verity "),
            "/usr is not protected by dm-verity",
        )
    }
    pub fn accept(&self, version: &str) -> Result<()> {
        require(
            version == self.current_version()?,
            "cannot accept a release that is not running",
        )
    }
    pub fn cleanup_cache(&self) -> Result<()> {
        let devices = list(field(&self.manifest, "devices")?)?;
        if devices
            .iter()
            .any(|d| d["path"].as_str().is_none_or(|p| !Path::new(p).exists()))
        {
            return Ok(());
        }
        let mut retained = BTreeSet::from([self.current_version()?]);
        let pattern = Regex::new(r"^PVE_([0-9.-]+)$").map_err(|e| Error::new(e.to_string()))?;
        for disk in devices {
            for part in crate::inventory::walk(&crate::inventory::block_tree(Some(text(field(
                disk, "path",
            )?)?))?)? {
                if let Some(c) = part["partlabel"].as_str().and_then(|s| pattern.captures(s)) {
                    retained.insert(c[1].to_owned());
                }
            }
        }
        let state_path = self.directory.join("state.json");
        if state_path.exists() {
            let state = read_json(state_path)?;
            if !state["pending"].is_null() {
                retained.insert(text(&state["pending"]["version"])?.into());
            }
        }
        if !self.cache.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.cache)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if entry.file_type()?.is_dir() && !retained.contains(name) && !name.starts_with('.') {
                let manifest = self.local_release(name)?;
                for item in object(field(&manifest, "artifacts")?)?.values() {
                    let path = entry.path().join(text(field(item, "file")?)?);
                    match fs::remove_file(path) {
                        Ok(()) => (),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        Ok(())
    }
    fn vm_shutdown(&self) -> Result<Shutdown<LinuxVMs>> {
        Ok(Shutdown::new(
            &self.directory,
            LinuxVMs,
            &self.boot_id()?,
            uint(&self.config["maintenance"]["graceful_seconds"])?,
            uint(&self.config["maintenance"]["restore_seconds"])?,
        ))
    }
    pub fn freeze_vms(&self) -> Result<()> {
        self.vm_shutdown()?.freeze()
    }
    pub fn stop_vms(&self) -> Result<()> {
        self.vm_shutdown()?.stop()
    }
    pub fn assert_no_vms(&self) -> Result<()> {
        self.vm_shutdown()?.assert_empty()
    }
    pub fn restore_vms(&self) -> Result<Value> {
        self.vm_shutdown()?.recover()
    }
    pub fn recover_vms(&self) -> Result<Value> {
        self.vm_shutdown()?.recover()
    }
    pub fn mark_vm_reboot(&self) -> Result<()> {
        self.vm_shutdown()?.mark_reboot()
    }
}
pub fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
}
impl crate::coordinator::Backend for Linux {
    fn config(&self) -> &Value {
        &self.config
    }
    fn current_version(&self) -> Result<String> {
        self.current_version()
    }
    fn boot_id(&self) -> Result<String> {
        self.boot_id()
    }
    fn check_commissioned(&self) -> Result<()> {
        self.check_commissioned()
    }
    fn check_firmware_clear(&self) -> Result<()> {
        self.check_firmware_clear()
    }
    fn check_storage(&self, healthy: bool) -> Result<Value> {
        self.check_storage(healthy)
    }
    fn check_resources(&self, healthy: bool) -> Result<Value> {
        self.check_resources(healthy)
    }
    fn release(&self, version: Option<&str>) -> Result<Value> {
        self.release(version)
    }
    fn check_compatibility(&self, current: &str, release: &Value) -> Result<()> {
        self.check_compatibility(current, release)
    }
    fn prove_fallback(&self, current: &str) -> Result<()> {
        self.prove_fallback(current)
    }
    fn protect_current(&self, current: &str, candidate: Option<&str>) -> Result<()> {
        self.protect_current(current, candidate)
    }
    fn pin_current(&self, current: &str) -> Result<()> {
        self.pin_current(current)
    }
    fn verify_disk(&self, role: &str, release: &Value, boot: bool) -> Result<bool> {
        self.verify_disk(role, release, boot)
    }
    fn transfer(&self, role: &str, release: &Value, current: &str) -> Result<()> {
        self.transfer(role, release, current)
    }
    fn expose_boot(&self, role: &str, release: &Value) -> Result<()> {
        self.expose_boot(role, release)
    }
    fn check_time(&self, anchor: Option<&Value>) -> Result<Value> {
        self.check_time(anchor)
    }
    fn freeze_vms(&self) -> Result<()> {
        self.freeze_vms()
    }
    fn stop_vms(&self) -> Result<()> {
        self.stop_vms()
    }
    fn assert_no_vms(&self) -> Result<()> {
        self.assert_no_vms()
    }
    fn restore_vms(&self) -> Result<Value> {
        self.restore_vms()
    }
    fn recover_vms(&self) -> Result<Value> {
        self.recover_vms()
    }
    fn mark_vm_reboot(&self) -> Result<()> {
        self.mark_vm_reboot()
    }
    fn select(&self, version: &str) -> Result<()> {
        self.select(version)
    }
    fn conditional_reboot(&self, version: &str) -> Result<bool> {
        self.conditional_reboot(version)
    }
    fn reject(&self, version: &str, current: &str) -> Result<()> {
        self.reject(version, current)
    }
    fn check_runtime_state(&self) -> Result<()> {
        self.check_runtime_state()
    }
    fn health(&self) -> Result<()> {
        self.health()
    }
    fn accept(&self, version: &str) -> Result<()> {
        self.accept(version)
    }
    fn bless_current(&self) -> Result<Value> {
        self.bless_current()
    }
    fn cleanup_cache(&self) -> Result<()> {
        self.cleanup_cache()
    }
}

#[cfg(test)]
mod mount_tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn firmware_history_is_recursive_and_only_known_clear_states_allow_os_work() {
        for state in 0..6 {
            let history = json!({"Devices":[{"UpdateState":state}]});
            assert_eq!(
                firmware_pending(&history).unwrap(),
                state == 1 || state == 4
            );
        }
        for state in [json!(true), json!("needs-reboot"), json!(6), json!(-1)] {
            assert!(firmware_pending(&json!({"Devices":[{"UpdateState":state}]})).is_err());
        }
    }

    #[test]
    fn mount_client_error_never_traverses_or_deletes_nested_storage_contents() {
        let fixture = tempfile::tempdir().expect("isolated fixture");
        let directory = MountDirectory::new(fixture.path(), "esp-").expect("mountpoint");
        let target = directory.path().to_path_buf();
        let operated = Cell::new(false);
        let unmounted = Cell::new(false);
        let error = with_mounted_directory(
            directory,
            |path| {
                fs::create_dir_all(path.join("EFI/Linux")).expect("simulated mounted data");
                fs::write(path.join("EFI/Linux/working.efi"), b"retained loader").expect("loader");
                fs::write(path.join("owner-data"), b"must survive").expect("owner data");
                Err(Error::deferred("mount client failed after kernel success"))
            },
            |_| {
                operated.set(true);
                Ok(())
            },
            |_| {
                unmounted.set(true);
                Ok(())
            },
        )
        .expect_err("mount client error");
        assert!(error.deferred);
        assert!(
            error
                .message
                .starts_with("mount client failed after kernel success")
        );
        assert!(error.message.contains(target.to_str().expect("test path")));
        assert!(!operated.get() && !unmounted.get());
        assert_eq!(
            fs::read(target.join("EFI/Linux/working.efi")).expect("retained loader"),
            b"retained loader"
        );
        assert_eq!(
            fs::read(target.join("owner-data")).expect("retained owner data"),
            b"must survive"
        );
    }
    #[test]
    fn failed_unmount_preserves_original_operation_failure_and_storage_contents() {
        let fixture = tempfile::tempdir().expect("fixture");
        let directory = MountDirectory::new(fixture.path(), "esp-").expect("mountpoint");
        let target = directory.path().to_path_buf();
        let error = with_mounted_directory(
            directory,
            |_| Ok(()),
            |path| {
                fs::create_dir_all(path.join("EFI/ParticleVE")).expect("mounted data");
                fs::write(path.join("EFI/ParticleVE/loader.efi"), b"working loader")
                    .expect("loader");
                Err::<(), _>(Error::deferred("operation failed"))
            },
            |_| Err(Error::new("umount failed")),
        )
        .expect_err("both operations fail");
        assert!(error.deferred);
        assert!(
            error
                .message
                .starts_with("operation failed; ESP cleanup failed: umount failed")
        );
        assert_eq!(
            fs::read(target.join("EFI/ParticleVE/loader.efi")).expect("loader retained"),
            b"working loader"
        );
        let empty = MountDirectory::new(fixture.path(), "detached-").expect("empty mountpoint");
        let path = empty.path().to_path_buf();
        assert_eq!(
            with_mounted_directory(empty, |_| Ok(()), |_| Ok(7), |_| Ok(())).expect("success"),
            7
        );
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod commissioning_tests {
    use super::*;
    #[test]
    fn old_or_changed_acceptance_records_fail_before_any_live_reporting_query() {
        let manifest = json!({"installation":"owned"});
        let config = json!({"policy":"owned"});
        let record = json!({"installation_sha256":digest(&manifest).expect("manifest"),"config_sha256":digest(&config).expect("configuration"),"reporting_policy_sha256":"reporting","startup_policy_sha256":"startup"});
        for requirements in [None, Some("0".repeat(64))] {
            let mut candidate = record.clone();
            if let Some(value) = requirements {
                candidate["acceptance_requirements_sha256"] = value.into();
            }
            assert!(
                commissioning_bindings(&candidate, &manifest, &config)
                    .expect_err("old receipt")
                    .message
                    .contains("acceptance requirements")
            );
        }
        let mut approved = record;
        approved["acceptance_requirements_sha256"] = crate::commission::requirements_digest()
            .expect("current requirements")
            .into();
        commissioning_bindings(&approved, &manifest, &config).expect("reviewed receipt");
        for field in [
            "installation_sha256",
            "config_sha256",
            "reporting_policy_sha256",
        ] {
            let mut candidate = approved.clone();
            candidate.as_object_mut().expect("record").remove(field);
            assert!(
                commissioning_bindings(&candidate, &manifest, &config).is_err(),
                "{field}"
            );
        }
    }
}
