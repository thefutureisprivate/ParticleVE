//! Test-only storage boundaries; production exposes none of these fixture actions.
use particleve::{
    common::{Result, field, list, text, uint},
    linux::Linux,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
fn path(request: &Value, key: &str) -> Result<PathBuf> {
    Ok(text(field(request, key)?)?.into())
}
fn backend(request: &Value) -> Result<Linux> {
    let directory = request
        .get("directory")
        .map(text)
        .transpose()?
        .unwrap_or("/unused");
    Ok(Linux {
        config: request.get("config").cloned().unwrap_or_else(|| json!({})),
        manifest: request
            .get("manifest")
            .cloned()
            .unwrap_or_else(|| json!({"devices":[]})),
        directory: directory.into(),
        cache: request
            .get("cache")
            .map(text)
            .transpose()?
            .map_or_else(|| Path::new(directory).join("releases"), PathBuf::from),
        keyring: "/unused/releases.gpg".into(),
        certificate: "/unused/secure-boot.crt".into(),
    })
}
/// Mount/readback fixture only; all quarantine transitions use the runtime code.
struct QuarantineFixture {
    linux: Linux,
    isolated: Vec<String>,
}
impl particleve::bootloaders::Backend for QuarantineFixture {
    fn directory(&self) -> &Path {
        &self.linux.directory
    }
    fn cache(&self) -> &Path {
        &self.linux.cache
    }
    fn disk(&self, _role: &str) -> Result<Value> {
        unreachable!("quarantine fixture does not select disks")
    }
    fn current_esp_role(&self) -> Result<String> {
        unreachable!("quarantine fixture does not select boot roles")
    }
    fn boot_id(&self) -> Result<String> {
        unreachable!("quarantine fixture does not select boots")
    }
    fn with_esp<T>(&self, role: &str, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
        operation(&self.linux.directory.join(role))
    }
}
impl particleve::quarantine::Backend for QuarantineFixture {
    fn isolated(&self, role: &str) -> Result<bool> {
        Ok(!self.linux.directory.join(role).try_exists()?
            && self.isolated.iter().any(|r| r == role))
    }
    fn fallback(&self, esp: &Path, version: &str) -> Result<()> {
        self.linux.default(esp, Some(version))?;
        self.verify_fallback(esp, version)
    }
    fn verify_fallback(&self, esp: &Path, version: &str) -> Result<()> {
        self.linux.verify_default(esp, version)?;
        particleve::common::require(
            particleve::common::hash_file(
                esp.join(format!("EFI/Linux/ParticleVE_{version}_x86-64.efi")),
                None,
            )? == particleve::common::hash_file(self.linux.directory.join("fallback.efi"), None)?,
            "fixture fallback changed",
        )
    }
}
pub fn evaluate(request: &Value) -> Option<Result<Value>> {
    let operation = request.get("operation")?.as_str()?;
    (|| -> Result<Option<Value>> {
        let value = match operation {
            "sfdisk-script" => Ok(json!(particleve::layout::sfdisk_script(field(
                request, "device"
            )?)?)),
            "accounts-audit" => {
                particleve::accounts::audit_local(
                    text(field(request, "passwd")?)?,
                    text(field(request, "shells")?)?,
                )?;
                Ok(Value::Null)
            }
            "accounts-authorize" => {
                particleve::accounts::authorize_login(text(field(request, "username")?)?)?;
                Ok(Value::Null)
            }
            "install-crypttab" => Ok(json!(particleve::install::crypttab(field(
                request, "manifest"
            )?)?)),
            "install-enrollment-uuids" => Ok(json!(particleve::install::enrollment_uuids(field(
                request, "manifest"
            )?)?)),
            "install-validate-keyfile" => {
                particleve::install::validate_keyfile(&path(request, "path")?)?;
                Ok(Value::Null)
            }
            "install-format-encrypted" => Ok(json!(particleve::install::format_encrypted(
                text(field(request, "source")?)?,
                text(field(request, "name")?)?,
                &path(request, "keyfile")?,
                request
                    .get("enroll")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            )?)),
            "install-write-os" => {
                particleve::install::write_os(
                    field(request, "device")?,
                    field(request, "release")?,
                    &path(request, "directory")?,
                )?;
                Ok(Value::Null)
            }
            "install-replace-btrfs" => {
                particleve::install::replace_btrfs(
                    uint(field(request, "devid")?)?,
                    text(field(request, "mapper")?)?,
                )?;
                Ok(Value::Null)
            }
            "admission-bindings" => particleve::admission::bindings(field(request, "manifest")?),
            "admission-mounts" => Ok(json!(particleve::admission::mounts(field(
                request, "record"
            )?)?)),
            "admission-mounted-uuid" => Ok(json!(particleve::admission::mounted_uuid(&path(
                request, "target"
            )?)?)),
            "storage-present-members" => {
                let admitted = request
                    .get("admitted")
                    .map(|v| {
                        list(v)?
                            .iter()
                            .map(|x| text(x).map(str::to_owned))
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
                Ok(json!(particleve::storage::present_members(
                    field(request, "manifest")?,
                    list(field(request, "devices")?)?,
                    admitted.as_deref()
                )?))
            }
            "linux-boot-entries" => Ok(json!(
                Linux::boot_entries(&path(request, "esp")?, text(field(request, "version")?)?)?
                    .into_iter()
                    .map(|(path, attempts)| json!({"path":path,"attempts":attempts}))
                    .collect::<Vec<_>>()
            )),
            "linux-default" => {
                backend(request)?.default(
                    &path(request, "esp")?,
                    request
                        .get("version")
                        .filter(|v| !v.is_null())
                        .map(text)
                        .transpose()?,
                )?;
                Ok(Value::Null)
            }
            "linux-matching-partition" => Ok(json!(backend(request)?.matching_partition(
                text(field(request, "role")?)?,
                field(request, "release")?,
                text(field(request, "kind")?)?
            )?)),
            "linux-verify-partitions" => Ok(json!(backend(request)?.verify_disk(
                text(field(request, "role")?)?,
                field(request, "release")?,
                false
            )?)),
            "witness-command" => Ok(json!(particleve::witness::command(&path(
                request, "variable"
            )?))),
            "witness-check-sandbox" => {
                particleve::witness::check_sandbox(&path(request, "variable")?)?;
                Ok(Value::Null)
            }
            "loader-path" => Ok(json!(particleve::bootloaders::loader_path(text(field(
                request, "sha256"
            )?)?)?)),
            "loader-ensure-fixed-entry" => {
                particleve::bootloaders::Loaders::new(&backend(request)?)
                    .ensure_fixed_entry(text(field(request, "role")?)?)?;
                Ok(Value::Null)
            }
            "quarantine-fixture" => {
                let fixture = QuarantineFixture {
                    linux: backend(request)?,
                    isolated: list(field(request, "isolated")?)?
                        .iter()
                        .map(|r| text(r).map(str::to_owned))
                        .collect::<Result<Vec<_>>>()?,
                };
                if let Some(version) = request.get("version") {
                    particleve::quarantine::reject(
                        &fixture,
                        text(version)?,
                        text(field(request, "fallback")?)?,
                    )?;
                } else {
                    particleve::quarantine::retry(&fixture)?;
                }
                particleve::quarantine::status(&fixture.linux.directory)
            }
            "loader-owned-entry" => Ok(json!(particleve::bootloaders::owned_entry(
                &path(request, "path")?,
                text(field(request, "sha256")?)?,
                text(field(request, "esp_uuid")?)?
            )?)),
            _ => return Ok(None),
        }?;
        Ok(Some(value))
    })()
    .transpose()
}
