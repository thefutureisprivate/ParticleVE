//! Durable per-ESP rejected-image work, independent of storage-member absence.
use crate::{
    bootloaders,
    common::{Result, field, read_json, require, text, write_json},
    linux::Linux,
};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub trait Backend: bootloaders::Backend {
    fn isolated(&self, role: &str) -> Result<bool>;
    fn fallback(&self, esp: &Path, version: &str) -> Result<()>;
    fn verify_fallback(&self, esp: &Path, version: &str) -> Result<()>;
}
fn load(path: &Path) -> Result<Value> {
    let record = read_json(path)?;
    require(
        crate::common::object(&record)?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == ["schema", "version", "fallback", "roles"]
                .into_iter()
                .collect(),
        "unknown ESP quarantine fields",
    )?;
    require(record["schema"] == 1, "unknown ESP quarantine journal")?;
    for name in ["version", "fallback"] {
        crate::config::version_key(text(field(&record, name)?)?)?;
    }
    require(
        record["version"] != record["fallback"],
        "cannot quarantine the fallback OS",
    )?;
    let roles = crate::common::object(field(&record, "roles")?)?;
    require(
        roles.len() == 2 && roles.contains_key("a") && roles.contains_key("b"),
        "incomplete ESP quarantine roles",
    )?;
    for value in roles.values() {
        let fields = crate::common::object(value)?;
        let status = text(field(value, "status")?)?;
        require(
            matches!(status, "pending" | "verified" | "isolated" | "failed"),
            "unknown ESP quarantine status",
        )?;
        require(
            fields.len() == if status == "failed" { 2 } else { 1 },
            "unknown ESP quarantine progress fields",
        )?;
        if status == "failed" {
            require(
                text(field(value, "detail")?)?.chars().count() <= 512,
                "oversized ESP quarantine detail",
            )?;
        }
    }
    Ok(record)
}
pub fn status(directory: &Path) -> Result<Value> {
    let path = directory.join("quarantine.json");
    if path.try_exists()? {
        load(&path)
    } else {
        Ok(Value::Null)
    }
}
pub fn reject(backend: &impl Backend, version: &str, fallback: &str) -> Result<()> {
    crate::config::version_key(version)?;
    crate::config::version_key(fallback)?;
    require(
        version != fallback,
        "cannot quarantine the running fallback",
    )?;
    let path = backend.directory().join("quarantine.json");
    let mut record = if path.try_exists()? {
        load(&path)?
    } else {
        json!({"schema":1,"version":version,"fallback":fallback,"roles":{"a":{"status":"pending"},"b":{"status":"pending"}}})
    };
    require(
        record["version"] == version,
        "another ESP quarantine needs reconciliation first",
    )?;
    record["fallback"] = json!(fallback);
    write_json(&path, &record)?;
    retry(backend)
}
pub fn retry(backend: &impl Backend) -> Result<()> {
    let path = backend.directory().join("quarantine.json");
    if !path.try_exists()? {
        return Ok(());
    }
    let mut record = load(&path)?;
    let version = text(field(&record, "version")?)?.to_owned();
    let fallback = text(field(&record, "fallback")?)?.to_owned();
    let mut failures = Vec::new();
    for role in ["a", "b"] {
        let result: Result<&str> = (|| {
            if backend.isolated(role)? {
                return Ok("isolated");
            }
            backend.with_esp(role, |esp| {
                backend.fallback(esp, &fallback)?;
                for (entry, _) in Linux::boot_entries(esp, &version)? {
                    fs::rename(&entry, entry.with_extension("rejected"))?;
                }
                fs::File::open(esp.join("EFI/Linux"))?.sync_all()?;
                require(
                    Linux::boot_entries(esp, &version)?.is_empty(),
                    "rejected UKI is still exposed",
                )?;
                // Verify the default after all file mutations, not just before them.
                backend.verify_fallback(esp, &fallback)
            })?;
            Ok("verified")
        })();
        match result {
            Ok(status) => record["roles"][role] = json!({"status":status}),
            Err(error) => {
                let detail = error.to_string().chars().take(512).collect::<String>();
                record["roles"][role] = json!({"status":"failed","detail":detail});
                failures.push(format!("{role}: {detail}"));
            }
        }
        write_json(&path, &record)?;
    }
    require(
        failures.is_empty(),
        format!("ESP quarantine incomplete: {}", failures.join("; ")),
    )?;
    if ["a", "b"]
        .iter()
        .all(|role| record["roles"][role]["status"] == "verified")
    {
        fs::remove_file(&path)?;
        fs::File::open(backend.directory())?.sync_all()?;
    }
    Ok(())
}
impl Backend for Linux {
    fn isolated(&self, role: &str) -> Result<bool> {
        let disk = self.disk(role)?;
        if Path::new(text(field(&disk, "path")?)?).try_exists()? {
            return Ok(false);
        }
        let witness = crate::admission::verify_manifest(&self.manifest, None)?;
        require(
            !crate::common::list(field(&witness, "allowed")?)?.contains(&json!(role)),
            "absent disk is not storage-quarantined",
        )?;
        Ok(true)
    }
    fn fallback(&self, esp: &Path, version: &str) -> Result<()> {
        fallback_artifacts(self, esp, version)?;
        self.default(esp, Some(version))?;
        self.verify_default(esp, version)
    }
    fn verify_fallback(&self, esp: &Path, version: &str) -> Result<()> {
        fallback_artifacts(self, esp, version)?;
        self.verify_default(esp, version)
    }
}
fn fallback_artifacts(backend: &Linux, esp: &Path, version: &str) -> Result<()> {
    let release = backend.local_release(version)?;
    let entries = Linux::boot_entries(esp, version)?;
    require(
        entries.len() == 1 && entries[0].1 != Some(0),
        "missing or exhausted fallback UKI",
    )?;
    require(
        crate::common::hash_file(&entries[0].0, None)?
            == text(&release["artifacts"]["uki"]["sha256"])?,
        "fallback UKI failed quarantine readback",
    )?;
    bootloaders::Loaders::new(backend).prove(esp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, path::PathBuf};
    const GOOD: &str = "45.0.3.4-1.4";
    const BAD: &str = "45.0.3.5-0.0";
    struct Fixture {
        root: tempfile::TempDir,
        failed: Cell<bool>,
        isolated: Cell<bool>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            for role in ["a", "b"] {
                let linux = root.path().join(role).join("EFI/Linux");
                fs::create_dir_all(&linux).unwrap();
                fs::write(linux.join(format!("ParticleVE_{GOOD}_x86-64.efi")), b"good").unwrap();
                fs::write(linux.join(format!("ParticleVE_{BAD}_x86-64+0.efi")), b"bad").unwrap();
                fs::create_dir_all(root.path().join(role).join("loader")).unwrap();
            }
            Self {
                root,
                failed: Cell::new(false),
                isolated: Cell::new(false),
            }
        }
        fn journal(&self) -> PathBuf {
            self.root.path().join("quarantine.json")
        }
    }
    impl bootloaders::Backend for Fixture {
        fn directory(&self) -> &Path {
            self.root.path()
        }
        fn cache(&self) -> &Path {
            self.root.path()
        }
        fn disk(&self, role: &str) -> Result<Value> {
            Ok(json!({"path":self.root.path().join(role)}))
        }
        fn current_esp_role(&self) -> Result<String> {
            Ok("a".into())
        }
        fn boot_id(&self) -> Result<String> {
            Ok("fixture".into())
        }
        fn with_esp<T>(&self, role: &str, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
            require(
                !(role == "b" && self.failed.get()),
                "ESP is present but unwritable",
            )?;
            operation(&self.root.path().join(role))
        }
    }
    impl Backend for Fixture {
        fn isolated(&self, role: &str) -> Result<bool> {
            Ok(role == "b" && self.isolated.get())
        }
        fn fallback(&self, esp: &Path, version: &str) -> Result<()> {
            crate::common::atomic_write(esp.join("loader/loader.conf"), version.as_bytes(), 0o600)?;
            self.verify_fallback(esp, version)
        }
        fn verify_fallback(&self, esp: &Path, version: &str) -> Result<()> {
            require(
                fs::read_to_string(esp.join("loader/loader.conf"))? == version,
                "wrong default",
            )
        }
    }
    #[test]
    fn present_failed_esp_is_durable_and_both_roles_are_verified_on_retry() {
        let fixture = Fixture::new();
        fixture.failed.set(true);
        assert!(reject(&fixture, BAD, GOOD).is_err());
        let journal = read_json(fixture.journal()).unwrap();
        assert_eq!(journal["roles"]["a"]["status"], "verified");
        assert_eq!(journal["roles"]["b"]["status"], "failed");
        assert!(
            Linux::boot_entries(&fixture.root.path().join("a"), BAD)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            Linux::boot_entries(&fixture.root.path().join("b"), BAD)
                .unwrap()
                .len(),
            1
        );
        fixture.failed.set(false);
        retry(&fixture).unwrap();
        assert!(!fixture.journal().exists());
        assert!(
            Linux::boot_entries(&fixture.root.path().join("b"), BAD)
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn isolated_member_retains_its_esp_obligation_until_it_is_reachable() {
        let fixture = Fixture::new();
        fixture.isolated.set(true);
        reject(&fixture, BAD, GOOD).unwrap();
        assert_eq!(
            read_json(fixture.journal()).unwrap()["roles"]["b"]["status"],
            "isolated"
        );
        fixture.isolated.set(false);
        fixture.failed.set(true);
        assert!(retry(&fixture).is_err());
        assert!(fixture.journal().exists());
        fixture.failed.set(false);
        retry(&fixture).unwrap();
        assert!(!fixture.journal().exists());
    }
}
