//! Trial EFI loaders while retaining both independent, proven recovery paths.
use crate::{
    common::{
        self, Error, Result, atomic_write, field, hash_file, list, read_json, require, run, text,
        write_json,
    },
    linux::Linux,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub const FIXED: [&str; 2] = ["EFI/systemd/systemd-bootx64.efi", "EFI/BOOT/BOOTX64.EFI"];
const BLI: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const VARIABLES: &str = "/sys/firmware/efi/efivars";
pub fn loader_path(sha: &str) -> Result<String> {
    require(
        sha.len() == 64
            && sha
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid EFI loader hash",
    )?;
    Ok(format!("EFI/ParticleVE/loaders/{sha}.efi"))
}
fn decode16(data: &[u8]) -> Result<String> {
    require(data.len().is_multiple_of(2), "invalid UTF-16 EFI variable")?;
    String::from_utf16(
        &data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| Error::new("invalid UTF-16 EFI variable"))
}
pub fn executed_path() -> Result<String> {
    executed_path_at(Path::new(VARIABLES))
}
fn executed_path_at(variables: &Path) -> Result<String> {
    let data = common::read_bounded(
        variables.join(format!("LoaderImageIdentifier-{BLI}")),
        65536,
    )?;
    require(data.len() >= 4, "truncated loader image identifier")?;
    Ok(decode16(&data[4..])?
        .trim_end_matches('\0')
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_owned())
}
pub fn owned_entry(path: &Path, sha: &str, esp_uuid: &str) -> Result<bool> {
    let data = common::read_bounded(path, 65536)?;
    require(data.len() >= 12, "truncated EFI boot option")?;
    let end = (10..data.len() - 1)
        .step_by(2)
        .find(|i| data[*i..*i + 2] == [0, 0])
        .ok_or_else(|| Error::new("unterminated EFI boot option description"))?;
    let label = decode16(&data[10..end])?;
    let expected = format!("\\{}\0", loader_path(sha)?.replace('/', "\\"))
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let uuid = Uuid::parse_str(esp_uuid)
        .map_err(|_| Error::new("invalid ESP UUID"))?
        .to_bytes_le();
    let rest = &data[end + 2..];
    Ok(label == format!("ParticleVE trial {sha}")
        && rest.windows(expected.len()).any(|w| w == expected)
        && rest.windows(16).any(|w| w == uuid))
}
fn variable_paths(variables: &Path, prefix: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(variables)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            require(
                out.len() < 65536,
                "EFI variable inventory exceeds its bound",
            )?;
            out.push(entry.path());
        }
    }
    Ok(out)
}
fn boot_value(variables: &Path, name: &str) -> Result<u16> {
    let data = common::read_bounded(variables.join(format!("{name}-{GLOBAL}")), 65536)?;
    require(data.len() == 6, "invalid EFI boot selection")?;
    Ok(u16::from_le_bytes([data[4], data[5]]))
}
/// The native backend owns mounts and EFI commands; tests inject these exact mutable boundaries.
pub trait Backend {
    fn directory(&self) -> &Path;
    fn cache(&self) -> &Path;
    fn variables(&self) -> &Path {
        Path::new(VARIABLES)
    }
    fn disk(&self, role: &str) -> Result<Value>;
    fn current_esp_role(&self) -> Result<String>;
    fn boot_id(&self) -> Result<String>;
    fn with_esp<T>(&self, role: &str, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T>;
    fn command(&self, args: &[&str]) -> Result<common::Output> {
        run(args)
    }
    fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
        atomic_write(path, data, 0o600)
    }
}
impl Backend for Linux {
    fn directory(&self) -> &Path {
        &self.directory
    }
    fn cache(&self) -> &Path {
        &self.cache
    }
    fn disk(&self, role: &str) -> Result<Value> {
        Linux::disk(self, role)
    }
    fn current_esp_role(&self) -> Result<String> {
        Linux::current_esp_role(self)
    }
    fn boot_id(&self) -> Result<String> {
        Linux::boot_id(self)
    }
    fn with_esp<T>(&self, role: &str, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
        Linux::with_esp(self, role, operation)
    }
}
pub struct Loaders<'a, B: Backend = Linux> {
    backend: &'a B,
    directory: PathBuf,
    path: PathBuf,
}
impl<'a, B: Backend> Loaders<'a, B> {
    pub fn new(backend: &'a B) -> Self {
        let directory = backend.directory().join("bootloaders");
        let path = directory.join("state.json");
        Self {
            backend,
            directory,
            path,
        }
    }
    pub fn load(&self) -> Result<Value> {
        let state = read_json(&self.path)?;
        require(
            state.is_object() && state.get("schema") == Some(&json!(1)),
            "unknown bootloader state; owner recovery required",
        )?;
        loader_path(text(field(&state, "seed")?)?)?;
        for sha in list(field(&state, "rejected")?)? {
            loader_path(text(sha)?)?;
        }
        if !field(&state, "good")?.is_null() {
            loader_path(text(field(&state, "good")?)?)?;
        }
        if !field(&state, "trial")?.is_null() {
            let trial = field(&state, "trial")?;
            loader_path(text(field(trial, "sha256")?)?)?;
            let entry = text(field(trial, "entry")?)?;
            require(
                entry.len() == 4
                    && entry.bytes().all(|c| c.is_ascii_hexdigit())
                    && matches!(text(field(trial, "role")?)?, "a" | "b"),
                "invalid EFI trial identity",
            )?;
        }
        Ok(state)
    }
    pub fn seed(&self, release: &Value) -> Result<()> {
        require(!self.path.exists(), "bootloader state already exists")?;
        let item = field(field(release, "artifacts")?, "bootloader")?;
        let sha = text(field(item, "sha256")?)?;
        let data = fs::read(
            self.backend
                .cache()
                .join(text(field(release, "version")?)?)
                .join(text(field(item, "file")?)?),
        )?;
        self.backend
            .write(&self.directory.join(format!("{sha}.efi")), &data)?;
        write_json(
            &self.path,
            &json!({"schema":1,"good":null,"seed":sha,"trial":null,"rejected":[]}),
        )?;
        for role in ["a", "b"] {
            self.restore(role)?;
        }
        Ok(())
    }
    pub fn restore(&self, role: &str) -> Result<()> {
        let state = self.load()?;
        let sha = text(if field(&state, "good")?.is_null() {
            field(&state, "seed")?
        } else {
            field(&state, "good")?
        })?;
        let source = self.directory.join(format!("{sha}.efi"));
        require(
            hash_file(&source, None)? == sha,
            "retained EFI loader changed",
        )?;
        self.backend.with_esp(role, |esp| {
            for name in FIXED {
                let dest = esp.join(name);
                if dest.is_file() && hash_file(&dest, None)? == sha {
                    continue;
                }
                self.backend.write(&dest, &fs::read(&source)?)?;
                require(
                    hash_file(&dest, None)? == sha,
                    "EFI loader write verification failed",
                )?;
            }
            Ok(())
        })
    }
    pub fn prove(&self, esp: &Path) -> Result<()> {
        let state = self.load()?;
        let good = field(&state, "good")?;
        require(
            !good.is_null(),
            "no healthy boot has validated the installation loader",
        )?;
        for name in FIXED {
            let path = esp.join(name);
            require(
                path.is_file() && hash_file(path, None)? == text(good)?,
                "known-working EFI loader is unavailable",
            )?;
        }
        Ok(())
    }
    pub fn queue(&self, release: &Value) -> Result<()> {
        let mut state = self.load()?;
        let sha = text(field(
            field(field(release, "artifacts")?, "bootloader")?,
            "sha256",
        )?)?;
        if state["good"] == sha || list(field(&state, "rejected")?)?.contains(&json!(sha)) {
            return Ok(());
        }
        require(
            field(&state, "trial")?.is_null(),
            "an EFI loader trial requires reconciliation",
        )?;
        require(
            variable_paths(self.backend.variables(), "BootNext-")?.is_empty(),
            "another UEFI one-time boot is staged",
        )?;
        let role = self.backend.current_esp_role()?;
        let disk = self.backend.disk(&role)?;
        let esp_uuid = list(field(&disk, "partitions")?)?
            .iter()
            .find(|p| p["role"] == "esp")
            .ok_or_else(|| Error::new("missing ESP partition"))?["uuid"]
            .as_str()
            .ok_or_else(|| Error::new("invalid ESP UUID"))?;
        let label = format!("ParticleVE trial {sha}");
        let mut existing = Vec::new();
        let expression = regex::Regex::new(&format!(r"^Boot[0-9A-Fa-f]{{4}}-{GLOBAL}$"))
            .expect("constant expression");
        for path in variable_paths(self.backend.variables(), "Boot")? {
            if expression.is_match(&path.file_name().unwrap_or_default().to_string_lossy())
                && owned_entry(&path, sha, esp_uuid)?
            {
                existing.push(path);
            }
        }
        require(
            existing.len() <= 1,
            "duplicate EFI trial entries require owner reconciliation",
        )?;
        let entry = if let Some(path) = existing.first() {
            path.file_name()
                .ok_or_else(|| Error::new("invalid EFI trial path"))?
                .to_string_lossy()[4..8]
                .to_owned()
        } else {
            let out = self.backend.command(&[
                "efibootmgr",
                "--create-only",
                "--disk",
                text(field(&disk, "path")?)?,
                "--part",
                "1",
                "--label",
                &label,
                "--loader",
                &format!("\\{}", loader_path(sha)?.replace('/', "\\")),
            ])?;
            let expression = regex::Regex::new(&format!(
                r"(?m)^Boot([0-9A-Fa-f]{{4}})\*?\s+{}(?:\t|$)",
                regex::escape(&label)
            ))
            .map_err(|e| Error::new(e.to_string()))?;
            let matches = expression
                .captures_iter(&out.stdout)
                .map(|m| m[1].to_owned())
                .collect::<Vec<_>>();
            require(
                matches.len() == 1,
                "cannot identify the created EFI trial entry",
            )?;
            matches[0].clone()
        };
        state["trial"] = json!({"sha256":sha,"entry":entry,"role":role,"esp_uuid":esp_uuid,"boot_id":self.backend.boot_id()?});
        write_json(&self.path, &state)?;
        self.backend
            .command(&["efibootmgr", "--bootnext", &entry])?;
        Ok(())
    }
    pub fn cancel(&self) -> Result<()> {
        let mut state = self.load()?;
        if field(&state, "trial")?.is_null() {
            return Ok(());
        }
        let trial = field(&state, "trial")?;
        let entry = text(field(trial, "entry")?)?;
        let option = self
            .backend
            .variables()
            .join(format!("Boot{entry}-{GLOBAL}"));
        require(
            !option.exists()
                || owned_entry(
                    &option,
                    text(field(trial, "sha256")?)?,
                    text(field(trial, "esp_uuid")?)?,
                )?,
            "foreign EFI option replaced the loader trial",
        )?;
        if self
            .backend
            .variables()
            .join(format!("BootNext-{GLOBAL}"))
            .exists()
        {
            require(
                boot_value(self.backend.variables(), "BootNext")?
                    == u16::from_str_radix(entry, 16)
                        .map_err(|_| Error::new("invalid EFI trial entry"))?,
                "foreign BootNext replaced the EFI loader trial",
            )?;
            self.backend.command(&["efibootmgr", "--delete-bootnext"])?;
        }
        if option.exists() {
            self.backend
                .command(&["efibootmgr", "--bootnum", entry, "--delete-bootnum"])?;
        }
        state["trial"] = Value::Null;
        write_json(&self.path, &state)
    }
    pub fn bless(&self) -> Result<Value> {
        let mut state = self.load()?;
        let trial = field(&state, "trial")?.clone();
        let role = self.backend.current_esp_role()?;
        let actual = executed_path_at(self.backend.variables())?;
        if !trial.is_null() && trial["sha256"] == state["good"] {
            for target in ["a", "b"] {
                if target == role
                    || Path::new(text(field(&self.backend.disk(target)?, "path")?)?).exists()
                {
                    self.restore(target)?;
                }
            }
            self.cancel()?;
            return Ok(json!({"loader":"validated","sha256":state["good"]}));
        }
        let sha = if !trial.is_null() {
            require(
                text(field(&trial, "boot_id")?)? != self.backend.boot_id()?,
                "EFI loader trial has not rebooted",
            )?;
            let proven = boot_value(self.backend.variables(), "BootCurrent")?
                == u16::from_str_radix(text(field(&trial, "entry")?)?, 16)
                    .map_err(|_| Error::new("invalid EFI trial identity"))?
                && role == text(field(&trial, "role")?)?
                && actual.to_lowercase()
                    == loader_path(text(field(&trial, "sha256")?)?)?.to_lowercase();
            if !proven {
                let sha = field(&trial, "sha256")?.clone();
                if !list(field(&state, "rejected")?)?.contains(&sha) {
                    state["rejected"]
                        .as_array_mut()
                        .ok_or_else(|| Error::new("invalid loader rejection state"))?
                        .push(sha.clone());
                }
                write_json(&self.path, &state)?;
                self.cancel()?;
                return Ok(json!({"loader":"quarantined","sha256":sha}));
            }
            text(field(&trial, "sha256")?)?.to_owned()
        } else {
            let sha = text(if field(&state, "good")?.is_null() {
                field(&state, "seed")?
            } else {
                field(&state, "good")?
            })?
            .to_owned();
            require(
                FIXED.iter().any(|p| p.eq_ignore_ascii_case(&actual))
                    || loader_path(&sha)?.eq_ignore_ascii_case(&actual),
                "running loader path is not recorded",
            )?;
            sha
        };
        self.backend.with_esp(&role, |esp| {
            require(
                hash_file(esp.join(&actual), None)? == sha,
                "executed EFI loader does not match its recorded hash",
            )?;
            self.backend.write(
                &self.directory.join(format!("{sha}.efi")),
                &fs::read(esp.join(&actual))?,
            )
        })?;
        state["good"] = json!(sha);
        write_json(&self.path, &state)?;
        for target in ["a", "b"] {
            if target == role
                || Path::new(text(field(&self.backend.disk(target)?, "path")?)?).exists()
            {
                self.restore(target)?;
            }
        }
        self.cancel()?;
        Ok(json!({"loader":"validated","sha256":sha}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Fixture {
        root: tempfile::TempDir,
        boot: RefCell<String>,
        commands: RefCell<Vec<Vec<String>>>,
        fail: Cell<Option<usize>>,
        writes: Cell<usize>,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            for name in ["a", "b", "cache", "state", "efivars"] {
                fs::create_dir(root.path().join(name)).unwrap();
            }
            Self {
                root,
                boot: RefCell::new("old-boot".into()),
                commands: RefCell::new(Vec::new()),
                fail: Cell::new(None),
                writes: Cell::new(0),
            }
        }
        fn release(&self, version: &str) -> Value {
            let directory = self.cache().join(version);
            fs::create_dir_all(&directory).unwrap();
            let data = format!("signed-loader-{version}");
            fs::write(directory.join("loader.efi"), data).unwrap();
            let sha = hash_file(directory.join("loader.efi"), None).unwrap();
            json!({"version":version,"artifacts":{"bootloader":{"file":"loader.efi","sha256":sha}}})
        }
        fn hashes(&self) -> Vec<String> {
            ["a", "b"]
                .iter()
                .flat_map(|role| {
                    FIXED.iter().map(move |path| {
                        hash_file(self.root.path().join(role).join(path), None).unwrap()
                    })
                })
                .collect()
        }
        fn boot(&self, path: &str, entry: u16) {
            *self.boot.borrow_mut() = "new-boot".into();
            let mut data = vec![7, 0, 0, 0];
            data.extend(entry.to_le_bytes());
            fs::write(self.variables().join(format!("BootCurrent-{GLOBAL}")), data).unwrap();
            let mut data = vec![7, 0, 0, 0];
            data.extend(
                format!("\\{}\0", path.replace('/', "\\"))
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            );
            fs::write(
                self.variables()
                    .join(format!("LoaderImageIdentifier-{BLI}")),
                data,
            )
            .unwrap();
        }
        fn stage(&self, release: &Value) {
            let sha = release["artifacts"]["bootloader"]["sha256"]
                .as_str()
                .unwrap();
            for role in ["a", "b"] {
                let target = self.root.path().join(role).join(loader_path(sha).unwrap());
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                fs::copy(
                    self.cache()
                        .join(release["version"].as_str().unwrap())
                        .join("loader.efi"),
                    target,
                )
                .unwrap();
            }
        }
    }
    impl Backend for Fixture {
        fn directory(&self) -> &Path {
            self.root.path()
        }
        fn cache(&self) -> &Path {
            self.root.path()
        }
        fn variables(&self) -> &Path {
            self.root.path()
        }
        fn disk(&self, role: &str) -> Result<Value> {
            Ok(
                json!({"path":self.root.path().join(role),"partitions":[{"role":"esp","uuid":"54a2d82d-fb84-4a79-949d-a807c1392cda"}]}),
            )
        }
        fn current_esp_role(&self) -> Result<String> {
            Ok("a".into())
        }
        fn boot_id(&self) -> Result<String> {
            Ok(self.boot.borrow().clone())
        }
        fn with_esp<T>(&self, role: &str, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
            operation(&self.root.path().join(role))
        }
        fn command(&self, args: &[&str]) -> Result<common::Output> {
            self.commands
                .borrow_mut()
                .push(args.iter().map(|s| (*s).to_owned()).collect());
            let stdout = if args.contains(&"--create-only") {
                let label = args.iter().position(|s| *s == "--label").unwrap();
                format!("Boot00AF* {}\tHD(...)\n", args[label + 1])
            } else {
                String::new()
            };
            Ok(common::Output {
                code: 0,
                stdout,
                stderr: String::new(),
            })
        }
        fn write(&self, path: &Path, data: &[u8]) -> Result<()> {
            if FIXED.iter().any(|p| path.ends_with(p)) {
                let count = self.writes.get() + 1;
                self.writes.set(count);
                if self.fail.get() == Some(count) {
                    return Err(Error::new("power loss"));
                }
            }
            atomic_write(path, data, 0o600)
        }
    }
    fn setup(fixture: &Fixture) -> (Value, Value) {
        let old = fixture.release("45.0.1.1-1.1");
        let new = fixture.release("45.0.1.2-1.1");
        let loaders = Loaders::new(fixture);
        loaders.seed(&old).unwrap();
        let mut state = loaders.load().unwrap();
        state["good"] = state["seed"].clone();
        write_json(&loaders.path, &state).unwrap();
        fixture.stage(&new);
        (old, new)
    }
    #[test]
    fn preparation_and_broken_loader_fallback_preserve_all_working_paths() {
        let fixture = Fixture::new();
        let (_old, new) = setup(&fixture);
        let loaders = Loaders::new(&fixture);
        let before = fixture.hashes();
        loaders.queue(&new).unwrap();
        assert_eq!(fixture.hashes(), before);
        for role in ["a", "b"] {
            loaders.prove(&fixture.root.path().join(role)).unwrap();
        }
        assert!(fixture.commands.borrow()[0].contains(&"--create-only".to_owned()));
        assert_eq!(
            fixture.commands.borrow()[1],
            vec!["efibootmgr", "--bootnext", "00AF"]
        );
        fixture.boot(FIXED[0], 1);
        let report = loaders.bless().unwrap();
        assert_eq!(report["loader"], "quarantined");
        assert_eq!(fixture.hashes(), before);
        let state = loaders.load().unwrap();
        assert!(
            state["rejected"]
                .as_array()
                .unwrap()
                .contains(&new["artifacts"]["bootloader"]["sha256"])
        );
        let commands = fixture.commands.borrow().len();
        loaders.queue(&new).unwrap();
        assert_eq!(fixture.commands.borrow().len(), commands);
    }
    #[test]
    fn every_promotion_interruption_leaves_a_reachable_working_loader() {
        for boundary in 1..=4 {
            let fixture = Fixture::new();
            let (old, new) = setup(&fixture);
            let loaders = Loaders::new(&fixture);
            loaders.queue(&new).unwrap();
            let old_sha = old["artifacts"]["bootloader"]["sha256"].as_str().unwrap();
            let new_sha = new["artifacts"]["bootloader"]["sha256"].as_str().unwrap();
            fixture.boot(&loader_path(new_sha).unwrap(), 0xaf);
            fixture.writes.set(0);
            fixture.fail.set(Some(boundary));
            assert!(
                loaders
                    .bless()
                    .unwrap_err()
                    .to_string()
                    .contains("power loss")
            );
            let hashes = fixture.hashes();
            assert!(hashes.iter().all(|h| h == old_sha || h == new_sha));
            assert!(hashes.iter().any(|h| h == old_sha));
            assert_eq!(loaders.load().unwrap()["good"], new_sha);
            fixture.fail.set(None);
            assert_eq!(loaders.bless().unwrap()["loader"], "validated");
            assert!(fixture.hashes().iter().all(|h| h == new_sha));
            assert!(loaders.load().unwrap()["trial"].is_null());
        }
    }
    #[test]
    fn modified_candidate_cannot_replace_the_fixed_paths() {
        let fixture = Fixture::new();
        let (_old, new) = setup(&fixture);
        let loaders = Loaders::new(&fixture);
        loaders.queue(&new).unwrap();
        let sha = new["artifacts"]["bootloader"]["sha256"].as_str().unwrap();
        let path = loader_path(sha).unwrap();
        fixture.boot(&path, 0xaf);
        fs::write(fixture.root.path().join("a").join(path), b"corrupted").unwrap();
        let before = fixture.hashes();
        assert!(
            loaders
                .bless()
                .unwrap_err()
                .to_string()
                .contains("recorded hash")
        );
        assert_eq!(fixture.hashes(), before);
    }
    #[test]
    fn foreign_bootnext_cannot_be_cleared() {
        let fixture = Fixture::new();
        let (_old, new) = setup(&fixture);
        let loaders = Loaders::new(&fixture);
        loaders.queue(&new).unwrap();
        fs::write(
            fixture.variables().join(format!("BootNext-{GLOBAL}")),
            [7, 0, 0, 0, 0x12, 0],
        )
        .unwrap();
        let commands = fixture.commands.borrow().len();
        assert!(
            loaders
                .cancel()
                .unwrap_err()
                .to_string()
                .contains("foreign BootNext")
        );
        assert_eq!(fixture.commands.borrow().len(), commands);
    }
    #[test]
    fn boot_option_ownership_checks_description_esp_and_loader_path() {
        let dir = tempfile::tempdir().unwrap();
        let option = dir.path().join("Boot00AF");
        let sha = "a".repeat(64);
        let esp = Uuid::new_v4();
        let mut data = vec![7, 0, 0, 0, 1, 0, 0, 0, 0, 0];
        data.extend(
            format!("ParticleVE trial {sha}\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        data.extend(esp.to_bytes_le());
        data.extend(
            format!("\\{}\0", loader_path(&sha).unwrap().replace('/', "\\"))
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        fs::write(&option, data).unwrap();
        assert!(owned_entry(&option, &sha, &esp.to_string()).unwrap());
        assert!(!owned_entry(&option, &sha, &Uuid::new_v4().to_string()).unwrap());
        assert!(!owned_entry(&option, &"b".repeat(64), &esp.to_string()).unwrap());
        fs::write(&option, [0; 11]).unwrap();
        assert!(owned_entry(&option, &sha, &esp.to_string()).is_err());
    }
}
