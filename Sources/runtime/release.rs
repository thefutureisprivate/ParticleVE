//! Authenticated immutable image releases and explicit native transfers.
use crate::common::{
    Error, Result, command, digest, field, hash_file, list, object, parse_json, read_json, require,
    text, uint,
};
use crate::config::{VERITY_SIGNATURE_SIZE, https_url, integer, version_key};
use regex::Regex;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    io::{Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};
pub const KINDS: [&str; 6] = [
    "usr",
    "verity",
    "verity_sig",
    "uki",
    "bootloader",
    "fwupd_efi",
];
fn matches(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).is_ok_and(|r| r.is_match(value))
}
pub fn validate(manifest: &Value) -> Result<Value> {
    require(manifest["schema"] == 1, "release schema must be 1")?;
    require(
        manifest["architecture"] == "x86-64",
        "release architecture mismatch",
    )?;
    require(
        manifest["cpu_baseline"] == "x86-64-v2",
        "release CPU baseline mismatch",
    )?;
    let version = version_key(text(field(manifest, "version")?)?)?;
    require(manifest["fedora"] == "45", "release must be Fedora 45")?;
    require(
        version[0].to_string() == text(field(manifest, "fedora")?)?,
        "release version and Fedora base differ",
    )?;
    require(
        !object(field(manifest, "persistent_state")?)?.is_empty(),
        "declare the retained-OS filesystem and VM auxiliary-state contract",
    )?;
    if let Some(identity) = manifest.get("implementation_sha256") {
        require(
            matches(r"^[0-9a-f]{64}$", text(identity)?),
            "invalid implementation content identity",
        )?;
    }
    let root_hash = text(field(manifest, "usr_root_hash")?)?;
    require(
        matches(r"^[0-9a-f]{64}$", root_hash),
        "invalid usr verity root hash",
    )?;
    for revision in ["particleos", "mkosi"] {
        require(
            matches(
                r"^[0-9a-f]{40}$",
                text(field(field(manifest, "sources")?, revision)?)?,
            ),
            format!("unresolved source pin: {revision}"),
        )?;
    }
    let artifacts = object(field(manifest, "artifacts")?)?;
    require(
        artifacts.len() == KINDS.len() && KINDS.iter().all(|k| artifacts.contains_key(*k)),
        "incomplete artifact set",
    )?;
    let mut names = BTreeSet::new();
    for kind in KINDS {
        let item = &artifacts[kind];
        let name = text(field(item, "file")?)?;
        require(
            matches(r"^[A-Za-z0-9_.+-]+$", name) && !name.starts_with('.'),
            "artifact names must be plain filenames",
        )?;
        require(names.insert(name), "duplicate artifact filenames")?;
        require(
            matches(r"^[0-9a-f]{64}$", text(field(item, "sha256")?)?),
            "invalid artifact hash",
        )?;
        let size = integer(field(item, "size")?, 1, &format!("{kind} size"))?;
        if kind == "verity_sig" {
            require(
                size == VERITY_SIGNATURE_SIZE,
                "signature payload must completely cover its fixed 1 MiB partition",
            )?;
        }
        if matches!(kind, "usr" | "verity" | "verity_sig") {
            let identity = text(field(item, "partition_uuid")?)?;
            require(
                uuid::Uuid::parse_str(identity).is_ok_and(|v| v.to_string() == identity),
                "invalid partition UUID",
            )?;
        }
    }
    for (kind, hash) in [("usr", &root_hash[..32]), ("verity", &root_hash[32..])] {
        let identity = uuid::Uuid::parse_str(text(field(&artifacts[kind], "partition_uuid")?)?)
            .map_err(|e| Error::new(e.to_string()))?;
        require(
            identity.simple().to_string() == hash,
            format!("{kind} UUID does not match verity root hash"),
        )?;
    }
    Ok(manifest.clone())
}
fn invoke(args: Vec<String>) -> Result<crate::common::Output> {
    command(
        &args,
        None,
        Some(Duration::from_secs(120)),
        8 * 1024 * 1024,
        true,
    )
}
pub fn checksums(directory: &Path, keyring: &Path) -> Result<BTreeMap<String, String>> {
    invoke(vec![
        "gpgv".into(),
        "--keyring".into(),
        keyring.display().to_string(),
        directory.join("SHA256SUMS.asc").display().to_string(),
        directory.join("SHA256SUMS").display().to_string(),
    ])?;
    let re = Regex::new(r"^([0-9a-f]{64}) [ *](?:\./)?([A-Za-z0-9_+.-]+)$")
        .map_err(|e| Error::new(e.to_string()))?;
    let mut index = BTreeMap::new();
    let data = crate::common::read_bounded(directory.join("SHA256SUMS"), 8 * 1024 * 1024)?;
    for line in std::str::from_utf8(&data)
        .map_err(|e| Error::new(e.to_string()))?
        .lines()
    {
        let captures = re
            .captures(line)
            .ok_or_else(|| Error::new("unsafe signed checksum entry"))?;
        require(
            !captures[2].starts_with('.'),
            "unsafe signed checksum entry",
        )?;
        require(
            index
                .insert(captures[2].into(), captures[1].into())
                .is_none(),
            "duplicate signed checksum entry",
        )?;
    }
    require(!index.is_empty(), "signed feed index is empty")?;
    Ok(index)
}
pub fn verify_directory(
    directory: &Path,
    keyring: &Path,
    certificate: &Path,
    artifacts: bool,
) -> Result<Value> {
    let index = checksums(directory, keyring)?;
    let files = fs::read_dir(directory)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| {
            p.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                s.starts_with("ParticleVE_") && s.ends_with("_x86-64.release.json")
            })
        })
        .collect::<Vec<_>>();
    require(
        files.len() == 1,
        "select exactly one authenticated release manifest",
    )?;
    let metadata = &files[0];
    let name = metadata
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::new("invalid release filename"))?;
    require(
        index.get(name) == Some(&hash_file(metadata, None)?),
        "release metadata hash mismatch",
    )?;
    let manifest = validate(&read_json(metadata)?)?;
    require(
        name == format!(
            "ParticleVE_{}_x86-64.release.json",
            text(field(&manifest, "version")?)?
        ),
        "release metadata identity mismatch",
    )?;
    for (kind, item) in object(field(&manifest, "artifacts")?)? {
        let name = text(field(item, "file")?)?;
        require(
            index.get(name).map(String::as_str) == Some(text(field(item, "sha256")?)?),
            "release artifact missing from signed OBS index",
        )?;
        if artifacts {
            let path = directory.join(name);
            require(
                path.is_file() && !path.is_symlink(),
                format!("artifact missing: {}", path.display()),
            )?;
            require(
                fs::metadata(&path)?.len() == uint(field(item, "size")?)?
                    && hash_file(&path, None)? == text(field(item, "sha256")?)?,
                format!("artifact hash/size mismatch: {kind}"),
            )?;
            if matches!(kind.as_str(), "uki" | "bootloader" | "fwupd_efi") {
                invoke(vec![
                    "sbverify".into(),
                    "--cert".into(),
                    certificate.display().to_string(),
                    path.display().to_string(),
                ])?;
            }
        }
    }
    if artifacts {
        inspect_uki(
            &directory.join(text(&manifest["artifacts"]["uki"]["file"])?),
            &manifest,
        )?;
    }
    Ok(manifest)
}
fn section(value: &Value) -> Result<String> {
    Ok(text(field(value, "text")?)?
        .trim_matches(['\0', ' ', '\n'])
        .into())
}
fn assignments(data: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    let mut words = Vec::new();
    for c in data.chars() {
        if escaped {
            // shlex preserves non-quote/backslash escapes inside double quotes.
            if quote == Some('"') && !matches!(c, '"' | '\\') {
                current.push('\\');
            }
            current.push(c);
            escaped = false;
        } else if c == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if quote.is_none() && matches!(c, ' ' | '\t' | '\r' | '\n') {
            if started {
                words.push(std::mem::take(&mut current));
                started = false;
            }
        } else {
            current.push(c);
            started = true;
        }
    }
    require(quote.is_none() && !escaped, "invalid UKI profile metadata")?;
    if started {
        words.push(current);
    }
    for word in words {
        let (key, value) = word
            .split_once('=')
            .ok_or_else(|| Error::new("invalid UKI profile metadata"))?;
        require(
            result.insert(key.into(), value.into()).is_none(),
            "duplicate UKI profile metadata",
        )?;
    }
    Ok(result)
}
pub fn inspect_uki(path: &Path, manifest: &Value) -> Result<()> {
    let response = invoke(vec![
        "/usr/lib/systemd/ukify".into(),
        "--json=short".into(),
        "inspect".into(),
        path.display().to_string(),
    ])?;
    require(
        response.stderr.trim().is_empty(),
        "UKI inspection produced diagnostics",
    )?;
    let sections = parse_json(response.stdout.as_bytes())?;
    verify_uki_sections(&sections, manifest)
}
pub fn verify_uki_sections(sections: &Value, manifest: &Value) -> Result<()> {
    let version = version_key(text(field(manifest, "version")?)?)?;
    let binding = manifest.get("kernel_verification");
    if let Some(value) = binding {
        require(
            value.is_object(),
            "UKI kernel source binding is missing or invalid",
        )?;
    }
    // Retained pre-adoption images have driver-only kernel metadata. New
    // source releases must bind the UKI to the verified kernel package.
    if [version[0], version[1], version[2], version[3]] >= [45, 0, 3, 0]
        || binding.is_some_and(|v| v.get("kernel_pe_sha256").is_some())
    {
        let binding = field(manifest, "kernel_verification")?;
        for key in ["kernel_pe_sha256", "source_sha256"] {
            require(
                binding[key]
                    .as_str()
                    .is_some_and(|v| matches(r"^[0-9a-f]{64}$", v)),
                "UKI kernel source binding is missing or invalid",
            )?;
        }
        require(
            field(field(sections, ".linux")?, "sha256")? == field(binding, "kernel_pe_sha256")?,
            "UKI kernel differs from the verified kernel package",
        )?;
        let kernel = text(field(binding, "kernel")?)?;
        require(
            matches(r"^[A-Za-z0-9_+.-]+\.x86_64$", kernel)
                && section(field(sections, ".uname")?)? == kernel,
            "UKI kernel release differs from the verified module tree",
        )?;
    }
    if [version[0], version[1], version[2], version[3]] >= [45, 0, 3, 0]
        || binding.is_some_and(|v| v.get("initrd").is_some())
    {
        let binding = field(manifest, "kernel_verification")?;
        let initrd = field(binding, "initrd")?;
        let values = object(initrd)?;
        require(
            values.len() == 4
                && ["kernel", "sha256", "module_files", "security_files"]
                    .iter()
                    .all(|name| values.contains_key(*name))
                && matches(r"^[0-9a-f]{64}$", text(field(initrd, "sha256")?)?)
                && field(initrd, "kernel")? == field(binding, "kernel")?
                && (1..=16384).contains(&uint(field(initrd, "module_files")?)?)
                && (1..=128).contains(&uint(field(initrd, "security_files")?)?)
                && field(field(sections, ".initrd")?, "sha256")? == field(initrd, "sha256")?,
            "UKI initrd differs from the verified early-boot payload",
        )?;
    }
    let osrel = section(field(sections, ".osrel")?)?;
    let values = osrel
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<BTreeMap<_, _>>();
    require(
        values
            .get("IMAGE_ID")
            .is_some_and(|v| v.trim_matches('"') == "ParticleVE"),
        "UKI image identity mismatch",
    )?;
    require(
        values
            .get("IMAGE_VERSION")
            .is_some_and(|v| v.trim_matches('"') == manifest["version"].as_str().unwrap_or("")),
        "UKI version mismatch",
    )?;
    let cmdline = section(field(sections, ".cmdline")?)?;
    let words = cmdline.split_whitespace().collect::<Vec<_>>();
    for expected in [
        format!("usrhash={}", text(field(manifest, "usr_root_hash")?)?),
        "audit=1".into(),
        "enforcing=1".into(),
        "zswap.enabled=1".into(),
        "systemd.ssh_auto=no".into(),
        "kvm_intel.nested=0".into(),
        "kvm_amd.nested=0".into(),
        "rfkill.default_state=0".into(),
    ] {
        let key = expected.split('=').next().unwrap_or("");
        require(
            words
                .iter()
                .filter(|v| v.split('=').next() == Some(key))
                .copied()
                .collect::<Vec<_>>()
                == [expected.as_str()],
            format!("UKI security command line differs: {key}"),
        )?;
    }
    require(
        words
            .iter()
            .filter(|v| v.starts_with("console="))
            .copied()
            .collect::<Vec<_>>()
            == ["console=tty0"],
        "base UKI recovery console differs",
    )?;
    let mut expected_profiles = vec![serde_json::json!({"ID":"main"})];
    expected_profiles.extend(
        crate::consoles::uki_profiles()
            .into_iter()
            .map(|v| v["Profile"].clone()),
    );
    let profiles = list(field(sections, "_profiles")?)?;
    require(
        profiles.len() == expected_profiles.len(),
        "UKI console profiles differ",
    )?;
    let mut policies = BTreeSet::new();
    for (index, (profile, expected)) in profiles.iter().zip(expected_profiles).enumerate() {
        let map = object(profile)?;
        require(
            map.len() == if index == 0 { 2 } else { 3 }
                && map.contains_key(".profile")
                && map.contains_key(".pcrsig")
                && (index == 0 || map.contains_key(".cmdline")),
            "unexpected UKI profile override or missing PCR signature",
        )?;
        let metadata = assignments(&section(field(profile, ".profile")?)?)?;
        let expected_map = object(&expected)?
            .iter()
            .map(|(k, v)| Ok((k.clone(), text(v)?.to_owned())))
            .collect::<Result<BTreeMap<_, _>>>()?;
        require(
            metadata == expected_map,
            "UKI profile identity/order differs",
        )?;
        if index > 0 {
            let selected = crate::consoles::serial_consoles()
                .into_iter()
                .find(|(id, _)| Some(id.as_str()) == expected["ID"].as_str())
                .ok_or_else(|| Error::new("unknown UKI profile"))?
                .1;
            let mut expected_words = words.clone();
            expected_words.push(&selected);
            let actual = section(field(profile, ".cmdline")?)?;
            require(
                actual.split_whitespace().collect::<Vec<_>>() == expected_words,
                "UKI console profile changes other kernel arguments",
            )?;
        }
        let signature = parse_json(section(field(profile, ".pcrsig")?)?.as_bytes())?;
        require(
            object(&signature)?.len() == 1 && signature.get("sha256").is_some(),
            "UKI lacks SHA256 PCR authorization",
        )?;
        let entries = list(field(&signature, "sha256")?)?;
        require(!entries.is_empty(), "UKI lacks SHA256 PCR authorization")?;
        for entry in entries {
            let sig = text(field(entry, "sig")?)?;
            require(
                list(field(entry, "pcrs")?)?.contains(&Value::from(11))
                    && matches(r"^[0-9a-f]{64}$", text(field(entry, "pol")?)?)
                    && matches(r"^[0-9a-f]{64}$", text(field(entry, "pkfp")?)?)
                    && sig.len() == 684
                    && matches(r"^[A-Za-z0-9+/]{683}=$", sig),
                "UKI profile lacks a complete RSA4096 PCR signature",
            )?;
            require(
                entry
                    .get("ref")
                    .is_none_or(|reference| !reference.is_array() && !reference.is_object()),
                "invalid UKI PCR policy reference",
            )?;
            require(
                policies.insert((
                    text(field(entry, "pol")?)?.to_owned(),
                    entry
                        .get("ref")
                        .filter(|value| !value.is_null())
                        .map(|v| v.to_string()),
                )),
                "UKI profiles reuse a PCR policy",
            )?;
        }
    }
    Ok(())
}
/// The Fedora trust extraction owns all HTTPS trust; no per-tool or environment CA override.
pub fn tls_config() -> Result<ureq::tls::TlsConfig> {
    let data = crate::common::read_bounded(
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        2 * 1024 * 1024,
    )?;
    tls_config_from_pem(&data)
}
pub(crate) fn tls_config_from_pem(data: &[u8]) -> Result<ureq::tls::TlsConfig> {
    let mut certificates = Vec::new();
    let mut roots = rustls::RootCertStore::empty();
    for item in ureq::tls::parse_pem(data) {
        let cert = match item.map_err(|error| Error::new(error.to_string()))? {
            ureq::tls::PemItem::Certificate(cert) => cert,
            _ => return Err(Error::new("unexpected item in system certificate store")),
        };
        roots
            .add(rustls::pki_types::CertificateDer::from(cert.der().to_vec()))
            .map_err(|error| Error::new(format!("invalid system certificate store: {error}")))?;
        certificates.push(cert);
    }
    require(
        !certificates.is_empty(),
        "empty system TLS certificate trust",
    )?;
    Ok(ureq::tls::TlsConfig::builder()
        .unversioned_rustls_crypto_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .root_certs(ureq::tls::RootCerts::new_with_certs(&certificates))
        .build())
}
pub fn download(url: &str, destination: &Path, size_limit: u64) -> Result<()> {
    let mut url = https_url(url)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
        // Bound each socket operation, while streaming multi-gigabyte resources
        // without treating a normal slow transfer as a sixty-second whole-file deadline.
        .timeout_resolve(Some(Duration::from_secs(60)))
        .timeout_connect(Some(Duration::from_secs(60)))
        .timeout_per_read(Some(Duration::from_secs(60)))
        .timeout_per_write(Some(Duration::from_secs(60)))
        .tls_config(tls_config()?)
        .build()
        .into();
    let mut redirected = 0;
    let mut response = loop {
        let response = agent
            .get(&url)
            .call()
            .map_err(|e| Error::new(format!("download failed: {url}: {e}")))?;
        if response.status().is_redirection() {
            require(redirected < 10, "too many release redirects")?;
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Error::new("release redirect lacks location"))?;
            let next = url::Url::parse(&url)
                .map_err(|e| Error::new(e.to_string()))?
                .join(location)
                .map_err(|e| Error::new(e.to_string()))?;
            url = https_url(next.as_str())?;
            redirected += 1;
        } else {
            require(
                response.status().is_success(),
                format!("download failed: {url}: HTTP {}", response.status()),
            )?;
            break response;
        }
    };
    let parent = destination
        .parent()
        .ok_or_else(|| Error::new("download destination lacks parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut received = 0u64;
    let mut buffer = [0u8; 1024 * 1024];
    let mut reader = response.body_mut().as_reader();
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        received = received
            .checked_add(n as u64)
            .ok_or_else(|| Error::new("download size overflow"))?;
        require(received <= size_limit, format!("download too large: {url}"))?;
        temporary.write_all(&buffer[..n])?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|e| Error::new(e.to_string()))?;
    Ok(())
}
pub fn fetch(
    feed: &str,
    cache: &Path,
    keyring: &Path,
    certificate: &Path,
    version: Option<&str>,
) -> Result<(PathBuf, Value)> {
    let feed = https_url(feed)?;
    fs::create_dir_all(cache)?;
    let temporary = tempfile::tempdir_in(cache)?;
    let directory = temporary.path();
    if let Some(version) = version {
        version_key(version)?;
    }
    for name in ["SHA256SUMS", "SHA256SUMS.asc"] {
        download(
            &format!("{feed}/{name}"),
            &directory.join(name),
            8 * 1024 * 1024,
        )?;
    }
    let index = checksums(directory, keyring)?;
    let re = Regex::new(r"^ParticleVE_([0-9.-]+)_x86-64\.release\.json$")
        .map_err(|e| Error::new(e.to_string()))?;
    let mut available = BTreeMap::new();
    for name in index.keys() {
        if let Some(m) = re.captures(name) {
            version_key(&m[1])?;
            available.insert(m[1].to_owned(), name.to_owned());
        }
    }
    require(
        !available.is_empty() && version.is_none_or(|v| available.contains_key(v)),
        "requested complete release is not published",
    )?;
    let chosen = if let Some(v) = version {
        v.to_owned()
    } else {
        available
            .keys()
            .max_by_key(|v| version_key(v).unwrap_or([0; 6]))
            .ok_or_else(|| Error::new("no published release"))?
            .clone()
    };
    let filename = &available[&chosen];
    download(
        &format!("{feed}/{filename}"),
        &directory.join(filename),
        2 * 1024 * 1024,
    )?;
    let manifest = verify_directory(directory, keyring, certificate, false)?;
    require(
        manifest["version"] == chosen,
        "feed returned a different release",
    )?;
    let target = cache.join(chosen);
    let replacing = target.exists();
    if replacing {
        let old = verify_directory(&target, keyring, certificate, false)?;
        require(
            digest(&old)? == digest(&manifest)?,
            "immutable release changed in the feed",
        )?;
        for item in object(field(&manifest, "artifacts")?)?.values() {
            let name = text(field(item, "file")?)?;
            let candidate = target.join(name);
            if candidate.is_file()
                && fs::metadata(&candidate)?.len() == uint(field(item, "size")?)?
                && hash_file(&candidate, None)? == text(field(item, "sha256")?)?
            {
                fs::copy(candidate, directory.join(name))?;
            }
        }
    }
    for item in object(field(&manifest, "artifacts")?)?.values() {
        let name = text(field(item, "file")?)?;
        if !directory.join(name).exists() {
            download(
                &format!("{feed}/{name}"),
                &directory.join(name),
                uint(field(item, "size")?)?,
            )?;
        }
    }
    verify_directory(directory, keyring, certificate, true)?;
    commit_cache(directory, &target, replacing)?;
    Ok((target, manifest))
}
fn commit_cache(staged: &Path, target: &Path, replacing: bool) -> Result<()> {
    // Publish the index, its signature and the verified artifacts together.
    // A refresh may change the index signer without changing the release, so
    // retaining the previous index would break a subsequent key retirement.
    for entry in fs::read_dir(staged)? {
        let entry = entry?;
        require(
            entry.file_type()?.is_file(),
            "unexpected staged cache entry",
        )?;
        fs::File::open(entry.path())?.sync_all()?;
    }
    fs::File::open(staged)?.sync_all()?;
    let source = CString::new(staged.as_os_str().as_bytes())
        .map_err(|_| Error::new("invalid staged cache path"))?;
    let destination = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| Error::new("invalid release cache path"))?;
    let flags = if replacing {
        libc::RENAME_EXCHANGE
    } else {
        libc::RENAME_NOREPLACE
    };
    // SAFETY: both C strings own NUL-terminated paths for the duration of this
    // synchronous Linux call. Exchange leaves the complete old cache at the
    // private TempDir path; its owner removes it only after this durable commit.
    // NOREPLACE preserves a cache concurrently published by another fetch.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    fs::File::open(
        target
            .parent()
            .ok_or_else(|| Error::new("release cache lacks parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
pub fn transfers(
    manifest: &Value,
    disk: &str,
    source: &Path,
    current: &str,
) -> Result<BTreeMap<String, String>> {
    version_key(current)?;
    let mut files = BTreeMap::new();
    let version = text(field(manifest, "version")?)?;
    for (order, kind) in ["verity_sig", "verity", "usr"].into_iter().enumerate() {
        let item = field(field(manifest, "artifacts")?, kind)?;
        let filename = text(field(item, "file")?)?.replacen(version, "@v", 1);
        let partition_type = match kind {
            "usr" => "usr",
            "verity" => "usr-verity",
            _ => "usr-verity-sig",
        };
        let uuid = text(field(item, "partition_uuid")?)?;
        files.insert(format!("{}-{kind}.transfer",order+10),format!("[Transfer]\nProtectVersion={current}\nVerify=yes\n\n[Source]\nType=regular-file\nPath={}\nPathRelativeTo=root\nMatchPattern={filename}\n\n[Target]\nType=partition\nPath={disk}\nPathRelativeTo=root\nMatchPattern=PVE_@v\nMatchPartitionType={partition_type}\nPartitionUUID={uuid}\nPartitionFlags=0\nReadOnly=yes\nInstancesMax=2\n",source.display()));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cache_generation(directory: &Path, generation: &str) {
        fs::create_dir(directory).expect("create cache generation");
        for name in ["SHA256SUMS", "SHA256SUMS.asc", "artifact.raw"] {
            fs::write(directory.join(name), format!("{generation}:{name}"))
                .expect("write cache generation");
        }
    }
    fn assert_generation(directory: &Path, generation: &str) {
        for name in ["SHA256SUMS", "SHA256SUMS.asc", "artifact.raw"] {
            assert_eq!(
                fs::read_to_string(directory.join(name)).expect("read cache generation"),
                format!("{generation}:{name}")
            );
        }
    }
    #[test]
    fn cache_refresh_commits_index_signature_and_artifacts_together() {
        let root = tempfile::tempdir().expect("cache fixture");
        let staged = root.path().join(".staged");
        let target = root.path().join("release");
        cache_generation(&staged, "new");
        cache_generation(&target, "old");
        let mut prior_index = fs::File::open(target.join("SHA256SUMS")).expect("open old index");
        commit_cache(&staged, &target, true).expect("refresh cache");
        assert_generation(&target, "new");
        assert_generation(&staged, "old");
        let mut retained = String::new();
        prior_index
            .read_to_string(&mut retained)
            .expect("read open old index");
        assert_eq!(retained, "old:SHA256SUMS");
    }
    #[test]
    fn failed_cache_commit_keeps_the_previous_generation_complete() {
        let root = tempfile::tempdir().expect("cache fixture");
        let staged = root.path().join(".staged");
        let target = root.path().join("release");
        cache_generation(&staged, "new");
        cache_generation(&target, "old");
        assert!(commit_cache(&staged, &target, false).is_err());
        assert_generation(&target, "old");
        assert_generation(&staged, "new");
        fs::create_dir(staged.join("unexpected")).expect("unexpected nested entry");
        assert!(commit_cache(&staged, &target, true).is_err());
        assert_generation(&target, "old");
    }
    #[test]
    fn first_cache_commit_requires_an_absent_target() {
        let root = tempfile::tempdir().expect("cache fixture");
        let staged = root.path().join(".staged");
        let target = root.path().join("release");
        cache_generation(&staged, "new");
        commit_cache(&staged, &target, false).expect("first cache commit");
        assert_generation(&target, "new");
        assert!(!staged.exists());
    }
    use serde_json::json;
    fn sections() -> (Value, Value) {
        let manifest = json!({"version":"45.0.1.2-1.1","usr_root_hash":"ab".repeat(32)});
        let cmdline = format!(
            "usrhash={} audit=1 enforcing=1 zswap.enabled=1 systemd.ssh_auto=no kvm_intel.nested=0 kvm_amd.nested=0 rfkill.default_state=0 console=tty0",
            manifest["usr_root_hash"].as_str().expect("hash")
        );
        let mut expected = vec![json!({"ID":"main"})];
        expected.extend(
            crate::consoles::uki_profiles()
                .into_iter()
                .map(|p| p["Profile"].clone()),
        );
        let profiles=expected.iter().enumerate().map(|(index,profile)|{let mut value=json!({".profile":{"text":object(profile).expect("metadata").iter().map(|(key,value)|format!("{key}=\"{}\"",value.as_str().expect("text"))).collect::<Vec<_>>().join("\n")},".pcrsig":{"text":json!({"sha256":[{"pcrs":[11],"pol":format!("{index:064x}"),"pkfp":"b".repeat(64),"sig":"A".repeat(683)+"="}]}).to_string()}});if index>0{value[".cmdline"]=json!({"text":format!("{cmdline} {}",crate::consoles::serial_consoles()[index-1].1)});}value}).collect::<Vec<_>>();
        (
            json!({".osrel":{"text":"IMAGE_ID=ParticleVE\nIMAGE_VERSION=45.0.1.2-1.1"},".cmdline":{"text":cmdline},"_profiles":profiles}),
            manifest,
        )
    }
    #[test]
    fn all_signed_profiles_enforce_the_same_kernel_policy() {
        let (sections, manifest) = sections();
        verify_uki_sections(&sections, &manifest).expect("valid profiles");
        for kind in [
            "missing-profile",
            "missing-signature",
            "weaker-kernel",
            "wrong-console",
            "override",
            "reordered",
            "duplicate",
            "reused-policy",
        ] {
            let mut changed = sections.clone();
            match kind {
                "missing-profile" => {
                    changed["_profiles"].as_array_mut().expect("profiles").pop();
                }
                "missing-signature" => {
                    changed["_profiles"][20]
                        .as_object_mut()
                        .expect("profile")
                        .remove(".pcrsig");
                }
                "weaker-kernel" => {
                    let text = changed["_profiles"][20][".cmdline"]["text"]
                        .as_str()
                        .expect("cmdline")
                        .to_owned()
                        + " enforcing=0";
                    changed["_profiles"][20][".cmdline"]["text"] = text.into();
                }
                "wrong-console" => {
                    changed["_profiles"][20][".cmdline"]["text"] = "console=ttyS0".into();
                }
                "override" => changed["_profiles"][20][".linux"] = json!({"size":42}),
                "reordered" => changed["_profiles"]
                    .as_array_mut()
                    .expect("profiles")
                    .swap(0, 1),
                "duplicate" => {
                    let value = changed["_profiles"][20][".cmdline"].clone();
                    changed["_profiles"][20][".cmdline"] = json!([value, value]);
                }
                _ => {
                    changed["_profiles"][20][".pcrsig"] = changed["_profiles"][0][".pcrsig"].clone()
                }
            };
            assert!(verify_uki_sections(&changed, &manifest).is_err(), "{kind}");
        }
    }
    #[test]
    fn pcr_policy_references_cannot_be_unhashable_json_structures() {
        let (mut sections, manifest) = sections();
        let mut signature = parse_json(
            sections["_profiles"][0][".pcrsig"]["text"]
                .as_str()
                .expect("signature")
                .as_bytes(),
        )
        .expect("JSON");
        signature["sha256"][0]["ref"] = json!([]);
        sections["_profiles"][0][".pcrsig"]["text"] = signature.to_string().into();
        assert!(verify_uki_sections(&sections, &manifest).is_err());
    }
    #[test]
    fn profile_assignments_preserve_shlex_token_and_escape_boundaries() {
        assert!(assignments("ID=main \"\"").is_err());
        assert_eq!(
            assignments("ID=serial0-9600\u{00a0}TITLE=ttyS0,9600n8")
                .expect("one shlex word")
                .len(),
            1
        );
        assert_eq!(
            assignments(r#"ID="ma\in""#).expect("quoted backslash")["ID"],
            r"ma\in"
        );
        assert_eq!(
            assignments(r"ID=ma\in").expect("unquoted escape")["ID"],
            "main"
        );
    }
    #[test]
    fn absent_and_null_policy_references_are_the_same_policy() {
        let (mut sections, manifest) = sections();
        let mut signature = parse_json(
            sections["_profiles"][0][".pcrsig"]["text"]
                .as_str()
                .expect("signature")
                .as_bytes(),
        )
        .expect("JSON");
        let mut duplicate = signature["sha256"][0].clone();
        duplicate["ref"] = Value::Null;
        signature["sha256"]
            .as_array_mut()
            .expect("policies")
            .push(duplicate);
        sections["_profiles"][0][".pcrsig"]["text"] = signature.to_string().into();
        assert!(verify_uki_sections(&sections, &manifest).is_err());
    }
}

#[cfg(test)]
#[path = "../../Tests/runtime/tls.rs"]
mod native_tls_tests;
