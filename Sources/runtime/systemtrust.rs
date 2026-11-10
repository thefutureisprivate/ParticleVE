//! Native shared-CA views and the NTS session refresh boundary.
use crate::common::{self, Error, Result, require};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Component, Path},
};

pub const DIRECTORY: &str = "/run/particleve-ca-trust";
pub fn output_link(path: &str) -> Option<&'static str> {
    match path {
        "etc/pki/ca-trust/extracted" => Some("/run/particleve-ca-trust/extracted"),
        "etc/pki/tls/certs" => Some("/run/particleve-ca-trust/extracted/pem/directory-hash"),
        _ => None,
    }
}
fn owned_directory(path: &Path, uid: u32) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    require(
        info.is_dir() && info.uid() == uid && info.mode() & 0o022 == 0,
        format!("unsafe system trust directory: {}", path.display()),
    )
}
fn generation(name: &Path) -> bool {
    matches!(name.components().next(), Some(Component::Normal(_)))
        && name.components().count() == 1
        && name
            .to_str()
            .is_some_and(|name| name.starts_with("generation-"))
}
fn public_inputs(
    path: &Path,
    entries: &mut usize,
    bytes: &mut u64,
    hash: &mut Sha256,
) -> Result<()> {
    require(
        *entries < 1024,
        "system CA input inventory exceeds its entry limit",
    )?;
    *entries += 1;
    let name = path.as_os_str().as_encoded_bytes();
    hash.update((name.len() as u64).to_be_bytes());
    hash.update(name);
    let info = fs::symlink_metadata(path)?;
    require(
        info.uid() == 0 && (info.file_type().is_symlink() || info.mode() & 0o022 == 0),
        "unsafe system CA input ownership or mode",
    )?;
    if info.is_dir() {
        require(
            info.mode() & 0o005 == 0o005,
            "system CA source directory is not publicly traversable",
        )?;
        hash.update(b"directory");
        let mut children = Vec::new();
        for entry in fs::read_dir(path)? {
            require(
                children.len() < 1024,
                "system CA directory exceeds its entry limit",
            )?;
            children.push(entry?.path());
        }
        children.sort();
        for child in children {
            public_inputs(&child, entries, bytes, hash)?;
        }
        return Ok(());
    }
    let info = if info.file_type().is_symlink() {
        require(
            fs::canonicalize(path)?.starts_with("/usr/"),
            "local CA source link leaves verified usr",
        )?;
        fs::metadata(path)?
    } else {
        info
    };
    require(
        info.is_file() && info.uid() == 0 && info.mode() & 0o022 == 0 && info.mode() & 0o004 != 0,
        "system CA input must be a root-owned public file",
    )?;
    *bytes = bytes
        .checked_add(info.len())
        .ok_or_else(|| Error::new("CA input size overflow"))?;
    require(
        info.len() <= 4 * 1024 * 1024 && *bytes <= 16 * 1024 * 1024,
        "system CA inputs exceed their size limit",
    )?;
    let data = common::read_bounded(path, 4 * 1024 * 1024)?;
    require(
        data.len() as u64 == info.len(),
        "system CA input changed during inspection",
    )?;
    hash.update(b"file");
    hash.update((data.len() as u64).to_be_bytes());
    hash.update(data);
    Ok(())
}
fn input_fingerprint() -> Result<String> {
    let mut hash = Sha256::new();
    let (mut entries, mut bytes) = (0, 0);
    for source in ["/usr/share/pki/ca-trust-source", "/etc/pki/ca-trust/source"] {
        public_inputs(Path::new(source), &mut entries, &mut bytes, &mut hash)?;
    }
    Ok(common::hex(&hash.finalize()))
}
fn writable_generation(path: &Path, uid: u32, remaining: &mut usize, depth: usize) -> Result<()> {
    require(
        *remaining > 0 && depth <= 16,
        "generated CA cleanup exceeds its bounds",
    )?;
    *remaining -= 1;
    let info = fs::symlink_metadata(path)?;
    require(
        info.uid() == uid,
        "generated CA cleanup encountered another owner",
    )?;
    if info.is_dir() {
        require(
            info.mode() & 0o022 == 0,
            "generated CA directory permits unprivileged writes",
        )?;
        // p11-kit deliberately publishes its hashed directory as 0555. The
        // owner may retire it without CAP_DAC_OVERRIDE by adding only owner
        // access after it leaves the active view. Never follow child links.
        fs::set_permissions(
            path,
            fs::Permissions::from_mode((info.mode() & 0o7777) | 0o700),
        )?;
        for entry in fs::read_dir(path)? {
            writable_generation(&entry?.path(), uid, remaining, depth + 1)?;
        }
    } else {
        require(
            info.is_file() || info.file_type().is_symlink(),
            "special file in generated CA cleanup",
        )?;
    }
    Ok(())
}
fn discard_generation(path: &Path, uid: u32) -> Result<()> {
    writable_generation(path, uid, &mut 16384, 0)?;
    fs::remove_dir_all(path)?;
    Ok(())
}
fn discard_failure(path: &Path, uid: u32, mut original: Error) -> Error {
    if let Err(cleanup) = discard_generation(path, uid) {
        original
            .message
            .push_str(&format!("; generated CA cleanup failed: {cleanup}"));
    }
    original
}
fn publish(base: &Path, extract: impl FnOnce(&Path) -> Result<()>) -> Result<()> {
    let uid = fs::symlink_metadata(base)?.uid();
    let current = base.join("extracted");
    let previous = match fs::read_link(&current) {
        Ok(name) => {
            require(
                generation(&name),
                "system trust view has an unexpected target",
            )?;
            Some(name)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let staging = tempfile::Builder::new()
        .prefix("generation-")
        .tempdir_in(base)?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o755))?;
    // No view is published until native extraction and our actual TLS parser
    // accept the complete server-auth bundle. The remaining native views are
    // generated by the same successful update-ca-trust invocation.
    let prepared = extract(staging.path()).and_then(|()| {
        crate::release::tls_config_from_pem(&common::read_bounded(
            staging.path().join("pem/tls-ca-bundle.pem"),
            2 * 1024 * 1024,
        )?)?;
        Ok(())
    });
    if let Err(error) = prepared {
        let staged = staging.keep();
        return Err(discard_failure(&staged, uid, error));
    }
    // Keep before publication: neither interruption nor a failed bounded
    // cleanup may fall through to TempDir's unrestricted recursive removal.
    let staged = staging.keep();
    let target = staged
        .file_name()
        .ok_or_else(|| Error::new("missing CA generation name"))?;
    if let Err(error) = symlink(target, staged.join(".publish"))
        .and_then(|()| fs::rename(staged.join(".publish"), &current))
    {
        return Err(discard_failure(&staged, uid, error.into()));
    }
    if let Some(previous) = previous {
        // Only this root-owned, locked, volatile directory can supply the old
        // single-component target. Never delete an arbitrary symlink target.
        discard_generation(&base.join(previous), uid)?;
    }
    Ok(())
}
pub fn extract() -> Result<()> {
    // SAFETY: geteuid only observes process identity.
    require(
        unsafe { libc::geteuid() } == 0,
        "system trust extraction requires root",
    )?;
    for path in [
        "/etc",
        "/etc/pki",
        "/etc/pki/tls",
        "/etc/pki/ca-trust",
        "/etc/pki/ca-trust/source",
        "/etc/pki/ca-trust/source/anchors",
        "/etc/pki/ca-trust/source/blocklist",
        DIRECTORY,
    ] {
        owned_directory(Path::new(path), 0)?;
    }
    for name in ["etc/pki/ca-trust/extracted", "etc/pki/tls/certs"] {
        require(
            fs::read_link(format!("/{name}"))?
                == Path::new(output_link(name).expect("fixed CA view")),
            "system CA view does not use the image's native shared layout",
        )?;
    }
    let base = Path::new(DIRECTORY);
    let _lock = common::lock(base)?;
    // Native PKCS#11 consumers run without root. Local trust must be public
    // certificate data, readable by those consumers as well as the extractor.
    let before = input_fingerprint()?;
    publish(base, |destination| {
        let output = common::run(&[
            "/usr/bin/update-ca-trust",
            "extract",
            "--output",
            destination
                .to_str()
                .ok_or_else(|| Error::new("non-Unicode CA output path"))?,
        ])?;
        require(
            output.stderr.is_empty(),
            format!(
                "native CA extraction produced diagnostics: {}",
                output.stderr
            ),
        )?;
        require(
            input_fingerprint()? == before,
            "system CA inputs changed during extraction; retry the reviewed refresh",
        )?;
        Ok(())
    })
}
fn private_file(path: &Path, uid: u32) -> Result<()> {
    let info = fs::symlink_metadata(path)?;
    require(
        info.is_file() && info.uid() == uid && info.nlink() == 1 && info.mode() & 0o022 == 0,
        "unsafe saved NTS trust state",
    )
}
fn refresh_sessions(directory: &Path, fingerprint: &str) -> Result<()> {
    // SAFETY: geteuid only observes the daemon's effective identity.
    let uid = unsafe { libc::geteuid() };
    owned_directory(directory, uid)?;
    let stamp = directory.join("particleve-ca-trust.sha256");
    match fs::symlink_metadata(&stamp) {
        Ok(_) => {
            private_file(&stamp, uid)?;
            let mut value = String::new();
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&stamp)?
                .take(66)
                .read_to_string(&mut value)?;
            if value == format!("{fingerprint}\n") {
                return Ok(());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let mut cookies = Vec::new();
    for (entries, entry) in fs::read_dir(directory)?.enumerate() {
        require(
            entries < 1024,
            "NTS state directory exceeds its entry limit",
        )?;
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().and_then(|name| name.strip_suffix(".nts")) else {
            continue;
        };
        require(
            name.parse::<IpAddr>().is_ok(),
            "unrecognized saved NTS session name",
        )?;
        private_file(&entry.path(), uid)?;
        cookies.push(entry.path());
    }
    // Validate every candidate before removal. These are disposable client
    // sessions, never clock drift, server keys, credentials or guest identity.
    for cookie in cookies {
        fs::remove_file(cookie)?;
    }
    File::open(directory)?.sync_all()?;
    common::atomic_write(stamp, format!("{fingerprint}\n").as_bytes(), 0o600)
}
pub fn nts_sessions() -> Result<()> {
    let bundle = common::read_bounded(
        "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt",
        4 * 1024 * 1024,
    )?;
    require(!bundle.is_empty(), "empty extracted system trust")?;
    refresh_sessions(
        Path::new("/var/lib/chrony"),
        &session_fingerprint(&input_fingerprint()?, &bundle),
    )
}
fn session_fingerprint(inputs: &str, bundle: &[u8]) -> String {
    // Native PKCS#11 distrust can change without changing the OpenSSL bundle.
    // Bind cached NTS keys to both source policies and the generated view so a
    // restart cannot keep authenticating with a previously accepted session.
    let mut hash = Sha256::new();
    hash.update(inputs.as_bytes());
    hash.update(bundle);
    common::hex(&hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_changed_store_discards_only_client_sessions() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let drift = directory.path().join("drift");
        fs::write(&drift, "retained clock state")?;
        let cookie = directory.path().join("192.0.2.1.nts");
        fs::write(&cookie, "old session")?;
        refresh_sessions(directory.path(), "first")?;
        assert!(!cookie.exists());
        fs::write(&cookie, "retained same-trust session")?;
        refresh_sessions(directory.path(), "first")?;
        assert_eq!(fs::read_to_string(&cookie)?, "retained same-trust session");
        refresh_sessions(directory.path(), "changed")?;
        assert!(!cookie.exists());
        assert_eq!(fs::read_to_string(drift)?, "retained clock state");
        Ok(())
    }
    #[test]
    fn source_distrust_invalidates_sessions_with_an_unchanged_bundle() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let bundle = b"unchanged native OpenSSL output";
        let accepted = session_fingerprint("accepted policy", bundle);
        refresh_sessions(directory.path(), &accepted)?;
        let cookie = directory.path().join("192.0.2.1.nts");
        fs::write(&cookie, "previously authenticated session")?;
        refresh_sessions(directory.path(), &accepted)?;
        assert!(cookie.exists());
        let distrusted = session_fingerprint("explicitly distrusted policy", bundle);
        refresh_sessions(directory.path(), &distrusted)?;
        assert!(!cookie.exists());
        Ok(())
    }
    #[test]
    fn unsafe_sessions_block_before_any_removal() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let cookie = directory.path().join("192.0.2.1.nts");
        fs::write(&cookie, "preserve on uncertainty")?;
        symlink("/dev/null", directory.path().join("2001:db8::1.nts"))?;
        assert!(refresh_sessions(directory.path(), "changed").is_err());
        assert_eq!(fs::read_to_string(cookie)?, "preserve on uncertainty");
        Ok(())
    }
    #[test]
    fn failed_extraction_keeps_the_previous_view() -> Result<()> {
        let directory = tempfile::tempdir()?;
        fs::create_dir(directory.path().join("generation-old"))?;
        symlink("generation-old", directory.path().join("extracted"))?;
        let failure = publish(directory.path(), |staging| {
            let hashes = staging.join("pem/directory-hash");
            fs::create_dir_all(&hashes)?;
            fs::write(hashes.join("root.pem"), "partial public output")?;
            fs::set_permissions(hashes, fs::Permissions::from_mode(0o555))?;
            Err(Error::new("interrupted extractor"))
        })
        .expect_err("interrupted extraction must fail");
        assert!(failure.to_string().contains("interrupted extractor"));
        assert_eq!(
            fs::read_link(directory.path().join("extracted"))?,
            Path::new("generation-old")
        );
        assert_eq!(fs::read_dir(directory.path())?.count(), 2);
        Ok(())
    }
    #[test]
    fn retired_native_readonly_hash_directories_need_no_extra_capability() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let generation = directory.path().join("generation-old");
        let hashes = generation.join("pem/directory-hash");
        fs::create_dir_all(&hashes)?;
        fs::write(hashes.join("root.pem"), "public certificate")?;
        fs::set_permissions(&hashes, fs::Permissions::from_mode(0o555))?;
        discard_generation(&generation, fs::symlink_metadata(directory.path())?.uid())?;
        assert!(!generation.exists());
        Ok(())
    }
    #[test]
    fn cleanup_uncertainty_preserves_the_original_error_and_unpublished_tree() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let failure = publish(directory.path(), |staging| {
            let unsafe_directory = staging.join("unexpected");
            fs::create_dir(&unsafe_directory)?;
            fs::set_permissions(unsafe_directory, fs::Permissions::from_mode(0o777))?;
            Err(Error::new("original extraction failure"))
        })
        .expect_err("untrusted generated metadata must fail");
        assert!(failure.to_string().contains("original extraction failure"));
        assert!(failure.to_string().contains("cleanup failed"));
        assert!(!directory.path().join("extracted").exists());
        assert_eq!(fs::read_dir(directory.path())?.count(), 1);
        Ok(())
    }
}
