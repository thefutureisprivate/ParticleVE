//! Upstream homed owns every non-root interactive account.
use crate::common::{Error, Result, command, parse_json, read_bounded, require};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

pub fn homed_record(username: &str) -> Result<Value> {
    require(
        !username.is_empty()
            && !username.starts_with('-')
            && !username.contains('\n')
            && !username.contains('\0'),
        "invalid login name",
    )?;
    let arguments = [
        "userdbctl",
        "--service=io.systemd.Home",
        "--with-nss=no",
        "--output=json",
        "user",
        username,
    ]
    .map(str::to_owned);
    let response = command(
        &arguments,
        None,
        Some(Duration::from_secs(15)),
        8 * 1024 * 1024,
        true,
    )?;
    let record = parse_json(response.stdout.as_bytes())?;
    require(
        record.is_object() && record.get("userName").and_then(Value::as_str) == Some(username),
        "login account is not managed by homed",
    )?;
    require(
        record
            .get("disposition")
            .is_none_or(|value| value.as_str() == Some("regular")),
        "not a regular homed login account",
    )?;
    Ok(record)
}
pub fn authorize_login(username: &str) -> Result<()> {
    if username != "root" {
        homed_record(username)?;
    }
    Ok(())
}

pub fn audit_local(passwd: &str, shells: &str) -> Result<()> {
    let shells: BTreeSet<_> = shells
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    let mut classic = Vec::new();
    for line in passwd.lines().filter(|s| !s.is_empty()) {
        let row: Vec<_> = line.split(':').collect();
        require(row.len() == 7, "malformed local passwd database")?;
        let uid: u32 = row[2]
            .parse()
            .map_err(|_| Error::new("malformed local passwd UID"))?;
        if row[0] != "root"
            && ![
                "/sbin/nologin",
                "/usr/sbin/nologin",
                "/bin/false",
                "/usr/bin/false",
            ]
            .contains(&row[6])
            && ((1000..60000).contains(&uid) || shells.contains(row[6]))
        {
            classic.push(row[0]);
        }
    }
    require(
        classic.is_empty(),
        format!(
            "non-root login accounts must be created with homectl, not useradd: {}",
            classic.join(", ")
        ),
    )
}
pub fn check() -> Result<Value> {
    audit_local(
        &String::from_utf8(read_bounded(Path::new("/etc/passwd"), 8 * 1024 * 1024)?)?,
        &String::from_utf8(read_bounded(Path::new("/etc/shells"), 1024 * 1024)?)?,
    )?;
    command(
        &["homectl", "list", "--no-pager"].map(str::to_owned),
        None,
        Some(Duration::from_secs(15)),
        8 * 1024 * 1024,
        true,
    )?;
    Ok(json!({"non_root_logins":"homed","ssh_keys":"upstream userdb records","root_home":"/root"}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_root_and_rejects_classic_logins() {
        assert!(
            audit_local(
                "root:x:0:0::/root:/bin/bash\nsshd:x:74:74::/:/sbin/nologin\n",
                "/bin/bash\n"
            )
            .is_ok()
        );
        assert!(audit_local("alice:x:1000:1000::/home/alice:/bin/bash\n", "/bin/bash\n").is_err());
        assert!(audit_local("alice:x:42:42::/:/bin/bash\n", "/bin/bash\n").is_err());
    }
}
