//! Canonical source and native OBS image identities.
use crate::common::{Error, Result, require};
use regex::Regex;
pub const NUMBER: &str = r"(?:0|[1-9][0-9]{0,5})";
pub fn version_key(value: &str) -> Result<[u64; 6]> {
    let pattern = Regex::new(&format!(
        r"^({NUMBER})\.({NUMBER})\.({NUMBER})\.({NUMBER})-({NUMBER})\.({NUMBER})$"
    ))
    .map_err(|e| Error::new(e.to_string()))?;
    let captures = pattern.captures(value).ok_or_else(|| {
        Error::new("version must use FEDORA.PVE_MAJOR.PVE_MINOR.PVE_PATCH-CHECKIN.BUILD")
    })?;
    let mut fields = [0; 6];
    for (index, field) in fields.iter_mut().enumerate() {
        *field = captures[index + 1]
            .parse()
            .map_err(|_| Error::new("invalid version component"))?;
    }
    require(
        fields[0] > 0,
        "version must use FEDORA.PVE_MAJOR.PVE_MINOR.PVE_PATCH-CHECKIN.BUILD",
    )?;
    require(
        value.len() <= 32,
        "version exceeds the native GPT label limit",
    )?;
    Ok(fields)
}
pub fn source_key(value: &str) -> Result<[u64; 4]> {
    let re = Regex::new(&format!(
        r"^({NUMBER})\.({NUMBER})\.({NUMBER})\.({NUMBER})$"
    ))
    .map_err(|e| Error::new(e.to_string()))?;
    let c = re.captures(value).ok_or_else(|| {
        Error::new("source version must be FEDORA_MAJOR.PVE_MAJOR.PVE_MINOR.PVE_PATCH")
    })?;
    let mut fields = [0; 4];
    for (i, f) in fields.iter_mut().enumerate() {
        *f = c[i + 1]
            .parse()
            .map_err(|_| Error::new("invalid source version"))?;
    }
    require(
        fields[0] > 0,
        "source version must be FEDORA_MAJOR.PVE_MAJOR.PVE_MINOR.PVE_PATCH",
    )?;
    Ok(fields)
}
