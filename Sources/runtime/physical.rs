//! Bounded read-only published physical capabilities; never device enrollment.
//! Descriptor blobs, serial/MAC/Thunderbolt UUIDs and PCI configuration are not read.
use crate::common::{Error, Result, require};
use crate::confinement::matches;
use serde_json::{Map, Value, json};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
pub const MAX_NODES: usize = 4096;
pub const MAX_ATTRIBUTE: usize = 1024;
pub struct Observation {
    pub root: PathBuf,
    remaining: usize,
}
impl Observation {
    pub fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
            remaining: MAX_NODES,
        })
    }
    fn nodes(&mut self, relative: &str) -> Result<(Value, Vec<PathBuf>)> {
        let iterator = match fs::read_dir(self.root.join(relative)) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((json!({"sysfs_present":false,"devices":[]}), Vec::new()));
            }
            Err(e) => return Err(e.into()),
        };
        let mut nodes = Vec::new();
        for entry in iterator {
            require(
                nodes.len() < self.remaining,
                "physical-interface inventory exceeds its node bound",
            )?;
            let path = entry?.path();
            require(
                path.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(printable),
                "invalid physical-interface node name",
            )?;
            nodes.push(path);
        }
        self.remaining -= nodes.len();
        nodes.sort();
        Ok((json!({"sysfs_present":true,"devices":[]}), nodes))
    }
    pub fn attribute(path: &Path, optional: bool) -> Result<Option<String>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(v) => v,
            Err(e)
                if optional
                    && e.kind() == std::io::ErrorKind::NotFound
                    && path.parent().is_some_and(Path::is_dir) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        require(
            file.metadata()?.is_file(),
            "physical attribute is not a regular file",
        )?;
        let mut bytes = Vec::new();
        file.take(MAX_ATTRIBUTE as u64 + 1)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() <= MAX_ATTRIBUTE,
            "physical-interface attribute exceeds its bound",
        )?;
        require(bytes.is_ascii(), "non-ASCII physical capability attribute")?;
        let value = String::from_utf8(bytes)?.trim_end_matches('\n').to_owned();
        require(
            !value.is_empty() && printable(&value),
            "invalid physical capability attribute",
        )?;
        Ok(Some(value))
    }
    fn fields(&self, path: &Path, names: &[&str]) -> Result<Map<String, Value>> {
        let mut values = Map::new();
        for name in names {
            values.insert(
                (*name).to_owned(),
                json!(Self::attribute(&path.join(name), true)?),
            );
        }
        Ok(values)
    }
    fn flag(&self, path: &Path, optional: bool) -> Result<Value> {
        let value = Self::attribute(path, optional)?;
        require(
            value.as_deref().is_none_or(|s| s == "0" || s == "1"),
            "unknown physical-interface boolean state",
        )?;
        Ok(value.map_or(Value::Null, |v| json!(v == "1")))
    }
    fn link(&self, path: &Path, under: Option<&Path>) -> Result<Value> {
        let info = match fs::symlink_metadata(path) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                require(
                    path.parent().is_some_and(Path::is_dir),
                    "physical-interface device disappeared",
                )?;
                return Ok(Value::Null);
            }
            Err(e) => return Err(e.into()),
        };
        require(
            info.is_symlink(),
            "physical-interface reference is not a symbolic link",
        )?;
        let target = path.canonicalize()?;
        require(
            target.starts_with(under.unwrap_or(&self.root)),
            "physical-interface reference escapes sysfs",
        )?;
        let name = target
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| printable(s))
            .ok_or_else(|| Error::new("invalid physical-interface reference name"))?;
        Ok(json!(name))
    }
    fn device<F>(&self, entry: &Path, reader: F) -> Result<Value>
    where
        F: FnOnce(&Path) -> Result<Map<String, Value>>,
    {
        let path = entry.canonicalize()?;
        require(
            path.starts_with(self.root.join("devices")),
            "physical-interface node escapes sysfs devices",
        )?;
        let before = path.metadata()?;
        let mut result = reader(&path)?;
        result.insert(
            "node".into(),
            json!(
                entry
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| Error::new("invalid physical-interface node"))?
            ),
        );
        let after = entry.canonicalize()?.metadata()?;
        require(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "physical-interface device changed during observation",
        )?;
        Ok(Value::Object(result))
    }
    pub fn usb(&mut self) -> Result<Value> {
        let (mut report, nodes) = self.nodes("bus/usb/devices")?;
        let mut devices = std::collections::BTreeMap::new();
        let mut records = Vec::new();
        let mut interfaces = Vec::new();
        for entry in nodes {
            if entry
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.contains(':'))
            {
                interfaces.push(entry);
                continue;
            }
            let record = self.device(&entry, |path| {
                let mut values = self.fields(
                    path,
                    &[
                        "idVendor",
                        "idProduct",
                        "bDeviceClass",
                        "bDeviceSubClass",
                        "bDeviceProtocol",
                    ],
                )?;
                for (name, value) in &values {
                    let pattern = if ["idVendor", "idProduct"].contains(&name.as_str()) {
                        r"\A[0-9a-fA-F]{4}\z"
                    } else {
                        r"\A[0-9a-fA-F]{2}\z"
                    };
                    require(
                        value
                            .as_str()
                            .is_some_and(|s| matches(pattern, s).unwrap_or(false)),
                        "invalid USB capability identifier",
                    )?;
                }
                values.insert(
                    "authorized".into(),
                    self.flag(&path.join("authorized"), false)?,
                );
                values.insert(
                    "authorized_default".into(),
                    json!(Self::attribute(&path.join("authorized_default"), true)?),
                );
                values.insert(
                    "interface_authorized_default".into(),
                    self.flag(&path.join("interface_authorized_default"), true)?,
                );
                values.insert(
                    "removable".into(),
                    json!(Self::attribute(&path.join("removable"), true)?),
                );
                values.insert("interfaces".into(), json!([]));
                Ok(values)
            })?;
            let key = entry
                .canonicalize()?
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::new("invalid USB node"))?
                .to_owned();
            devices.insert(key, records.len());
            records.push(record);
        }
        for entry in interfaces {
            let path = entry.canonicalize()?;
            let parent = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::new("USB interface has no observed parent device"))?;
            require(
                devices.contains_key(parent),
                "USB interface has no observed parent device",
            )?;
            let record = self.device(&entry, |path| {
                let mut values = self.fields(
                    path,
                    &[
                        "bInterfaceClass",
                        "bInterfaceSubClass",
                        "bInterfaceProtocol",
                    ],
                )?;
                for value in values.values() {
                    require(
                        value
                            .as_str()
                            .is_some_and(|s| matches(r"\A[0-9a-fA-F]{2}\z", s).unwrap_or(false)),
                        "invalid USB interface capability",
                    )?;
                }
                values.insert("driver".into(), self.link(&path.join("driver"), None)?);
                values.insert(
                    "authorized".into(),
                    self.flag(&path.join("authorized"), true)?,
                );
                Ok(values)
            })?;
            devices
                .get(parent)
                .and_then(|index| records.get_mut(*index))
                .and_then(|v| v["interfaces"].as_array_mut())
                .ok_or_else(|| Error::new("USB interface has no observed parent device"))?
                .push(record);
        }
        report["devices"] = Value::Array(records);
        Ok(report)
    }
    pub fn radios(&mut self) -> Result<Value> {
        let (mut report, nodes) = self.nodes("class/rfkill")?;
        let mut records = Vec::new();
        for entry in nodes {
            records.push(self.device(&entry, |path| {
                let mut values = Map::new();
                values.insert(
                    "type".into(),
                    json!(Self::attribute(&path.join("type"), false)?),
                );
                values.insert("soft_blocked".into(), self.flag(&path.join("soft"), false)?);
                values.insert("hard_blocked".into(), self.flag(&path.join("hard"), false)?);
                Ok(values)
            })?);
        }
        report["devices"] = Value::Array(records);
        Ok(report)
    }
    pub fn thunderbolt(&mut self) -> Result<Value> {
        let (mut report, nodes) = self.nodes("bus/thunderbolt/devices")?;
        let mut records = Vec::new();
        for entry in nodes {
            records.push(self.device(&entry, |path| {
                let mut values =
                    self.fields(path, &["security", "vendor", "device", "authorized"])?;
                values.insert(
                    "iommu_dma_protection".into(),
                    self.flag(&path.join("iommu_dma_protection"), true)?,
                );
                values.insert(
                    "deauthorization".into(),
                    self.flag(&path.join("deauthorization"), true)?,
                );
                Ok(values)
            })?);
        }
        report["devices"] = Value::Array(records);
        Ok(report)
    }
    pub fn pci(&mut self) -> Result<Value> {
        let (mut report, nodes) = self.nodes("bus/pci/devices")?;
        let mut records = Vec::new();
        for entry in nodes {
            records.push(self.device(&entry, |path| {
                let mut values = self.fields(path, &["class", "vendor", "device"])?;
                for (name, value) in &values {
                    let pattern = if name == "class" {
                        r"\A0x[0-9a-fA-F]{6}\z"
                    } else {
                        r"\A0x[0-9a-fA-F]{4}\z"
                    };
                    require(
                        value
                            .as_str()
                            .is_some_and(|s| matches(pattern, s).unwrap_or(false)),
                        "invalid PCI capability identifier",
                    )?;
                }
                values.insert("driver".into(), self.link(&path.join("driver"), None)?);
                values.insert(
                    "iommu_group".into(),
                    self.link(
                        &path.join("iommu_group"),
                        Some(&self.root.join("kernel/iommu_groups")),
                    )?,
                );
                values.insert(
                    "untrusted".into(),
                    self.flag(&path.join("untrusted"), true)?,
                );
                values.insert(
                    "removable".into(),
                    json!(Self::attribute(&path.join("removable"), true)?),
                );
                Ok(values)
            })?);
        }
        report["devices"] = Value::Array(records);
        Ok(report)
    }
    pub fn network(&mut self) -> Result<Value> {
        let (mut report, nodes) = self.nodes("class/net")?;
        let mut records = Vec::new();
        for entry in nodes {
            records.push(self.device(&entry, |path| {
                let device = self.link(&path.join("device"), Some(&self.root.join("devices")))?;
                let mut values = Map::new();
                values.insert("device_node".into(), device.clone());
                values.insert(
                    "device_path".into(),
                    if device.is_null() {
                        Value::Null
                    } else {
                        json!(
                            path.join("device")
                                .canonicalize()?
                                .strip_prefix(self.root.join("devices"))
                                .map_err(|_| Error::new("network device escapes sysfs"))?
                                .to_str()
                                .ok_or_else(|| Error::new("invalid network device path"))?
                        )
                    },
                );
                values.insert(
                    "driver".into(),
                    if device.is_null() {
                        Value::Null
                    } else {
                        self.link(&path.join("device/driver"), None)?
                    },
                );
                values.insert(
                    "wireless".into(),
                    json!(
                        path.join("wireless").is_dir()
                            || fs::symlink_metadata(path.join("phy80211"))
                                .is_ok_and(|m| m.is_symlink())
                    ),
                );
                Ok(values)
            })?);
        }
        report["devices"] = Value::Array(records);
        Ok(report)
    }
    pub fn iommu(&mut self) -> Result<Value> {
        let (mut report, nodes) = self.nodes("kernel/iommu_groups")?;
        let mut records = Vec::new();
        for entry in nodes {
            let name = entry
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::new("invalid IOMMU group"))?;
            require(
                entry.is_dir() && !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()),
                "invalid IOMMU group",
            )?;
            let (_, members) = self.nodes(&format!("kernel/iommu_groups/{name}/devices"))?;
            let mut targets = Vec::new();
            for member in members {
                targets.push(self.link(&member, Some(&self.root.join("devices")))?);
            }
            records.push(json!({"group":name,"type":Self::attribute(&entry.join("type"),true)?,"members":targets}));
        }
        report["devices"] = Value::Array(records);
        Ok(report)
    }
}
fn printable(value: &str) -> bool {
    // Match Python's prior printable-name contract: letters, marks, numbers,
    // punctuation, symbols and ordinary ASCII space, never format/separator controls.
    static PRINTABLE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\A[\p{L}\p{M}\p{N}\p{P}\p{S} ]*\z")
            .expect("constant printable-name expression")
    });
    PRINTABLE.is_match(value)
}
pub fn collect(sysfs: &Path) -> Result<Value> {
    let mut observer = Observation::new(sysfs)?;
    Ok(
        json!({"schema":1,"usb":observer.usb()?,"radios":observer.radios()?,"thunderbolt":observer.thunderbolt()?,"pci":observer.pci()?,"network":observer.network()?,"iommu":observer.iommu()?}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_missing_is_distinct_from_bus_absence() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("devices")).unwrap();
        let mut observer = Observation::new(root.path()).unwrap();
        assert_eq!(
            observer.radios().unwrap(),
            json!({"sysfs_present":false,"devices":[]})
        );
        fs::create_dir_all(root.path().join("class/rfkill")).unwrap();
        assert_eq!(
            observer.radios().unwrap(),
            json!({"sysfs_present":true,"devices":[]})
        );
        assert!(
            Observation::attribute(&root.path().join("devices/missing"), true)
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod negative_tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn references_cannot_escape_sysfs_and_attributes_cannot_follow_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("devices")).unwrap();
        fs::create_dir_all(root.path().join("class/rfkill")).unwrap();
        fs::write(outside.path().join("type"), "wlan\n").unwrap();
        symlink(outside.path(), root.path().join("class/rfkill/rfkill0")).unwrap();
        assert!(Observation::new(root.path()).unwrap().radios().is_err());
        symlink(
            outside.path().join("type"),
            root.path().join("devices/type"),
        )
        .unwrap();
        assert!(Observation::attribute(&root.path().join("devices/type"), false).is_err());
    }
    #[test]
    fn complete_inventory_and_attribute_bounds_are_enforced() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("class/rfkill")).unwrap();
        fs::write(root.path().join("class/rfkill/one"), "unused").unwrap();
        let mut observer = Observation::new(root.path()).unwrap();
        observer.remaining = 0;
        assert!(observer.radios().is_err());
        let path = root.path().join("oversized");
        fs::write(&path, vec![b'x'; MAX_ATTRIBUTE + 1]).unwrap();
        assert!(Observation::attribute(&path, false).is_err());
        fs::write(&path, b"bad\0value").unwrap();
        assert!(Observation::attribute(&path, false).is_err());
    }
}
