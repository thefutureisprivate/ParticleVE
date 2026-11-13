//! Validate installation inputs before command generation or disk authority.
use crate::common::{Error, Result, command, field, list, object, require, text, uint};
pub use crate::versioning::version_key;
use regex::Regex;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};
pub const VERITY_SIGNATURE_SIZE: u64 = 1024 * 1024;
fn matches(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).is_ok_and(|r| r.is_match(value))
}
pub fn dns_name(value: &str) -> Result<&str> {
    require(
        (2..=253).contains(&value.len())
            && value.contains('.')
            && value
                .split('.')
                .all(|label| matches(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label)),
        "use a canonical fully qualified DNS name",
    )?;
    Ok(value)
}
pub fn integer(value: &Value, minimum: u64, label: &str) -> Result<u64> {
    let v = uint(value)?;
    require(
        v >= minimum,
        format!("{label} must be an integer >= {minimum}"),
    )?;
    Ok(v)
}
pub fn https_url(value: &str) -> Result<String> {
    // Url's browser-oriented parser repairs missing or repeated authority
    // slashes. Feed and receiver inputs must retain an explicit HTTPS authority.
    let (scheme, authority) = value
        .split_once("://")
        .ok_or_else(|| Error::new("feed must be an HTTPS URL without credentials"))?;
    require(
        scheme.eq_ignore_ascii_case("https")
            && !authority.is_empty()
            && !authority.starts_with('/'),
        "feed must be an HTTPS URL without credentials",
    )?;
    let parsed = url::Url::parse(value)
        .map_err(|_| Error::new("feed must be an HTTPS URL without credentials"))?;
    require(
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "feed must be an HTTPS URL without credentials",
    )?;
    require(
        parsed.query().is_none()
            && parsed.fragment().is_none()
            && !value
                .chars()
                .any(|c| c.is_whitespace() || c == '%' || c == '\\'),
        "invalid feed URL",
    )?;
    let hostname = parsed
        .host_str()
        .ok_or_else(|| Error::new("missing feed hostname"))?;
    require(
        !hostname.ends_with(".invalid") && !hostname.ends_with(".example"),
        "configure the real ParticleVE feed",
    )?;
    Ok(value.trim_end_matches('/').into())
}
pub fn ssh_key(value: &Value) -> bool {
    let Some(value) = value.as_str() else {
        return false;
    };
    let printable = Regex::new(r"[\p{C}\p{Z}]")
        .is_ok_and(|regex| value.split(' ').all(|part| !regex.is_match(part)));
    if value.len() > 8192 || !printable {
        return false;
    }
    let Ok(re) = Regex::new(
        r"^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,2})(?: .+)?$",
    ) else {
        return false;
    };
    let Some(c) = re.captures(value) else {
        return false;
    };
    let data = format!("{} {}\n", &c[1], &c[2]);
    command(
        &[
            "/usr/bin/ssh-keygen".into(),
            "-l".into(),
            "-f".into(),
            "-".into(),
        ],
        Some(data.as_bytes()),
        Some(Duration::from_secs(2)),
        65536,
        false,
    )
    .is_ok_and(|r| r.code == 0 && r.stderr.trim().is_empty())
}
pub fn ip_interface(value: &str, strict_network: bool) -> Result<(IpAddr, u8)> {
    require(!value.contains('%'), "use an unscoped literal address")?;
    let (ip, prefix) = value
        .split_once('/')
        .map_or((value, None), |(ip, p)| (ip, Some(p)));
    let address: IpAddr = ip
        .parse()
        .map_err(|_| Error::new("invalid literal IP address"))?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.map_or(Ok(width), |p| {
        p.parse::<u8>()
            .map_err(|_| Error::new("invalid address prefix"))
    })?;
    require(prefix <= width, "invalid address prefix")?;
    if strict_network {
        let bits = match address {
            IpAddr::V4(v) => u128::from(u32::from(v)),
            IpAddr::V6(v) => u128::from(v),
        };
        let hostbits = width - prefix;
        let mask = if hostbits == 128 {
            u128::MAX
        } else {
            (1u128 << hostbits) - 1
        };
        require(
            bits & mask == 0,
            "management source network contains host bits",
        )?;
    }
    Ok((address, prefix))
}
fn visit(
    name: &str,
    graph: &BTreeMap<String, Vec<String>>,
    ancestors: &mut BTreeSet<String>,
) -> Result<()> {
    require(
        ancestors.insert(name.into()),
        "network ownership contains a cycle",
    )?;
    if let Some(children) = graph.get(name) {
        for child in children {
            visit(child, graph, ancestors)?
        }
    }
    ancestors.remove(name);
    Ok(())
}
pub fn validate(config: Value, publication: bool) -> Result<Value> {
    object(&config)?;
    require(
        config.get("schema") == Some(&Value::from(2)),
        "installation schema must be 2; no implicit migrations",
    )?;
    require(
        config["architecture"] == "x86-64",
        "only the x86-64/v2 build target is implemented",
    )?;
    require(
        config["cpu_baseline"] == "x86-64-v2",
        "CPU baseline must be x86-64-v2",
    )?;
    require(
        matches(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
            text(field(&config, "hostname")?)?,
        ),
        "invalid hostname",
    )?;
    let disks = list(field(&config, "disks")?)?;
    require(disks.len() == 2, "select exactly two boot disks")?;
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut serials = BTreeSet::new();
    for disk in disks {
        roles.insert(text(field(disk, "role")?)?);
        let path = text(field(disk, "path")?)?;
        require(
            matches(r"^/dev/disk/by-id/[a-zA-Z0-9_.:+-]+$", path),
            "disks must use explicit /dev/disk/by-id identities",
        )?;
        require(
            !matches(r"-part[0-9]+$", path),
            "select whole disks, not partitions",
        )?;
        let serial = text(field(disk, "serial")?)?;
        require(!serial.trim().is_empty(), "record each disk serial")?;
        paths.insert(path);
        serials.insert(serial);
    }
    require(
        roles == BTreeSet::from(["a", "b"]),
        "disk roles must be a and b",
    )?;
    require(paths.len() == 2, "disk paths must differ")?;
    require(serials.len() == 2, "disk serials must differ")?;
    let storage = field(&config, "storage")?;
    for (name, min) in [
        ("esp_mib", 1024),
        ("usr_growth_percent", 20),
        ("swap_mib", 1024),
        ("minimum_state_mib", 8192),
        ("reserve_mib", 2048),
        ("reserve_percent", 10),
        ("metadata_max_percent", 50),
        ("degraded_wait_seconds", 5),
        ("firmware_staging_mib", 64),
    ] {
        integer(field(storage, name)?, min, name)?;
    }
    require(
        uint(&storage["reserve_percent"])? <= 50,
        "state reserve must be <= 50%",
    )?;
    require(
        uint(&storage["metadata_max_percent"])? <= 95,
        "metadata threshold must be <= 95%",
    )?;
    require(
        uint(&storage["degraded_wait_seconds"])? <= 120,
        "missing-device wait must be bounded to 120 seconds",
    )?;
    require(
        storage.get("discard") == Some(&Value::Bool(false)),
        "discard requires a separately commissioned policy",
    )?;
    let minimum_ram = integer(field(&config, "minimum_ram_mib")?, 2048, "minimum_ram_mib")?;
    require(
        config.get("recovery_console_confirmed") == Some(&Value::Bool(true)),
        "confirm independent recovery console access",
    )?;
    let physical = object(field(&config, "physical")?)?;
    require(
        physical.len() == 1 && physical.contains_key("radios"),
        "declare the physical radio policy",
    )?;
    crate::radio::validate(&physical["radios"])?;
    require(
        config["tpm_policy"] == "pcr7+signed-pcr11",
        "this implementation uses PCR7 + signed PCR11",
    )?;
    crate::consoles::profile(&config)?;
    let network = field(&config, "network")?;
    let links = list(field(network, "links")?)?;
    require(
        !links.is_empty(),
        "declare at least one physical management NIC",
    )?;
    let mut devices: Vec<&Value> = links.iter().collect();
    for kind in ["bridges", "vlans"] {
        if let Some(devices_kind) = network.get(kind) {
            devices.extend(list(devices_kind)?);
        }
    }
    let mut names = BTreeSet::new();
    for d in &devices {
        let name = text(field(d, "name")?)?;
        require(
            matches(r"^[a-zA-Z][a-zA-Z0-9_-]{0,14}$", name) && names.insert(name.to_owned()),
            "invalid network names",
        )?;
    }
    require(
        names.contains(text(field(network, "management")?)?),
        "management interface must be declared",
    )?;
    let mut macs = BTreeSet::new();
    for link in links {
        let mac = text(field(link, "mac")?)?;
        require(
            matches(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", mac),
            "invalid permanent NIC MAC",
        )?;
        require(macs.insert(mac), "duplicate NIC MAC")?;
    }
    let bridges: BTreeSet<_> = network
        .get("bridges")
        .map(list)
        .transpose()?
        .into_iter()
        .flatten()
        .map(|v| text(field(v, "name")?))
        .collect::<Result<_>>()?;
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for dev in &devices {
        if let Some(bridge) = dev.get("bridge") {
            let bridge = text(bridge)?;
            let name = text(field(dev, "name")?)?;
            require(
                bridges.contains(bridge) && bridge != name,
                "invalid bridge owner",
            )?;
            graph.entry(name.into()).or_default().push(bridge.into());
        }
    }
    if let Some(vlans) = network.get("vlans") {
        for vlan in list(vlans)? {
            let parent = text(field(vlan, "parent")?)?;
            let name = text(field(vlan, "name")?)?;
            require(
                names.contains(parent) && parent != name,
                "invalid VLAN parent",
            )?;
            require(
                integer(field(vlan, "id")?, 1, "VLAN id")? <= 4094,
                "VLAN id must be <= 4094",
            )?;
            graph.entry(parent.into()).or_default().push(name.into());
        }
    }
    for name in &names {
        visit(name, &graph, &mut BTreeSet::new())?;
    }
    let addresses = list(field(network, "addresses")?)?;
    require(
        !addresses.is_empty(),
        "configure static management addresses",
    )?;
    for a in addresses {
        ip_interface(text(a)?, false)?;
    }
    let sources = list(field(network, "allowed_sources")?)?;
    require(
        !sources.is_empty(),
        "management sources cannot include the Internet",
    )?;
    for source in sources {
        require(
            ip_interface(text(source)?, true)?.1 > 0,
            "management sources cannot include the Internet",
        )?;
    }
    for gateway in list(field(network, "gateways")?)? {
        let gateway = text(gateway)?;
        require(
            !gateway.contains('%') && gateway.parse::<IpAddr>().is_ok(),
            "gateways must be unscoped literals",
        )?;
    }
    crate::dns::validate(
        field(network, "dns")?,
        &[text(field(network, "management")?)?.to_owned()],
    )?;
    require(
        network.get("ntp").is_none(),
        "unauthenticated NTP settings are unsupported",
    )?;
    crate::timesync::validate(field(&config, "time")?)?;
    let maintenance = field(&config, "maintenance")?;
    for (key, min, max) in [
        ("start_tolerance_seconds", 1, 60),
        ("graceful_seconds", 10, 1800),
        ("restore_seconds", 10, 600),
    ] {
        require(
            integer(field(maintenance, key)?, min, key)? <= max,
            format!("{key} exceeds its bounded policy"),
        )?;
    }
    let reserve = integer(
        field(maintenance, "minimum_available_ram_mib")?,
        256,
        "minimum_available_ram_mib",
    )?;
    require(
        reserve < minimum_ram,
        "maintenance RAM reserve must be below the minimum physical RAM",
    )?;
    let resources = object(field(&config, "resources")?)?;
    require(
        resources.len() == 2
            && resources.contains_key("minimum_available_ram_mib")
            && resources.contains_key("pressure_avg60_percent"),
        "declare normal RAM headroom and resource pressure policy",
    )?;
    require(
        integer(
            &resources["minimum_available_ram_mib"],
            256,
            "normal RAM reserve",
        )? <= reserve,
        "normal RAM reserve must not exceed the maintenance reserve",
    )?;
    let thresholds = object(&resources["pressure_avg60_percent"])?;
    require(
        thresholds.len() == 3
            && ["cpu", "memory", "io"]
                .iter()
                .all(|s| thresholds.contains_key(*s)),
        "declare CPU, memory and I/O pressure thresholds",
    )?;
    for (kind, value) in thresholds {
        require(
            integer(value, 1, kind)? <= 100,
            "pressure thresholds must be <= 100 percent",
        )?;
    }
    let keys = list(field(&config, "admin_ssh_keys")?)?;
    require(
        (1..=16).contains(&keys.len()) && keys.iter().all(ssh_key),
        "configure 1..16 owner Ed25519 or FIDO2 SSH public keys without key options",
    )?;
    if publication {
        https_url(text(field(&config, "feed")?)?)?;
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_label_versions_and_literal_networks_reject_ambiguous_values() {
        for version in ["45.0.1.2-1.1", "45.0.1.13-87.2"] {
            assert!(version_key(version).is_ok());
        }
        for version in [
            "0.0.1.1-1.1",
            "045.0.1.1-1.1",
            "45.0.1.1-01.1",
            "45.0.1.1-1.1\n",
            "45.0.1.1",
            "45.0.1.1-1.1-2.2",
        ] {
            assert!(version_key(version).is_err(), "{version}");
        }
        assert!(ip_interface("192.0.2.0/24", true).is_ok());
        assert!(ip_interface("192.0.2.1/24", true).is_err());
        assert!(ip_interface("2001:db8::/64", true).is_ok());
        assert!(ip_interface("2001:db8::1/64", true).is_err());
        assert!(ip_interface("2001:db8::1%mgmt0/64", false).is_err());
        assert!(https_url("https://updates.example.org/feed").is_ok());
        assert!(https_url("HTTPS://updates.example.org/feed").is_ok());
        for value in [
            "http://updates.example.org",
            "https:updates.example.org",
            "https:/updates.example.org",
            "https:///updates.example.org",
            "https:////updates.example.org",
            "https://owner:secret@updates.example.org",
            "https://updates.example.org/%20",
            "https://updates.example.org/feed?other",
            "https://updates.example.invalid",
        ] {
            assert!(https_url(value).is_err());
        }
    }
}
