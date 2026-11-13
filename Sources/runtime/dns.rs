//! Strict resolved transport and explicit private-zone link routing.
use crate::common::{Error, Result, command, field, list, object, parse_json, require, text};
use crate::config::dns_name;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};
pub const RUNTIME: &str = "/run/particleve-dns-policy";
pub const PRIVATE_DELEGATE: &str = "50-particleve-private";
pub fn remote_address(value: &str) -> Result<String> {
    require(
        !value.contains('%'),
        "use an unscoped literal remote address",
    )?;
    let ip: IpAddr = value
        .parse()
        .map_err(|_| Error::new("invalid literal IP address"))?;
    let valid = match ip {
        IpAddr::V4(v) => {
            !v.is_loopback() && !v.is_unspecified() && !v.is_multicast() && !v.is_link_local()
        }
        IpAddr::V6(v) => {
            !v.is_loopback()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_unicast_link_local()
                && v.to_ipv4_mapped().is_none()
        }
    };
    require(
        valid,
        "authenticated endpoints need distinct remote unicast addresses",
    )?;
    Ok(ip.to_string())
}
fn keys(value: &Value, expected: &[&str], message: &str) -> Result<()> {
    let map = object(value)?;
    require(
        map.len() == expected.len() && expected.iter().all(|name| map.contains_key(*name)),
        message,
    )
}
pub fn servers(value: &Value) -> Result<()> {
    let servers = list(value)?;
    require(
        (1..=8).contains(&servers.len()),
        "configure 1..8 authenticated DNS endpoints",
    )?;
    let mut addresses = BTreeSet::new();
    for server in servers {
        keys(server, &["address", "tls_name"], "unknown DNS endpoint")?;
        let address = text(field(server, "address")?)?;
        require(
            remote_address(address)? == address && addresses.insert(address),
            "use unique canonical remote unicast DNS addresses",
        )?;
        dns_name(text(field(server, "tls_name")?)?)?;
    }
    Ok(())
}
pub fn validate(policy: &Value, links: &[String]) -> Result<()> {
    keys(policy, &["public", "private"], "unknown DNS policy")?;
    servers(field(policy, "public")?)?;
    let private = list(field(policy, "private")?)?;
    require(private.len() <= 16, "bound private DNS routing policies")?;
    let mut routed = Vec::<String>::new();
    let mut used = BTreeSet::new();
    for route in private {
        keys(
            route,
            &["link", "servers", "domains", "negative_trust_anchors"],
            "unknown private DNS routing policy",
        )?;
        let link = text(field(route, "link")?)?;
        require(
            links.iter().any(|l| l == link) && used.insert(link),
            "one DNS policy per declared link",
        )?;
        servers(field(route, "servers")?)?;
        let domains = list(field(route, "domains")?)?;
        require(
            (1..=32).contains(&domains.len()),
            "bound private DNS route domains",
        )?;
        for d in domains {
            let domain = dns_name(text(d)?)?;
            require(
                routed.iter().all(|other| {
                    domain != other
                        && !domain.ends_with(&format!(".{other}"))
                        && !other.ends_with(&format!(".{domain}"))
                }),
                "private DNS routes must not overlap",
            )?;
            routed.push(domain.into());
        }
        let anchors = list(field(route, "negative_trust_anchors")?)?;
        require(anchors.len() <= 32, "bound private DNSSEC exceptions")?;
        let mut unique = BTreeSet::new();
        for anchor in anchors {
            let anchor = dns_name(text(anchor)?)?;
            require(unique.insert(anchor), "duplicate private DNSSEC exception")?;
            require(
                domains.iter().any(|d| {
                    d.as_str()
                        .is_some_and(|d| anchor == d || anchor.ends_with(&format!(".{d}")))
                }),
                "DNSSEC exception must stay within this link's explicit private routes",
            )?;
        }
    }
    Ok(())
}
pub fn endpoint(server: &Value) -> Result<String> {
    let ip = text(field(server, "address")?)?;
    let name = text(field(server, "tls_name")?)?;
    Ok(if ip.contains(':') {
        format!("[{ip}]#{name}")
    } else {
        format!("{ip}#{name}")
    })
}
pub fn render(policy: &Value) -> Result<BTreeMap<String, String>> {
    let endpoints = list(field(policy, "public")?)?
        .iter()
        .map(endpoint)
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    Ok(BTreeMap::from([(
        "etc/systemd/resolved.conf.d/50-particleve.conf".into(),
        format!(
            "[Resolve]\nDNS=\nDNS={endpoints}\nFallbackDNS=\nDomains=\nDomains=~.\nDNSOverTLS=yes\nDNSSEC=yes\nLLMNR=no\nMulticastDNS=no\nDNSStubListener=yes\nResolveUnicastSingleLabel=no\n"
        ),
    )]))
}
fn negative_anchors(policy: &Value) -> Result<BTreeSet<String>> {
    let mut anchors = nta();
    for route in list(field(policy, "private")?)? {
        anchors.extend(strings(field(route, "negative_trust_anchors")?)?);
    }
    Ok(anchors)
}
pub fn runtime_files(network: &Value, ifindex: Option<u32>) -> Result<BTreeMap<String, String>> {
    let policy = field(network, "dns")?;
    validate(policy, &[text(field(network, "management")?)?.to_owned()])?;
    let mut files = BTreeMap::from([
        (
            "resolved.conf.d/90-particleve.conf".into(),
            render(policy)?["etc/systemd/resolved.conf.d/50-particleve.conf"].clone(),
        ),
        (
            "anchors/50-particleve.negative".into(),
            negative_anchors(policy)?
                .into_iter()
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        ),
    ]);
    if let Some(route) = list(field(policy, "private")?)?.first() {
        let index = ifindex
            .filter(|i| *i > 0)
            .ok_or_else(|| Error::new("private DNS management interface is unavailable"))?;
        let servers = list(field(route, "servers")?)?
            .iter()
            .map(|server| {
                let value = endpoint(server)?;
                let (address, name) = value
                    .split_once('#')
                    .ok_or_else(|| Error::new("DNS endpoint lacks TLS identity"))?;
                Ok(format!("{address}%{index}#{name}"))
            })
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let domains = list(field(route, "domains")?)?
            .iter()
            .map(|v| text(v).map(|s| format!("~{s}")))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        files.insert(
            format!("delegates/{PRIVATE_DELEGATE}.dns-delegate"),
            format!("[Delegate]\nDNS={servers}\nDomains={domains}\nDefaultRoute=no\n"),
        );
    }
    Ok(files)
}
fn management_index(name: &str) -> Result<u32> {
    let name = CString::new(name).map_err(|_| Error::new("invalid management interface"))?;
    let started = Instant::now();
    loop {
        // SAFETY: libc observes this live NUL-terminated name and retains no pointer.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index > 0 {
            return Ok(index);
        }
        let error = std::io::Error::last_os_error();
        require(
            matches!(
                error.raw_os_error(),
                Some(libc::ENODEV | libc::ENXIO | libc::ENOENT)
            ),
            format!("cannot inspect management interface: {error}"),
        )?;
        require(
            started.elapsed() < Duration::from_secs(30),
            "management interface did not appear for private DNS",
        )?;
        std::thread::sleep(Duration::from_millis(50));
    }
}
pub fn write_runtime(network: &Value, root: &Path) -> Result<()> {
    let index = if list(field(field(network, "dns")?, "private")?)?.is_empty() {
        None
    } else {
        Some(management_index(text(field(network, "management")?)?)?)
    };
    let files = runtime_files(network, index)?;
    require(!root.is_symlink(), "DNS runtime directory is a symlink")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    for name in ["delegates", "anchors", "resolved.conf.d"] {
        let directory = root.join(name);
        require(!directory.is_symlink(), "DNS policy directory is a symlink")?;
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let relative = format!("{name}/{}", entry.file_name().to_string_lossy());
            require(
                entry.file_type()?.is_file(),
                "unexpected non-file DNS runtime input",
            )?;
            require(
                matches!(
                    relative.as_str(),
                    "anchors/50-particleve.negative" | "resolved.conf.d/90-particleve.conf"
                ) || relative == format!("delegates/{PRIVATE_DELEGATE}.dns-delegate"),
                "unknown file in managed DNS policy",
            )?;
            if !files.contains_key(&relative) {
                fs::remove_file(entry.path())?;
            }
        }
    }
    for (name, content) in files {
        crate::common::atomic_write(root.join(name), content.as_bytes(), 0o644)?;
    }
    Ok(())
}
pub fn link_settings(policy: &Value, name: &str) -> Result<Vec<String>> {
    let mut lines = [
        "DNSDefaultRoute=no",
        "DNSOverTLS=yes",
        "DNSSEC=yes",
        "LLMNR=no",
        "MulticastDNS=no",
    ]
    .map(String::from)
    .to_vec();
    if let Some(route) = list(field(policy, "private")?)?
        .iter()
        .find(|r| r["link"] == name)
    {
        for server in list(field(route, "servers")?)? {
            lines.push(format!("DNS={}", endpoint(server)?));
        }
        lines.push(format!(
            "Domains={}",
            list(field(route, "domains")?)?
                .iter()
                .map(|v| text(v).map(|v| format!("~{v}")))
                .collect::<Result<Vec<_>>>()?
                .join(" ")
        ));
        lines.push(format!(
            "DNSSECNegativeTrustAnchors={}",
            list(field(route, "negative_trust_anchors")?)?
                .iter()
                .map(|v| text(v).map(str::to_owned))
                .collect::<Result<Vec<_>>>()?
                .join(" ")
        ));
    }
    Ok(lines)
}
fn strings(value: &Value) -> Result<BTreeSet<String>> {
    list(value)?
        .iter()
        .map(|v| text(v).map(String::from))
        .collect()
}
fn values(row: &Value, key: &str) -> Result<Vec<Value>> {
    row.get(key)
        .map(|v| list(v).cloned())
        .transpose()
        .map(|v| v.unwrap_or_default())
}
fn endpoints(row: &Value) -> Result<BTreeSet<(String, String)>> {
    let mut result = BTreeSet::new();
    for server in values(row, "servers")? {
        require(server["port"] == 53, "unexpected DNS endpoint port")?;
        let ip: IpAddr = text(field(&server, "addressString")?)?
            .parse()
            .map_err(|_| Error::new("invalid DNS observation address"))?;
        require(
            result.insert((ip.to_string(), text(field(&server, "name")?)?.into())),
            "duplicate effective DNS endpoint",
        )?;
    }
    Ok(result)
}
fn expected_endpoints(value: &Value) -> Result<BTreeSet<(String, String)>> {
    list(value)?
        .iter()
        .map(|s| {
            Ok((
                text(field(s, "address")?)?.into(),
                text(field(s, "tls_name")?)?.into(),
            ))
        })
        .collect()
}
fn domains(row: &Value) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for v in values(row, "searchDomains")? {
        require(
            v["routeOnly"] == true,
            "DNS search suffixes or unknown routing status",
        )?;
        require(
            result.insert(text(field(&v, "name")?)?.into()),
            "duplicate effective DNS route",
        )?;
    }
    Ok(result)
}
fn strict(row: &Value) -> Result<()> {
    require(
        [
            ("dnsOverTLS", "yes"),
            ("dnssec", "yes"),
            ("llmnr", "no"),
            ("mDNS", "no"),
        ]
        .iter()
        .all(|(k, v)| row[*k] == *v),
        "effective DNS transport, DNSSEC or local-discovery policy drift",
    )
}
fn nta() -> BTreeSet<String> {
    let mut values = [
        "home.arpa",
        "10.in-addr.arpa",
        "168.192.in-addr.arpa",
        "d.f.ip6.arpa",
        "170.0.0.192.in-addr.arpa",
        "171.0.0.192.in-addr.arpa",
        "ipv4only.arpa",
        "resolver.arpa",
        "corp",
        "home",
        "internal",
        "intranet",
        "lan",
        "local",
        "private",
        "test",
    ]
    .map(String::from)
    .into_iter()
    .collect::<BTreeSet<_>>();
    for i in 16..32 {
        values.insert(format!("{i}.172.in-addr.arpa"));
    }
    values
}
pub fn assess(
    policy: &Value,
    observed: &Value,
    links: &[String],
    management: &str,
) -> Result<Value> {
    validate(policy, &[management.to_owned()])?;
    let rows = list(observed)?;
    require(
        (1..=4096).contains(&rows.len()) && rows.iter().all(Value::is_object),
        "unknown resolved status format",
    )?;
    let global: Vec<_> = rows
        .iter()
        .filter(|r| r.get("ifname").is_none() && r.get("delegate").is_none())
        .collect();
    require(global.len() == 1, "missing or ambiguous global DNS status")?;
    let global = global[0];
    strict(global)?;
    require(
        global["resolvConfMode"] == "stub",
        "applications bypass the resolved stub",
    )?;
    require(
        global
            .get("fallbackServers")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "unreviewed fallback DNS endpoints",
    )?;
    require(
        endpoints(global)? == expected_endpoints(field(policy, "public")?)?,
        "effective public DNS endpoints differ",
    )?;
    require(
        domains(global)? == BTreeSet::from([".".into()]),
        "public DNS routing policy drift",
    )?;
    require(
        strings(global.get("negativeTrustAnchors").unwrap_or(&json!([])))?
            == negative_anchors(policy)?,
        "global DNSSEC exception policy drift",
    )?;
    let private = list(field(policy, "private")?)?;
    let mut names = BTreeSet::new();
    let mut count = 0;
    for row in rows.iter().filter(|r| r.get("ifname").is_some()) {
        count += 1;
        let name = text(field(row, "ifname")?)?;
        require(names.insert(name), "missing or ambiguous DNS link status")?;
        let route = private.iter().find(|r| r["link"] == name);
        let expected = route
            .map(|r| expected_endpoints(&r["servers"]))
            .transpose()?
            .unwrap_or_default();
        require(
            endpoints(row)? == expected,
            "unexpected per-link DNS endpoint",
        )?;
        require(
            domains(row)?
                == route
                    .map(|r| strings(&r["domains"]))
                    .transpose()?
                    .unwrap_or_default(),
            "private DNS route drift",
        )?;
        require(
            strings(row.get("negativeTrustAnchors").unwrap_or(&json!([])))?
                == route
                    .map(|r| strings(&r["negative_trust_anchors"]))
                    .transpose()?
                    .unwrap_or_default(),
            "private DNSSEC exception drift",
        )?;
        if links.iter().any(|l| l == name) {
            strict(row)?;
            require(
                row["defaultRoute"] == false,
                "private DNS became a public default route",
            )?;
        }
        require(
            values(row, "scopes")?
                .iter()
                .all(|s| s["protocol"] == "dns"),
            "unexpected local DNS discovery scope",
        )?;
        if route.is_some() {
            require(
                !values(row, "scopes")?.is_empty(),
                "private DNS link has no active unicast scope",
            )?;
        }
    }
    require(
        links.iter().all(|l| names.contains(l.as_str())),
        "missing or ambiguous DNS link status",
    )?;
    let delegates = rows
        .iter()
        .filter(|row| row.get("delegate").is_some())
        .collect::<Vec<_>>();
    require(
        delegates.len() == private.len(),
        "missing or unexpected private DNS delegation",
    )?;
    if let Some(route) = private.first() {
        let row = delegates[0];
        require(
            row["delegate"] == PRIVATE_DELEGATE
                && row.get("ifname").is_none()
                && row["defaultRoute"] == false,
            "private DNS delegate identity or default-route drift",
        )?;
        require(
            endpoints(row)? == expected_endpoints(&route["servers"])?
                && domains(row)? == strings(&route["domains"])?
                && !values(row, "scopes")?.is_empty()
                && values(row, "scopes")?.iter().all(|s| {
                    s["protocol"] == "dns" && s["dnsOverTLS"] == "yes" && s["dnssec"] == "yes"
                }),
            "private DNS delegation has no matching active scope",
        )?;
        let managed = rows
            .iter()
            .find(|r| r["ifname"] == management)
            .ok_or_else(|| Error::new("missing management DNS status"))?;
        let index = crate::common::uint(field(managed, "ifindex")?)?;
        require(
            index > 0
                && values(row, "servers")?
                    .iter()
                    .all(|s| s["ifindex"].as_u64() == Some(index)),
            "private DNS delegation is not bound to management",
        )?;
    }
    Ok(
        json!({"strict_tls":true,"dnssec":true,"private_route_count":private.len(),"link_count":count}),
    )
}
pub fn probe(network: &Value) -> Result<Value> {
    let observed = command(
        &[
            "/usr/bin/resolvectl".into(),
            "--json=short".into(),
            "status".into(),
        ],
        None,
        Some(Duration::from_secs(5)),
        1024 * 1024,
        false,
    )?;
    require(
        observed.code == 0 && observed.stderr.is_empty(),
        "effective DNS policy observation unavailable",
    )?;
    let status = parse_json(observed.stdout.as_bytes())?;
    let mut links = Vec::new();
    for kind in ["links", "bridges", "vlans"] {
        if let Some(devices) = network.get(kind) {
            for device in list(devices)? {
                links.push(text(field(device, "name")?)?.into());
            }
        }
    }
    assess(
        field(network, "dns")?,
        &status,
        &links,
        text(field(network, "management")?)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Value {
        json!({"public":[{"address":"1.1.1.1","tls_name":"cloudflare-dns.com"}],"private":[{"link":"mgmt0","servers":[{"address":"192.0.2.53","tls_name":"dns.example.org"}],"domains":["corp.example.org"],"negative_trust_anchors":["unsigned.corp.example.org"]}]})
    }
    fn observation() -> Value {
        let mut global = json!({"dnsOverTLS":"yes","dnssec":"yes","llmnr":"no","mDNS":"no","servers":[{"addressString":"1.1.1.1","name":"cloudflare-dns.com","port":53}],"resolvConfMode":"stub","searchDomains":[{"name":".","routeOnly":true}]});
        global["negativeTrustAnchors"] = json!(negative_anchors(&policy()).unwrap());
        json!([global,{"dnsOverTLS":"yes","dnssec":"yes","llmnr":"no","mDNS":"no","ifname":"mgmt0","ifindex":2,"defaultRoute":false,"servers":[{"addressString":"192.0.2.53","name":"dns.example.org","port":53}],"searchDomains":[{"name":"corp.example.org","routeOnly":true}],"negativeTrustAnchors":["unsigned.corp.example.org"],"scopes":[{"protocol":"dns"}]},{"ifname":"ns-guest","defaultRoute":false,"scopes":[]},{"delegate":PRIVATE_DELEGATE,"defaultRoute":false,"servers":[{"addressString":"192.0.2.53","name":"dns.example.org","port":53,"ifindex":2}],"searchDomains":[{"name":"corp.example.org","routeOnly":true}],"scopes":[{"protocol":"dns","dnsOverTLS":"yes","dnssec":"yes"}]}])
    }
    #[test]
    fn strict_effective_policy_rejects_transport_routing_and_trust_drift() {
        let links = vec!["mgmt0".into()];
        assert!(assess(&policy(), &observation(), &links, "mgmt0").is_ok());
        for (kind, value) in [
            ("dnsOverTLS", json!("opportunistic")),
            ("dnssec", json!("allow-downgrade")),
            ("resolvConfMode", json!("foreign")),
            ("fallbackServers", json!([{"addressString":"192.0.2.55"}])),
            ("negativeTrustAnchors", json!(["example.org"])),
        ] {
            let mut status = observation();
            status[0][kind] = value;
            assert!(
                assess(&policy(), &status, &links, "mgmt0").is_err(),
                "{kind}"
            );
        }
        let mut status = observation();
        status[1]["defaultRoute"] = true.into();
        assert!(assess(&policy(), &status, &links, "mgmt0").is_err());
        status = observation();
        status[2]["servers"] = status[0]["servers"].clone();
        assert!(assess(&policy(), &status, &links, "mgmt0").is_err());
    }
    #[test]
    fn private_exceptions_cannot_expand_or_overlap_routes() {
        let links = vec!["mgmt0".into()];
        let mut policy = policy();
        policy["private"][0]["domains"] = json!(["corp.example.org", "child.corp.example.org"]);
        assert!(validate(&policy, &links).is_err());
        policy["private"][0]["domains"] = json!(["corp.example.org"]);
        policy["private"][0]["negative_trust_anchors"] = json!(["example.org"]);
        assert!(validate(&policy, &links).is_err());
        assert_eq!(
            endpoint(&json!({"address":"2001:db8::53","tls_name":"dns.example.org"}))
                .expect("IPv6 endpoint"),
            "[2001:db8::53]#dns.example.org"
        );
    }
}
