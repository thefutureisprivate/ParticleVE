//! Strict resolved transport and explicit private-zone link routing.
use crate::common::{Error, Result, command, field, list, object, parse_json, require, text};
use crate::config::dns_name;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};
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
pub fn assess(policy: &Value, observed: &Value, links: &[String]) -> Result<Value> {
    validate(policy, links)?;
    let rows = list(observed)?;
    require(
        (1..=4096).contains(&rows.len()) && rows.iter().all(Value::is_object),
        "unknown resolved status format",
    )?;
    let global: Vec<_> = rows.iter().filter(|r| r.get("ifname").is_none()).collect();
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
        strings(global.get("negativeTrustAnchors").unwrap_or(&json!([])))? == nta(),
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
    }
    require(
        links.iter().all(|l| names.contains(l.as_str())),
        "missing or ambiguous DNS link status",
    )?;
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
    assess(field(network, "dns")?, &status, &links)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Value {
        json!({"public":[{"address":"1.1.1.1","tls_name":"cloudflare-dns.com"}],"private":[{"link":"mgmt0","servers":[{"address":"192.0.2.53","tls_name":"dns.example.org"}],"domains":["corp.example.org"],"negative_trust_anchors":["unsigned.corp.example.org"]}]})
    }
    fn observation() -> Value {
        let mut global = json!({"dnsOverTLS":"yes","dnssec":"yes","llmnr":"no","mDNS":"no","servers":[{"addressString":"1.1.1.1","name":"cloudflare-dns.com","port":53}],"resolvConfMode":"stub","searchDomains":[{"name":".","routeOnly":true}]});
        global["negativeTrustAnchors"] = json!(nta());
        json!([global,{"dnsOverTLS":"yes","dnssec":"yes","llmnr":"no","mDNS":"no","ifname":"mgmt0","defaultRoute":false,"servers":[{"addressString":"192.0.2.53","name":"dns.example.org","port":53}],"searchDomains":[{"name":"corp.example.org","routeOnly":true}],"negativeTrustAnchors":["unsigned.corp.example.org"],"scopes":[{"protocol":"dns"}]},{"ifname":"ns-guest","defaultRoute":false,"scopes":[]}])
    }
    #[test]
    fn strict_effective_policy_rejects_transport_routing_and_trust_drift() {
        let links = vec!["mgmt0".into()];
        assert!(assess(&policy(), &observation(), &links).is_ok());
        for (kind, value) in [
            ("dnsOverTLS", json!("opportunistic")),
            ("dnssec", json!("allow-downgrade")),
            ("resolvConfMode", json!("foreign")),
            ("fallbackServers", json!([{"addressString":"192.0.2.55"}])),
            ("negativeTrustAnchors", json!(["example.org"])),
        ] {
            let mut status = observation();
            status[0][kind] = value;
            assert!(assess(&policy(), &status, &links).is_err(), "{kind}");
        }
        let mut status = observation();
        status[1]["defaultRoute"] = true.into();
        assert!(assess(&policy(), &status, &links).is_err());
        status = observation();
        status[2]["servers"] = status[0]["servers"].clone();
        assert!(assess(&policy(), &status, &links).is_err());
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
