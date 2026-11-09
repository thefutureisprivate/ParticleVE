"""Strict resolved transport and explicit per-link routing for private DNS zones."""

import ipaddress
import json

from .common import Error, capture_bounded, require
from .config import dns_name

# The selected resolved build's documented built-in private/reserved-zone
# exceptions remain explicit. Additional exceptions must be per-link policy.
BUILTIN_NTA = {
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
    *(f"{i}.172.in-addr.arpa" for i in range(16, 32)),
}


def servers(value):
    require(type(value) is list and 1 <= len(value) <= 8, "configure 1..8 authenticated DNS endpoints")
    addresses = set()
    for server in value:
        require(type(server) is dict and set(server) == {"address", "tls_name"}, "unknown DNS endpoint")
        require(
            type(server["address"]) is str and "%" not in server["address"],
            "use an unscoped literal DNS address; private routing declares the link separately",
        )
        ip = ipaddress.ip_address(server["address"])
        require(
            str(ip) == server["address"]
            and not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local)
            and getattr(ip, "ipv4_mapped", None) is None,
            "use a canonical remote unicast DNS address",
        )
        require(str(ip) not in addresses, "duplicate DNS endpoint")
        addresses.add(str(ip))
        dns_name(server["tls_name"])
    return value


def validate(policy, links):
    require(type(policy) is dict and set(policy) == {"public", "private"}, "unknown DNS policy")
    servers(policy["public"])
    private = policy["private"]
    require(type(private) is list and len(private) <= 16, "bound private DNS routing policies")
    routed, used_links = [], set()
    for route in private:
        require(
            type(route) is dict and set(route) == {"link", "servers", "domains", "negative_trust_anchors"},
            "unknown private DNS routing policy",
        )
        require(
            route["link"] in links and route["link"] not in used_links, "one DNS policy per declared link"
        )
        used_links.add(route["link"])
        servers(route["servers"])
        domains = route["domains"]
        require(type(domains) is list and 1 <= len(domains) <= 32, "bound private DNS route domains")
        for domain in domains:
            dns_name(domain)
            require(
                all(
                    domain != other and not domain.endswith("." + other) and not other.endswith("." + domain)
                    for other in routed
                ),
                "private DNS routes must not overlap",
            )
            routed.append(domain)
        anchors = route["negative_trust_anchors"]
        require(type(anchors) is list and len(anchors) <= 32, "bound private DNSSEC exceptions")
        require(len(set(anchors)) == len(anchors), "duplicate private DNSSEC exception")
        for anchor in anchors:
            dns_name(anchor)
            require(
                any(anchor == domain or anchor.endswith("." + domain) for domain in domains),
                "DNSSEC exception must stay within this link's explicit private routes",
            )
    return policy


def endpoint(server):
    ip = server["address"]
    return ("[" + ip + "]" if ":" in ip else ip) + "#" + server["tls_name"]


def render(policy):
    # Configuration validation supplies the complete link topology before this
    # renderer is used. Certificate identities always use the OS trust store.
    return {
        "etc/systemd/resolved.conf.d/50-particleve.conf": "[Resolve]\nDNS=\nDNS="
        + " ".join(endpoint(server) for server in policy["public"])
        + "\nFallbackDNS=\nDomains=\nDomains=~.\nDNSOverTLS=yes\nDNSSEC=yes\n"
        + "LLMNR=no\nMulticastDNS=no\nDNSStubListener=yes\nResolveUnicastSingleLabel=no\n"
    }


def link_settings(policy, name):
    lines = ["DNSDefaultRoute=no", "DNSOverTLS=yes", "DNSSEC=yes", "LLMNR=no", "MulticastDNS=no"]
    route = next((route for route in policy["private"] if route["link"] == name), None)
    if route:
        lines.extend("DNS=" + endpoint(server) for server in route["servers"])
        lines.append("Domains=" + " ".join("~" + domain for domain in route["domains"]))
        lines.append("DNSSECNegativeTrustAnchors=" + " ".join(route["negative_trust_anchors"]))
    return lines


def assess(policy, observed, links):
    validate(policy, links)
    require(
        type(observed) is list and 1 <= len(observed) <= 4096 and all(type(row) is dict for row in observed),
        "unknown resolved status format",
    )
    global_rows = [row for row in observed if "ifname" not in row]
    require(len(global_rows) == 1, "missing or ambiguous global DNS status")
    global_row = global_rows[0]

    def endpoints(row):
        values = row.get("servers", [])
        require(type(values) is list and all(type(v) is dict for v in values), "unknown DNS server status")
        result = []
        for server in values:
            # resolved represents the configured default port as 53 even when
            # strict TLS selects its encrypted transport port internally.
            require(server.get("port") == 53, "unexpected DNS endpoint port")
            result.append((str(ipaddress.ip_address(server["addressString"])), server.get("name")))
        require(len(result) == len(set(result)), "duplicate effective DNS endpoint")
        return set(result)

    def domains(row):
        values = row.get("searchDomains", [])
        require(
            type(values) is list and all(type(v) is dict and v.get("routeOnly") is True for v in values),
            "DNS search suffixes or unknown routing status",
        )
        names = [v["name"] for v in values]
        require(len(names) == len(set(names)), "duplicate effective DNS route")
        return set(names)

    def strict(row):
        require(
            all(
                row.get(name) == value
                for name, value in {"dnsOverTLS": "yes", "dnssec": "yes", "llmnr": "no", "mDNS": "no"}.items()
            ),
            "effective DNS transport, DNSSEC or local-discovery policy drift",
        )

    strict(global_row)
    require(global_row.get("resolvConfMode") == "stub", "applications bypass the resolved stub")
    require(not global_row.get("fallbackServers"), "unreviewed fallback DNS endpoints")
    require(
        endpoints(global_row) == {(s["address"], s["tls_name"]) for s in policy["public"]},
        "effective public DNS endpoints differ",
    )
    require(domains(global_row) == {"."}, "public DNS routing policy drift")
    require(
        set(global_row.get("negativeTrustAnchors", [])) == BUILTIN_NTA, "global DNSSEC exception policy drift"
    )
    private = {route["link"]: route for route in policy["private"]}
    rows = [row for row in observed if "ifname" in row]
    by_name = {row["ifname"]: row for row in rows}
    require(len(rows) == len(by_name) and set(links) <= set(by_name), "missing or ambiguous DNS link status")
    for name, row in by_name.items():
        route = private.get(name)
        expected = {(s["address"], s["tls_name"]) for s in route["servers"]} if route else set()
        require(endpoints(row) == expected, "unexpected per-link DNS endpoint")
        require(domains(row) == (set(route["domains"]) if route else set()), "private DNS route drift")
        require(
            set(row.get("negativeTrustAnchors", []))
            == (set(route["negative_trust_anchors"]) if route else set()),
            "private DNSSEC exception drift",
        )
        if name in links:
            strict(row)
            require(row.get("defaultRoute") is False, "private DNS became a public default route")
        require(
            all(scope.get("protocol") == "dns" for scope in row.get("scopes", [])),
            "unexpected local DNS discovery scope",
        )
    return {"strict_tls": True, "dnssec": True, "private_route_count": len(private), "link_count": len(rows)}


def probe(network):
    observed = capture_bounded(
        ["/usr/bin/resolvectl", "--json=short", "status"], timeout=5, maximum_bytes=1024**2
    )
    require(observed.returncode == 0 and not observed.stderr, "effective DNS policy observation unavailable")
    try:
        status = json.loads(observed.stdout)
    except ValueError as exc:
        raise Error("invalid resolved machine status") from exc
    links = [device["name"] for kind in ("links", "bridges", "vlans") for device in network.get(kind, [])]
    return assess(network["dns"], status, links)
