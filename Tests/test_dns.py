"""Exercise strict resolver policy through the compiled implementation."""

import copy

from Tests.fixtures import host
from Tests.runtime import RustDriverTests

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
    *(f"{index}.172.in-addr.arpa" for index in range(16, 32)),
}


def configured():
    config = host()
    config["network"]["dns"]["private"] = [
        {
            "link": "mgmt0",
            "servers": [{"address": "192.0.2.53", "tls_name": "dns.example.org"}],
            "domains": ["corp.example.org"],
            "negative_trust_anchors": ["unsigned.corp.example.org"],
        }
    ]
    return config


def observation(config):
    policy = config["network"]["dns"]
    strict = {"dnsOverTLS": "yes", "dnssec": "yes", "llmnr": "no", "mDNS": "no"}

    def servers(values):
        return [{"addressString": v["address"], "name": v["tls_name"], "port": 53} for v in values]

    return [
        {
            **strict,
            "servers": servers(policy["public"]),
            "resolvConfMode": "stub",
            "searchDomains": [{"name": ".", "routeOnly": True}],
            "negativeTrustAnchors": sorted(BUILTIN_NTA | set(policy["private"][0]["negative_trust_anchors"])),
        },
        {
            **strict,
            "ifname": "mgmt0",
            "ifindex": 2,
            "defaultRoute": False,
            "servers": servers(policy["private"][0]["servers"]),
            "searchDomains": [{"name": "corp.example.org", "routeOnly": True}],
            "negativeTrustAnchors": ["unsigned.corp.example.org"],
            "scopes": [{"protocol": "dns", "dnsOverTLS": "yes", "dnssec": "yes"}],
        },
        {"ifname": "ns-guest", "defaultRoute": False, "scopes": []},
        {
            "delegate": "50-particleve-private",
            "defaultRoute": False,
            "servers": [dict(row, ifindex=2) for row in servers(policy["private"][0]["servers"])],
            "searchDomains": [{"name": "corp.example.org", "routeOnly": True}],
            "scopes": [{"protocol": "dns", "dnsOverTLS": "yes", "dnssec": "yes"}],
        },
    ]


class DNSPolicyTests(RustDriverTests):
    def test_declared_but_unaddressed_private_interface_is_rejected(self):
        config = configured()
        config["network"]["links"].append({"name": "priv0", "mac": "52:54:00:23:00:02"})
        config["network"]["dns"]["private"][0]["link"] = "priv0"
        self.assertIn("error", self.request("config-validate", config=config))

    def test_private_delegation_survives_link_scope_loss_and_requires_management_binding(self):
        config = configured()
        files = self.evaluate("dns-runtime-files", network=config["network"], ifindex=2)
        delegate = files["delegates/50-particleve-private.dns-delegate"]
        self.assertIn("DNS=192.0.2.53%2#dns.example.org\n", delegate)
        self.assertIn("Domains=~corp.example.org\nDefaultRoute=no\n", delegate)
        anchors = set(files["anchors/50-particleve.negative"].splitlines())
        self.assertEqual(anchors, BUILTIN_NTA | {"unsigned.corp.example.org"})
        self.assertIn("DNSOverTLS=yes\nDNSSEC=yes\n", files["resolved.conf.d/90-particleve.conf"])
        self.assertIn("error", self.request("dns-runtime-files", network=config["network"]))
        for mutation in (
            "lost_link_scope",
            "lost_delegate",
            "lost_delegate_scope",
            "wrong_delegate_interface",
            "insecure_delegate_scope",
        ):
            rows = observation(config)
            if mutation == "lost_link_scope":
                rows[1]["scopes"] = []
            elif mutation == "lost_delegate":
                rows.pop()
            elif mutation == "lost_delegate_scope":
                rows[-1]["scopes"] = []
            elif mutation == "wrong_delegate_interface":
                rows[-1]["servers"][0]["ifindex"] = 3
            else:
                rows[-1]["scopes"][0]["dnsOverTLS"] = "no"
            with self.subTest(mutation=mutation):
                self.assertIn(
                    "error",
                    self.request(
                        "dns-assess",
                        policy=config["network"]["dns"],
                        observed=rows,
                        links=["mgmt0"],
                        management="mgmt0",
                    ),
                )

    def test_private_routes_require_strict_tls_dnssec_and_scoped_exceptions(self):
        config = configured()
        self.evaluate("config-validate", config=config)
        files = self.evaluate("network-render", config=config)
        global_config = files["etc/systemd/resolved.conf.d/50-particleve.conf"]
        self.assertIn("DNSOverTLS=yes\nDNSSEC=yes\n", global_config)
        self.assertIn("FallbackDNS=\n", global_config)
        self.assertNotIn("opportunistic", global_config)
        link = files["etc/systemd/network/30-particleve-mgmt0.network"]
        for line in (
            "DNS=192.0.2.53#dns.example.org",
            "Domains=~corp.example.org",
            "DNSDefaultRoute=no",
            "DNSSECNegativeTrustAnchors=unsigned.corp.example.org",
        ):
            self.assertIn(line + "\n", link)
        self.assertNotIn("NTP=", link)
        self.assertFalse(any("timesyncd" in name for name in files))
        self.assertEqual(
            self.evaluate("dns-endpoint", server={"address": "2001:db8::53", "tls_name": "dns.example.org"}),
            "[2001:db8::53]#dns.example.org",
        )

    def test_unsafe_resolver_identities_and_private_route_expansion_are_rejected(self):
        for mutation in (
            "missing_sni",
            "local",
            "scope_injection",
            "mapped_alias",
            "global_nta",
            "other_link",
            "overlap",
            "root",
            "plaintext",
        ):
            config = configured()
            dns = config["network"]["dns"]
            route = dns["private"][0]
            if mutation == "missing_sni":
                dns["public"][0]["tls_name"] = ""
            elif mutation == "local":
                dns["public"][0]["address"] = "127.0.0.1"
            elif mutation == "scope_injection":
                dns["public"][0]["address"] = "2001:db8::53%eth0\nDNSOverTLS=no"
            elif mutation == "mapped_alias":
                dns["public"][0]["address"] = "::ffff:101:101"
            elif mutation == "global_nta":
                route["negative_trust_anchors"] = ["example.org"]
            elif mutation == "other_link":
                route["link"] = "undeclared"
            elif mutation == "overlap":
                route["domains"].append("child.corp.example.org")
            elif mutation == "root":
                route["domains"] = ["."]
            else:
                dns["opportunistic"] = True
            with self.subTest(mutation=mutation):
                self.assertIn("error", self.request("config-validate", config=config))

    def test_effective_policy_detects_transport_downgrade_routing_and_trust_drift(self):
        config = configured()
        expected = observation(config)
        self.assertTrue(
            self.evaluate(
                "dns-assess",
                policy=config["network"]["dns"],
                observed=expected,
                links=["mgmt0"],
                management="mgmt0",
            )["strict_tls"]
        )
        for mutation in (
            "tls",
            "dnssec",
            "discovery",
            "sni",
            "endpoint",
            "fallback",
            "stub",
            "public_route",
            "private_route",
            "search",
            "default",
            "global_nta",
            "private_nta",
            "guest_dns",
            "guest_discovery",
            "duplicate",
        ):
            rows = copy.deepcopy(expected)
            if mutation == "tls":
                rows[0]["dnsOverTLS"] = "opportunistic"
            elif mutation == "dnssec":
                rows[0]["dnssec"] = "allow-downgrade"
            elif mutation == "discovery":
                rows[1]["llmnr"] = "resolve"
            elif mutation == "sni":
                rows[0]["servers"][0]["name"] = "other.example.org"
            elif mutation == "endpoint":
                rows[1]["servers"][0]["addressString"] = "192.0.2.54"
            elif mutation == "fallback":
                rows[0]["fallbackServers"] = [{"addressString": "192.0.2.55"}]
            elif mutation == "stub":
                rows[0]["resolvConfMode"] = "foreign"
            elif mutation == "public_route":
                rows[0]["searchDomains"] = []
            elif mutation == "private_route":
                rows[1]["searchDomains"][0]["name"] = "."
            elif mutation == "search":
                rows[1]["searchDomains"][0]["routeOnly"] = False
            elif mutation == "default":
                rows[1]["defaultRoute"] = True
            elif mutation == "global_nta":
                rows[0]["negativeTrustAnchors"].append("example.org")
            elif mutation == "private_nta":
                rows[1]["negativeTrustAnchors"].append("example.org")
            elif mutation == "guest_dns":
                rows[2]["servers"] = rows[0]["servers"]
            elif mutation == "guest_discovery":
                rows[2]["scopes"] = [{"protocol": "llmnr"}]
            else:
                rows.append(rows[1])
            with self.subTest(mutation=mutation):
                self.assertIn(
                    "error",
                    self.request(
                        "dns-assess",
                        policy=config["network"]["dns"],
                        observed=rows,
                        links=["mgmt0"],
                        management="mgmt0",
                    ),
                )

    def test_obsolete_installation_contract_cannot_be_implicitly_converted(self):
        config = host()
        config["schema"] = 1
        self.assertIn("no implicit migrations", self.request("config-validate", config=config)["error"])
