"""Exercise authenticated clock policy with compiled machine-report validation."""

import csv
import io
import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests

MASKED_UNITS = ("systemd-timesyncd.service", "chronyd.service", "chrony-wait.service")

NOW = 1794182000


def policy():
    return {
        "sources": [
            {"server": "time-a.example.org", "operator": "operator_a", "trust": "system"},
            {"server": "time-b.example.org", "operator": "operator_b", "trust": "system"},
        ],
        "certificates": "",
    }


def encode(rows):
    stream = io.StringIO()
    csv.writer(stream, lineterminator="\n").writerows(rows)
    return stream.getvalue()


def reports():
    addresses = ["203.0.113.10", "203.0.113.20"]
    tracking = [
        "CB00710A",
        addresses[0],
        "2",
        str(NOW - 2),
        "0.001",
        "0.001",
        "0.001",
        "9.0",
        "0.01",
        "1.0",
        "0.02",
        "0.001",
        "64.0",
        "Normal",
    ]
    source_rows = [
        ["^", state, ip, "1", "6", "377", "2", "0.001", "0.001", "0.01"]
        for ip, state in zip(addresses, ["*", "+"], strict=True)
    ]
    auth = [[ip, "NTS", "1", "15", "256", "30", "0", "0", "8", "100"] for ip in addresses]
    packets = []
    for ip in addresses:
        row = ["0"] * 38
        row[0:9] = [ip, "CB00710A", "123", "203.0.113.1", "CB007101", "Normal", "4", "Server", "1"]
        row[23:28] = ["111", "111", "1111", "No", "Yes"]
        row[33] = "10"
        packets.append(row)
    return {
        "tracking": encode([tracking]),
        "sources": encode(source_rows),
        "authdata": encode(auth),
        "ntpdata": encode(packets),
        "names": dict(zip(addresses, [s["server"] for s in policy()["sources"]], strict=True)),
    }


def change(observation, report, row, field, value):
    data = list(csv.reader(observation[report].splitlines()))
    data[row][field] = value
    observation[report] = encode(data)


class AuthenticatedTimeTests(RustDriverTests):
    def test_unsafe_source_or_separate_certificate_trust_cannot_enter_configuration(self):
        for server in (
            "2001:db8::53%eth0",
            "2001:db8::53%eth0\nnocerttimecheck 1",
            "::ffff:101:101",
            "127.0.0.1",
            "::1",
            "localhost",
            "time.example.org\nlocal stratum 1",
        ):
            selected = policy()
            selected["sources"][0]["server"] = server
            self.assertIn("error", self.request("timesync-render", policy=selected))
        for field, value in (("certificates", "PRIVATE KEY"), ("sources", [])):
            selected = policy()
            selected[field] = value
            self.assertIn("error", self.request("timesync-render", policy=selected))
        selected = policy()
        selected["sources"][0]["trust"] = "installation"
        self.assertIn("system trust store", self.request("timesync-render", policy=selected)["error"])
        selected["sources"][0]["trust"] = "system"
        selected["certificates"] = "ignored trailing trust input"
        self.assertIn("system trust store", self.request("timesync-render", policy=selected)["error"])

    def test_changed_configuration_or_second_clock_owner_cannot_authorize_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in self.evaluate("timesync-render", policy=policy()).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            units = root / "usr/lib/systemd/system"
            units.mkdir(parents=True)
            for unit in MASKED_UNITS:
                (units / unit).symlink_to("/dev/null")
            self.evaluate("timesync-check", policy=policy(), root=str(root))
            path = root / "etc/chrony.conf"
            expected = path.read_text()
            path.write_text(expected + "server unreviewed.example.org\n")
            self.assertIn(
                "configuration drift",
                self.request("timesync-check", policy=policy(), root=str(root))["error"],
            )
            path.write_text(expected)
            for unit in MASKED_UNITS:
                mask = units / unit
                mask.unlink()
                self.assertIn(
                    "not masked", self.request("timesync-check", policy=policy(), root=str(root))["error"]
                )
                mask.symlink_to("/dev/null")

    def test_only_fresh_authenticated_agreement_can_authorize_activation(self):
        result = self.evaluate("timesync-assess", policy=policy(), reports=reports(), wall=NOW)
        self.assertEqual(result["operators"], ["operator_a", "operator_b"])
        self.assertLess(result["maximum_error_seconds"], 0.5)
        failures = [
            ("authdata", 0, 1, "-"),
            ("authdata", 1, 4, "0"),
            ("authdata", 1, 5, "86401"),
            ("authdata", 1, 8, "0"),
            ("ntpdata", 1, 27, "No"),
            ("ntpdata", 1, 23, "110"),
            ("sources", 1, 1, "x"),
            ("sources", 1, 6, "301"),
            ("sources", 1, 5, "000"),
            ("sources", 1, 7, "0.6"),
            ("sources", 1, 9, "0.6"),
            ("tracking", 0, 13, "Not synchronised"),
            ("tracking", 0, 4, "1.0"),
            ("tracking", 0, 3, str(NOW - 301)),
            ("tracking", 0, 3, str(NOW + 2)),
            ("tracking", 0, 11, "nan"),
            ("tracking", 0, 9, "inf"),
            ("tracking", 0, 1, "203.0.113.20"),
        ]
        for args in failures:
            observed = reports()
            change(observed, *args)
            with self.subTest(change=args):
                self.assertIn(
                    "error", self.request("timesync-assess", policy=policy(), reports=observed, wall=NOW)
                )

    def test_selectable_uncombined_authenticated_source_can_supply_agreement(self):
        observed = reports()
        change(observed, "sources", 1, 1, "-")
        self.assertEqual(
            self.evaluate("timesync-assess", policy=policy(), reports=observed, wall=NOW)["operators"],
            ["operator_a", "operator_b"],
        )
        change(observed, "authdata", 1, 1, "-")
        self.assertIn(
            "not authenticated",
            self.request("timesync-assess", policy=policy(), reports=observed, wall=NOW)["error"],
        )

    def test_duplicate_unreviewed_and_oversized_observations_are_not_votes(self):
        for kind in ("operator", "address", "name", "packet", "format", "size"):
            selected, observed = policy(), reports()
            if kind == "operator":
                selected["sources"][1]["operator"] = "operator_a"
            elif kind == "address":
                change(observed, "sources", 1, 2, "203.0.113.10")
            elif kind == "name":
                observed["names"]["203.0.113.10"] = "unknown.example.org"
            elif kind == "packet":
                observed["ntpdata"] += observed["ntpdata"].splitlines()[0] + "\n"
            elif kind == "size":
                observed["sources"] = "x" * 65537
            else:
                observed["ntpdata"] = encode(
                    [row[:-1] for row in csv.reader(observed["ntpdata"].splitlines())]
                )
            self.assertIn(
                "error", self.request("timesync-assess", policy=selected, reports=observed, wall=NOW)
            )

    def test_renderer_has_one_authenticated_system_trust_policy_and_no_bypass(self):
        files = self.evaluate("timesync-render", policy=policy())
        self.assertEqual(set(files), {"etc/chrony.conf"})
        content = files["etc/chrony.conf"]
        self.assertIn("authselectmode require\nminsources 2\n", content)
        self.assertIn("port 0\ncmdport 0\n", content)
        self.assertEqual(content.count(" nts certset 0 "), 2)
        for directive in (
            "nocerttimecheck",
            "pool ",
            "include ",
            "sourcedir",
            "allow ",
            "local ",
            "ntstrustedcerts",
        ):
            self.assertNotIn(directive, content)
