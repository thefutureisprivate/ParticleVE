import copy
import csv
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from particleve.timesync import MASKED_UNITS, assess, check_configuration, probe, render, validate

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


class AuthenticatedTimeTests(unittest.TestCase):
    def test_ipv6_scope_text_cannot_inject_clock_configuration(self):
        for server in ("2001:db8::53%eth0", "2001:db8::53%eth0\nnocerttimecheck 1"):
            selected = policy()
            selected["sources"][0]["server"] = server
            with self.subTest(server=server), self.assertRaisesRegex(Error, "unscoped"):
                render(selected)
        selected = policy()
        selected["sources"][0]["server"] = "::ffff:101:101"
        with self.assertRaisesRegex(Error, "remote unicast"):
            render(selected)

    def test_public_trust_input_cannot_publish_ignored_trailing_data(self):
        selected = policy()
        selected["sources"][0]["trust"] = "installation"
        certificate = (
            Path(__file__).resolve().parent.parent / "mkosi.extra/usr/lib/particleve/trust/secure-boot.crt"
        ).read_text()
        selected["certificates"] = certificate
        validate(selected)
        selected["certificates"] += "\nowner-private-notes-that-TLS-would-ignore\n"
        with self.assertRaisesRegex(Error, "only PEM certificates"):
            validate(selected)

    def test_changed_configuration_or_second_clock_owner_cannot_authorize_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in render(policy()).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            unit_directory = root / "usr/lib/systemd/system"
            unit_directory.mkdir(parents=True)
            for unit in MASKED_UNITS:
                (unit_directory / unit).symlink_to("/dev/null")
            check_configuration(policy(), root=root)
            path = root / "etc/chrony.conf"
            expected = path.read_text()
            path.write_text(expected + "server unauthenticated.example.org\n")
            with self.assertRaisesRegex(Error, "configuration drift"):
                check_configuration(policy(), root=root)
            path.write_text(expected)
            for unit in MASKED_UNITS:
                mask = unit_directory / unit
                mask.unlink()
                with self.assertRaisesRegex(Error, "not masked"):
                    check_configuration(policy(), root=root)
                mask.symlink_to("/dev/null")

    def test_only_fresh_authenticated_agreement_can_authorize_activation(self):
        result = assess(policy(), reports(), wall=NOW)
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
            with self.subTest(change=args), self.assertRaises(Error):
                assess(policy(), observed, wall=NOW)

    def test_selectable_uncombined_authenticated_source_can_supply_agreement(self):
        observed = reports()
        change(observed, "sources", 1, 1, "-")
        self.assertEqual(assess(policy(), observed, wall=NOW)["operators"], ["operator_a", "operator_b"])
        change(observed, "authdata", 1, 1, "-")
        with self.assertRaisesRegex(Error, "not authenticated"):
            assess(policy(), observed, wall=NOW)

    def test_extra_duplicate_and_unreviewed_source_identities_are_not_votes(self):
        for kind in ("operator", "address", "name", "packet", "format"):
            selected, observed = policy(), reports()
            if kind == "operator":
                selected["sources"][1]["operator"] = "operator_a"
            elif kind == "address":
                change(observed, "sources", 1, 2, "203.0.113.10")
            elif kind == "name":
                observed["names"]["203.0.113.10"] = "unreviewed.example.org"
            elif kind == "packet":
                observed["ntpdata"] += observed["ntpdata"].splitlines()[0] + "\n"
            else:
                packet = list(csv.reader(observed["ntpdata"].splitlines()))
                observed["ntpdata"] = encode([row[:-1] for row in packet])
            with self.subTest(kind=kind), self.assertRaises(Error):
                assess(selected, observed, wall=NOW)

    def test_renderer_has_one_authenticated_client_policy_and_no_bypass(self):
        config = render(policy())["etc/chrony.conf"]
        self.assertIn("authselectmode require\nminsources 2\n", config)
        self.assertIn("port 0\ncmdport 0\n", config)
        self.assertEqual(config.count(" nts certset 0 "), 2)
        for directive in ("nocerttimecheck", "pool ", "include ", "sourcedir", "allow ", "local "):
            self.assertNotIn(directive, config)
        invalid = policy()
        invalid["sources"][1]["trust"] = "installation"
        with self.assertRaisesRegex(Error, "explicit certificate"):
            validate(invalid)
        for server in ("127.0.0.1", "::1", "localhost", "time.example.org\nlocal stratum 1"):
            invalid = policy()
            invalid["sources"][1]["server"] = server
            with self.subTest(server=server), self.assertRaises(Error):
                validate(invalid)

    def test_reader_uses_only_the_private_command_socket_and_detects_clock_steps(self):
        observed = reports()

        def capture(args, **_kwargs):
            self.assertEqual(args[0], "/usr/bin/setpriv")
            for option in (
                "--reuid=chrony",
                "--regid=chrony",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
            ):
                self.assertIn(option, args)
            start = args.index("/usr/bin/chronyc")
            self.assertEqual(
                args[start : start + 5], ["/usr/bin/chronyc", "-h", "/run/chrony/chronyd.sock", "-c", "-n"]
            )
            command = args[start + 5 :]
            data = (
                observed[command[0]] if command[0] != "sourcename" else observed["names"][command[1]] + "\n"
            )
            return SimpleNamespace(returncode=0, stdout=data, stderr="")

        for anchor, wall, success in (
            (None, NOW, True),
            ({"wall": NOW - 10, "boottime": 90.0}, NOW, True),
            ({"wall": NOW - 3600, "boottime": 90.0}, NOW, False),
        ):
            with (
                self.subTest(anchor=anchor),
                patch("particleve.timesync.capture_bounded", side_effect=capture),
                patch("particleve.timesync.time.time", return_value=wall),
                patch("particleve.timesync.time.clock_gettime", return_value=100.0),
            ):
                if success:
                    self.assertEqual(probe(policy(), anchor=anchor)["wall"], wall)
                else:
                    with self.assertRaisesRegex(Error, "clock stepped during activation"):
                        probe(policy(), anchor=anchor)

    def test_machine_reports_and_policy_do_not_accept_unbounded_or_ambiguous_inputs(self):
        bad = reports()
        bad["sources"] = "x" * 65537
        with self.assertRaisesRegex(Error, "oversized"):
            assess(policy(), bad, wall=NOW)
        for field, value in (("certificates", "PRIVATE KEY"), ("sources", [])):
            config = copy.deepcopy(policy())
            config[field] = value
            with self.subTest(field=field), self.assertRaises(Error):
                validate(config)
