"""Authenticated chrony observations and a clock-step barrier for OS activation."""

import csv
import ipaddress
import math
import re
import ssl
import time
from pathlib import Path

from .common import Error, capture_bounded, require
from .config import dns_name

MIN_OPERATORS = 2
MAX_SOURCES = 8
MAX_AGE = 300
MAX_ERROR = 0.5
MAX_STEP = 1.0
MAX_KE_AGE = 86400
SOCKET = "/run/chrony/chronyd.sock"
MASKED_UNITS = ("systemd-timesyncd.service", "chronyd.service", "chrony-wait.service")
# The daemon's command socket is writable only by its service UID. Query as
# that UID with no capabilities; do not add DAC override to the inspector.
QUERY = [
    "/usr/bin/setpriv",
    "--reuid=chrony",
    "--regid=chrony",
    "--clear-groups",
    "--bounding-set=-all",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--no-new-privs",
    "/usr/bin/chronyc",
    "-h",
    SOCKET,
    "-c",
    "-n",
]
LEAP = {"Normal", "Insert second", "Delete second"}


def address(value):
    require(type(value) is str and "%" not in value, "use an unscoped literal time-source address")
    result = ipaddress.ip_address(value)
    require(
        not (result.is_loopback or result.is_unspecified or result.is_multicast or result.is_link_local)
        and getattr(result, "ipv4_mapped", None) is None,
        "authenticated time needs distinct remote unicast sources",
    )
    return str(result)


def validate(policy):
    require(type(policy) is dict and set(policy) == {"sources", "certificates"}, "unknown time policy")
    sources = policy["sources"]
    require(
        type(sources) is list and MIN_OPERATORS <= len(sources) <= MAX_SOURCES, "configure 2..8 NTS sources"
    )
    for source in sources:
        require(
            type(source) is dict and set(source) == {"server", "operator", "trust"},
            "unknown NTS source policy",
        )
        try:
            require(address(source["server"]) == source["server"], "use a canonical NTS source address")
        except ValueError:
            dns_name(source["server"])
        require(
            type(source["operator"]) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", source["operator"]),
            "record the independently reviewed source operator",
        )
        require(source["trust"] in ("system", "installation"), "unknown NTS certificate trust set")
    require(len({s["server"] for s in sources}) == len(sources), "duplicate NTS endpoint")
    require(len({s["operator"] for s in sources}) >= MIN_OPERATORS, "require independent NTS operators")
    certificates = policy["certificates"]
    require(
        type(certificates) is str
        and len(certificates.encode()) <= 65536
        and "PRIVATE KEY" not in certificates,
        "time trust input must contain only bounded public certificates",
    )
    installation = any(s["trust"] == "installation" for s in sources)
    require(
        bool(certificates) == installation, "installation NTS trust requires its explicit certificate set"
    )
    if certificates:
        require(
            re.fullmatch(
                r"(?:\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+"
                r"-----END CERTIFICATE-----\s*)+",
                certificates,
            ),
            "NTS trust input must contain only PEM certificates",
        )
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=certificates)
        except (ssl.SSLError, ValueError) as exc:
            raise Error("invalid NTS public certificate set") from exc
    return policy


def render(policy):
    validate(policy)
    lines = [
        "# Generated ParticleVE NTS client; no unauthenticated sources or dynamic includes.",
        "authselectmode require",
        "minsources 2",
        "maxdistance 0.5",
        "maxupdateskew 100",
        "driftfile /var/lib/chrony/drift",
        "ntsdumpdir /var/lib/chrony",
        "dumpdir /var/lib/chrony",
        "makestep 1.0 3",
        "rtcsync",
        "port 0",
        "cmdport 0",
    ]
    for source in policy["sources"]:
        trust = 1 if source["trust"] == "installation" else 0
        lines.append(f"server {source['server']} nts certset {trust} iburst minpoll 6 maxpoll 7")
    files = {}
    if policy["certificates"]:
        lines.append("ntstrustedcerts 1 /etc/particleve/time-certificates.pem")
        files["etc/particleve/time-certificates.pem"] = policy["certificates"]
    files["etc/chrony.conf"] = "\n".join(lines) + "\n"
    return files


def check_configuration(policy, *, root=Path("/")):
    for name, expected in render(policy).items():
        path = root / name
        require(path.is_file() and path.read_text() == expected, "authenticated time configuration drift")
    for unit in MASKED_UNITS:
        mask = root / "usr/lib/systemd/system" / unit
        require(
            mask.is_symlink() and mask.readlink() == Path("/dev/null"),
            "an alternate clock owner or synchronization waiter is not masked",
        )


def rows(data, width, *, maximum=MAX_SOURCES):
    require(type(data) is str and len(data.encode()) <= 65536, "oversized time observation")
    try:
        parsed = list(csv.reader(data.splitlines(), strict=True))
    except csv.Error as exc:
        raise Error("malformed time observation") from exc
    require(
        len(parsed) <= maximum and all(len(row) == width for row in parsed),
        "unknown chrony machine-report format",
    )
    return parsed


def number(value, *, minimum=None, maximum=None):
    require(type(value) is str and len(value) <= 64, "invalid time measurement")
    try:
        result = float(value)
    except ValueError as exc:
        raise Error("invalid time measurement") from exc
    require(
        math.isfinite(result)
        and (minimum is None or result >= minimum)
        and (maximum is None or result <= maximum),
        "time measurement is non-finite or outside policy",
    )
    return result


def assess(policy, reports, *, wall):
    """Validate chrony 4.9 CSV fields against configured identities and current packets."""
    validate(policy)
    tracking = rows(reports["tracking"], 14, maximum=1)
    require(len(tracking) == 1, "missing clock tracking observation")
    track = tracking[0]
    require(track[13] in LEAP, "clock is not synchronised")
    number(track[2], minimum=1, maximum=15)
    update_age = wall - number(track[3], minimum=0)
    require(-MAX_STEP <= update_age <= MAX_AGE, "clock update is stale or in the future")
    error = (
        abs(number(track[4]))
        + number(track[10], minimum=0) / 2
        + number(track[11], minimum=0)
        + number(track[9], minimum=0) * max(0, update_age) / 1_000_000
    )
    require(error <= MAX_ERROR, "clock error bound exceeds activation policy")
    source_rows = rows(reports["sources"], 10)
    source_ips = [address(row[2]) for row in source_rows]
    require(len(set(source_ips)) == len(source_ips), "ambiguous source addresses")
    auth_rows = rows(reports["authdata"], 10)
    packet_rows = rows(reports["ntpdata"], 38)
    auth = {address(row[0]): row for row in auth_rows}
    packets = {address(row[0]): row for row in packet_rows}
    require(len(auth) == len(auth_rows) and len(packets) == len(packet_rows), "ambiguous time observations")
    configured = {source["server"]: source for source in policy["sources"]}
    operators = set()
    selected = []
    for row, ip in zip(source_rows, source_ips, strict=True):
        name = reports["names"][ip]
        require(name in configured, "unreviewed time source was added")
        require(row[0] == "^", "only configured NTS servers may discipline this clock")
        # '-' is selectable but not combined; chrony's minsources policy
        # counts these agreeing sources too. Falsetickers/unusable sources
        # ('x', '~', '?') cannot contribute to the operator quorum.
        if row[1] not in ("*", "+", "-"):
            continue
        require(ip in auth and ip in packets, "selected source lacks authentication/packet evidence")
        a, p = auth[ip], packets[ip]
        require(a[1] == "NTS", "selected time source is not authenticated with NTS")
        number(a[4], minimum=128)
        number(a[5], minimum=0, maximum=MAX_KE_AGE)
        number(a[8], minimum=1)
        require(p[5] in LEAP and p[6:8] == ["4", "Server"] and p[27] == "Yes", "unauthenticated NTP sample")
        require(p[23:26] == ["111", "111", "1111"], "NTP response failed measurement tests")
        number(p[2], minimum=1, maximum=65535)
        number(p[33], minimum=1)
        number(row[6], minimum=0, maximum=MAX_AGE)
        require(
            max(abs(number(row[7])), abs(number(row[8]))) + number(row[9], minimum=0) <= MAX_ERROR,
            "authenticated source error bound exceeds activation policy",
        )
        require(re.fullmatch(r"[0-7]{1,3}", row[5]) and int(row[5], 8), "source has no valid replies")
        if row[1] == "*":
            selected.append(ip)
        operators.add(configured[name]["operator"])
    require(len(selected) == 1 and address(track[1]) == selected[0], "selected clock source identity differs")
    require(len(operators) >= MIN_OPERATORS, "fewer than two independent authenticated sources agree")
    return {"operators": sorted(operators), "maximum_error_seconds": error, "update_age_seconds": update_age}


def probe(policy, *, anchor=None):
    started_wall, started_mono = time.time(), time.clock_gettime(time.CLOCK_BOOTTIME)
    deadline = time.monotonic() + 5

    def query(*command):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "authenticated time observation exceeded its total deadline")
        observed = capture_bounded([*QUERY, *command], timeout=min(2, remaining))
        require(
            observed.returncode == 0 and not observed.stderr, "authenticated time observation unavailable"
        )
        return observed.stdout

    reports = {name: query(name) for name in ("tracking", "sources", "authdata", "ntpdata")}
    reports["names"] = {}
    for row in rows(reports["sources"], 10):
        ip = address(row[2])
        reports["names"][ip] = query("sourcename", ip).strip()
    wall, mono = time.time(), time.clock_gettime(time.CLOCK_BOOTTIME)
    require(
        abs((wall - started_wall) - (mono - started_mono)) <= MAX_STEP, "clock stepped during observation"
    )
    if anchor is not None:
        require(
            mono >= anchor["boottime"]
            and abs((wall - anchor["wall"]) - (mono - anchor["boottime"])) <= MAX_STEP,
            "clock stepped during activation; preserve the current OS and restore VMs",
        )
    return {**assess(policy, reports, wall=wall), "wall": wall, "boottime": mono}
