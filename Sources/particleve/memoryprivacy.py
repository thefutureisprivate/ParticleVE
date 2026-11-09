"""Read-only checks for host dump handling and cross-VM memory privacy."""

import configparser
import re
from pathlib import Path

from .common import Error, capture_bounded, require

KSM_UNITS = ("ksm.service", "ksmtuned.service")
MAX_SMAPS = 16 * 1024 * 1024
CORE_PATTERN = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F %I"


def core_handling():
    result = capture_bounded(["systemd-analyze", "cat-config", "--tldr", "systemd/coredump.conf"], timeout=5)
    require(result.returncode == 0 and not result.stderr, "cannot inspect native coredump configuration")
    # Native systemd keys are case sensitive and have no INI [DEFAULT]
    # inheritance. Do not let Python's additional INI features invent policy.
    config = configparser.ConfigParser(interpolation=None, strict=False, default_section=None)
    config.optionxform = str
    try:
        config.read_string(result.stdout)
    except configparser.Error as exc:
        raise Error("cannot parse effective coredump configuration") from exc
    expected = {"Storage": "none", "ProcessSizeMax": "0", "EnterNamespace": "no"}
    require(
        config.has_section("Coredump") and all(config["Coredump"].get(k) == v for k, v in expected.items()),
        "coredump payload handling is enabled",
    )
    return {key.lower(): value for key, value in expected.items()}


def configuration():
    expected = core_handling()
    result = capture_bounded(
        ["systemctl", "show", "--property=DefaultLimitCORE", "--property=DefaultLimitCORESoft"], timeout=5
    )
    require(result.returncode == 0 and not result.stderr, "cannot inspect manager core limits")
    require(
        set(result.stdout.splitlines()) == {"DefaultLimitCORE=0", "DefaultLimitCORESoft=0"},
        "system manager core limits changed",
    )
    return expected | {"manager_core_limit": 0}


def check_ksm_activation():
    result = capture_bounded(["systemctl", "is-enabled", *KSM_UNITS], timeout=5)
    states = result.stdout.splitlines()
    require(
        result.returncode in (0, 1)
        and not result.stderr
        and len(states) == len(KSM_UNITS)
        and all(state in ("masked", "masked-runtime") for state in states),
        "KSM activation is not masked",
    )


def baseline(*, proc=Path("/proc"), sysfs=Path("/sys")):
    require((proc / "sys/fs/suid_dumpable").read_text().strip() == "0", "privileged core dumps are enabled")
    require(
        (proc / "sys/kernel/core_pattern").read_text().strip() == CORE_PATTERN, "core dump handler changed"
    )
    ksm = sysfs / "kernel/mm/ksm"
    observed = {"available": ksm.is_dir()}
    if observed["available"]:
        for name in ("run", "pages_shared", "pages_sharing", "ksm_zero_pages"):
            value = (ksm / name).read_text().strip()
            require(value == "0", "KSM is active or merged pages remain: " + name)
            observed[name] = 0
    check_ksm_activation()
    return {"ksm": observed, "core_handling": configuration(), "suid_dumpable": 0}


def process_policy(process, *, qemu=False):
    limits = re.findall(r"^Max core file size\s+(\S+)\s+(\S+)\s+bytes\s*$", process.read_text("limits"), re.M)
    require(limits == [("0", "0")], "VM process core limits are not both zero")
    mask = process.read_text("coredump_filter", 64).strip()
    require(re.fullmatch(r"0{1,16}", mask), "VM core filter is not empty")
    if qemu:
        # Only mapping metadata is read; no process-memory contents are opened
        # or exported. Refuse an incomplete or excessively large observation.
        maps = process.read_bytes("smaps", MAX_SMAPS)
        mappings = re.findall(rb"^[0-9a-f]+-[0-9a-f]+ ", maps, re.M)
        flags = re.findall(rb"^VmFlags:[ \t]*(.*)$", maps, re.M)
        require(mappings and len(mappings) == len(flags), "QEMU mapping observation is incomplete")
        require(all(b"mg" not in line.split() for line in flags), "QEMU memory is registered for KSM merging")
        sharing = re.findall(rb"^KSM:[ \t]+(\d+) kB$", maps, re.M)
        try:
            stats = process.read_text("ksm_stat")
        except FileNotFoundError:
            require(not sharing, "QEMU KSM accounting interface is missing")
        else:
            require(len(sharing) == len(mappings), "QEMU KSM observation is incomplete")
            require(all(value == b"0" for value in sharing), "QEMU has merged memory pages")
            counts = re.findall(r"^ksm_(zero_pages|merging_pages) (\d+)$", stats, re.M)
            require(
                len(counts) == 2 and dict(counts) == {"zero_pages": "0", "merging_pages": "0"},
                "QEMU retains KSM-shared or KSM-zero pages",
            )
