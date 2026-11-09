"""One-file firmware writer, isolated before accepting its input."""

import json
import os
import sys
from pathlib import Path

from .common import Error, canonical, require, run


def command(variable):
    return [
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--ro-bind",
        "/proc/sys",
        "/proc/sys",
        "--bind",
        str(variable),
        str(variable),
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CAP_LINUX_IMMUTABLE",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/usr/sbin",
        "/usr/libexec/particleve-witness-write",
    ]


def save(record):
    from .admission import VARIABLE, load, validate

    require(VARIABLE.is_file(), "missing firmware witness; owner recovery required")
    run(command(VARIABLE), input=canonical(validate(record)).decode())
    require(load() == record, "isolated firmware witness write did not persist")


def check_sandbox(variable):
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    require(
        os.geteuid() == 0 and status["NoNewPrivs"].strip() == "1", "writer requires its isolated launcher"
    )
    # NoNewPrivs prevents exec from regaining capabilities from the wider
    # bounding set retained by bubblewrap. Every possessed set is restricted.
    for field in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
        require(int(status[field].strip(), 16) == 1 << 9, "writer must retain only CAP_LINUX_IMMUTABLE")
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields = before.split()
        if after.split()[0] == "efivarfs":
            mounts.append((fields[3], fields[4], set(fields[5].split(","))))
    writable = [(root, target) for root, target, options in mounts if "rw" in options]
    require(writable == [("/" + variable.name, str(variable))], "only the existing witness may be writable")


def main():
    from .admission import VARIABLE, _write_existing, validate

    try:
        check_sandbox(VARIABLE)
        data = sys.stdin.buffer.read(4097)
        require(0 < len(data) <= 4096, "invalid witness request size")
        _write_existing(validate(json.loads(data)))
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ParticleVE isolated witness writer: {exc}", file=sys.stderr)
        return 1
