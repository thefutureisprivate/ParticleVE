"""Reject privileged management from check-homed-ssh.py's disposable nonadministrator."""

import errno
import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/usr/lib/particleve")
from particleve.common import require
from particleve.linux import image_version

image_version()
require(os.geteuid() != 0, "management rejection requires a non-root SSH session")
require("wheel" not in subprocess.check_output(["id", "-nG"], text=True).split(), "use a nonadministrator")
paths = json.load(sys.stdin)["vm_sockets"]
require(paths, "start a disposable VM before testing its management sockets")
for path in paths:
    require(Path(path).is_relative_to("/run/particleve-vm"), "unexpected management socket path")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        try:
            connection.connect(path)
        except OSError as exc:
            require(
                exc.errno == errno.EACCES, "management socket failed for a reason other than access denial"
            )
        else:
            raise SystemExit("nonadministrator connected to a VM management socket")

# If authorization regresses, this creates only a short-lived /usr/bin/true unit.
# Supplying a valid request distinguishes authorization denial from bad arguments.
name = "particleve-unprivileged-probe-" + secrets.token_hex(6) + ".service"
command = [
    "busctl",
    "--system",
    "--allow-interactive-authorization=no",
    "call",
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    "StartTransientUnit",
    "ssa(sv)a(sa(sv))",
    name,
    "fail",
    "1",
    "ExecStart",
    "a(sasb)",
    "1",
    "/usr/bin/true",
    "1",
    "/usr/bin/true",
    "false",
    "0",
]
result = subprocess.run(command, capture_output=True, text=True, timeout=15, env=os.environ | {"LC_ALL": "C"})
require(result.returncode != 0, "nonadministrator started a privileged transient service")
require(
    any(message in result.stderr for message in ("Access denied", "Interactive authentication required")),
    "D-Bus request did not reach the expected authorization denial: " + result.stderr,
)
print(
    json.dumps(
        {
            "vm_management_sockets": "denied",
            "tested_socket_count": len(paths),
            "privileged_dbus": "denied",
            "uid": os.geteuid(),
        }
    )
)
