#!/usr/bin/python3
"""Check cold-home key/PAM SSH using one disposable homed account on a booted ParticleVE host."""

import argparse
import json
import os
import secrets
import shlex
import stat
import tempfile
import time
from pathlib import Path

from particleve.common import require, run
from particleve.versioning import image_version

require(os.geteuid() == 0, "run this acceptance check as root on the target ParticleVE host")
image_version()  # Do not modify a developer workstation's account database.
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--port", type=int, default=22, help="port of the target host's local SSH listener")
checks = parser.add_mutually_exclusive_group()
checks.add_argument(
    "--elevation", action="store_true", help="also test native run0 with a disposable wheel member"
)
checks.add_argument(
    "--management", action="store_true", help="test management rejection for a disposable nonadministrator"
)
args = parser.parse_args()
require(1 <= args.port <= 65535, "SSH port must be in 1..65535")
username = "pvssh" + secrets.token_hex(4)
with tempfile.TemporaryDirectory(prefix="particleve-ssh-", dir="/run") as temporary:
    directory = Path(temporary)
    key = directory / "id_ed25519"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    password = secrets.token_urlsafe(48)
    password_hash = run(["openssl", "passwd", "-6", "-stdin"], input=password).stdout.strip()
    identity = directory / "identity.json"
    identity.write_text(
        json.dumps(
            {
                "userName": username,
                "storage": "subvolume",
                "shell": "/bin/bash",
                "memberOf": ["wheel"] if args.elevation else [],
                "privileged": {
                    "hashedPassword": [password_hash],
                    "sshAuthorizedKeys": [key.with_suffix(".pub").read_text().strip()],
                },
                "secret": {"password": [password]},
            }
        )
    )
    identity.chmod(0o600)
    created = False
    try:
        run(["homectl", "--no-ask-password", "create", username, f"--identity={identity}"])
        created = True
        # Native Btrfs subvolume creation skips the inode-security initializer.
        # Label only this newly provisioned home, before it has any user data.
        run(["restorecon", "-RF", "/home/" + username + ".homedir"])
        machine_id = Path("/etc/machine-id").read_text().strip()

        def home_state():
            record = json.loads(run(["homectl", "--json=short", "inspect", username]).stdout)
            return record.get("status", {}).get(machine_id, {}).get("state")

        if home_state() == "active":
            run(["homectl", "deactivate", username])
        require(home_state() == "inactive", "SSH acceptance check requires an inactive home")
        run(["getent", "passwd", username])
        public_key = key.with_suffix(".pub").read_text().split()[:2]
        keys = run(["userdbctl", "ssh-authorized-keys", username]).stdout.splitlines()
        require(
            any(line.split()[:2] == public_key for line in keys),
            "upstream userdb did not return the inactive user's SSH key",
        )
        # Bind this local test to the installed server key; do not disable host-key verification.
        public = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text().strip()
        known = directory / "known_hosts"
        address = "127.0.0.1" if args.port == 22 else f"[127.0.0.1]:{args.port}"
        known.write_text(address + " " + public + "\n")
        command = [
            "ssh",
            "-p",
            str(args.port),
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ControlPath=none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known}",
            username + "@127.0.0.1",
            'id -un; test -w "$HOME" && touch "$HOME/.particleve-ssh-test"',
        ]
        require(run(command, timeout=45, check=False).returncode != 0, "SSH key alone bypassed PAM")
        require(home_state() == "inactive", "key-only attempt unexpectedly activated the home")
        password_file = directory / "password"
        password_file.write_text(password)
        password_file.chmod(0o600)
        askpass = directory / "askpass"
        askpass.write_text(f"#!/bin/sh\nexec /usr/bin/cat '{password_file}'\n")
        askpass.chmod(0o700)
        os.environ.update(
            SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force", DISPLAY="particleve-acceptance"
        )
        command[command.index("BatchMode=yes")] = "BatchMode=no"
        result = run(command, input="", timeout=45)
        require(not result.stderr, "cold-home SSH produced diagnostics: " + result.stderr.strip())
        require(result.stdout.strip() == username, "SSH did not enter the expected homed account")
        record = json.loads(
            run(
                ["userdbctl", "--service=io.systemd.Home", "--with-nss=no", "--output=json", "user", username]
            ).stdout
        )
        require(record["storage"] == "subvolume", "test account did not use subvolume storage")
        if args.elevation:
            probe = Path(__file__).with_name("run0-pty-probe.py").read_text()
            command[-1] = shlex.join(["/usr/bin/python3", "-c", probe])
            result = run(command, input=json.dumps({"password": password}), timeout=90, check=False)
            print(result.stdout, end="")
            require(result.returncode == 0, "native run0 acceptance failed: " + result.stderr.strip())
            require(not result.stderr, "run0 SSH produced diagnostics: " + result.stderr.strip())
        if args.management:
            sockets = [
                str(path)
                for path in Path("/run/particleve-vm").rglob("*")
                if stat.S_ISSOCK(path.lstat().st_mode)
            ]
            require(sockets, "management acceptance requires a running disposable VM")
            probe = Path(__file__).with_name("nonroot-management-probe.py").read_text()
            command[-1] = shlex.join(["/usr/bin/python3", "-c", probe])
            result = run(command, input=json.dumps({"vm_sockets": sockets}), timeout=45)
            require(not result.stderr, "management SSH produced diagnostics: " + result.stderr.strip())
            print(result.stdout, end="")
    finally:
        if created:
            run(["loginctl", "terminate-user", username], check=False)
            deadline = time.monotonic() + 30
            while home_state() != "inactive" and time.monotonic() < deadline:
                if home_state() == "active":
                    run(["homectl", "deactivate", username], check=False, timeout=120)
                time.sleep(1)
            require(home_state() == "inactive", "disposable home did not become inactive for cleanup")
            run(["homectl", "remove", username], timeout=120)
print(json.dumps({"cold_home_ssh": "pass", "image": image_version(), "disposable_user": username}))
