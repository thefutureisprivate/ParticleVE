#!/usr/bin/python3
"""Test native FIDO signature flags with OpenSSH's software regression provider.

Run only in an explicitly selected disposable installation. The provider contains
software private keys; it proves daemon enforcement, never hardware provenance,
PIN handling or biometric verification. It is not included in the runtime RPM.
"""

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from particleve.common import read_json, require, run
from particleve.linux import image_version

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--expect-installation", required=True)
parser.add_argument("--provider", type=Path, required=True)
parser.add_argument("--ssh-config", type=Path, required=True)
parser.add_argument("--homed-check", type=Path, required=True)
parser.add_argument(
    "--preserve-unit", action="append", default=[], help="verify a running unit's PID is retained"
)
args = parser.parse_args()
require(os.geteuid() == 0, "run inside the disposable test installation as root")
version = image_version()
manifest = read_json("/var/lib/particleve/installation.json")
require(manifest["installation_uuid"] == args.expect_installation, "unexpected test installation")
factory = args.ssh_config.read_text()
require(
    "PubkeyAuthOptions touch-required verify-required" in factory,
    "test the selected FIDO2 factory policy",
)
provider = args.provider.resolve(strict=True)
original_pids = {
    name: run(["systemctl", "show", "-p", "MainPID", "--value", name]).stdout.strip()
    for name in args.preserve_unit
}
require(all(int(pid) > 0 for pid in original_pids.values()), "preserved units must already be running")
cases = {}
with tempfile.TemporaryDirectory(prefix="particleve-fido-", dir="/run") as temporary:
    directory = Path(temporary)
    os.chmod(directory, 0o700)
    keys = {}
    public_keys = []
    for kind in ("ed25519-sk", "ecdsa-sk"):
        for flags, options in (
            ("presence-verification", ["-O", "verify-required"]),
            ("presence-only", []),
            ("verification-only", ["-O", "verify-required", "-O", "no-touch-required"]),
            ("neither", ["-O", "no-touch-required"]),
        ):
            name = kind + "-" + flags
            key = directory / name
            run(["ssh-keygen", "-q", "-t", kind, "-w", provider, "-N", "", "-f", key, *options])
            keys[name] = key
            # Try the record-level presence override too: global touch-required
            # must reject a correctly signed message whose UP flag is absent.
            option = "no-touch-required " if flags in ("verification-only", "neither") else ""
            public_keys.append(option + key.with_suffix(".pub").read_text().strip())
    recovery = directory / "recovery"
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", recovery])
    keys["independent-ed25519-recovery"] = recovery
    public_keys.append(recovery.with_suffix(".pub").read_text().strip())
    authorized = directory / "authorized_keys"
    authorized.write_text("\n".join(public_keys) + "\n")
    authorized.chmod(0o600)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = directory / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\n"
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        f"PidFile {directory}/pid\nAuthorizedKeysFile none\nLogLevel VERBOSE\n"
        # This loopback-only test daemon checks independent signature cases;
        # cumulative penalties would turn later cases into rate-limit tests.
        "PerSourcePenalties no\n"
        + factory
        + f"\nMatch User root\n    AuthorizedKeysFile {authorized}\nMatch all\n"
    )
    run(["/usr/sbin/sshd", "-t", "-f", config])
    for user in ("root", "particleve-policy-probe"):
        effective = run(["/usr/sbin/sshd", "-T", "-f", config, "-C", f"user={user},addr=127.0.0.1"])
        values = dict(line.lower().split(" ", 1) for line in effective.stdout.splitlines())
        require(values["pubkeyauthoptions"] == "touch-required verify-required", "FIDO option drift")
        require(
            values["authenticationmethods"] == ("publickey" if user == "root" else "publickey,password"),
            "root/homed authentication drift",
        )
        require(not effective.stderr, "native SSH configuration diagnostics")
    known = directory / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} " + Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text())
    log = directory / "sshd.log"
    with log.open("w+") as stream:
        server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stderr=stream)
        try:
            deadline = time.monotonic() + 5
            while True:
                require(server.poll() is None, "test SSH daemon exited: " + log.read_text())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    require(time.monotonic() < deadline, "test SSH listener did not start")
                    time.sleep(0.05)
            for name, key in keys.items():
                nonce = secrets.token_hex(16)
                log_start = len(log.read_text())
                result = run(
                    [
                        "ssh",
                        "-p",
                        str(port),
                        "-i",
                        key,
                        "-o",
                        f"SecurityKeyProvider={provider}",
                        "-o",
                        "IdentitiesOnly=yes",
                        "-o",
                        "IdentityAgent=none",
                        "-o",
                        "ControlPath=none",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "StrictHostKeyChecking=yes",
                        "-o",
                        f"UserKnownHostsFile={known}",
                        "root@127.0.0.1",
                        f"printf '%s' {nonce}",
                    ],
                    timeout=20,
                    check=False,
                )
                allowed = "presence-verification" in name or name == "independent-ed25519-recovery"
                if allowed:
                    require(result.returncode == 0 and result.stdout == nonce, f"positive case {name} failed")
                    require(not result.stderr, "positive SSH diagnostics: " + result.stderr)
                else:
                    require(result.returncode == 255 and not result.stdout, f"negative case {name} bypassed")
                    reason = (
                        "verification requirement not met"
                        if "presence-only" in name
                        else "user presence (authenticator touch) requirement not met"
                    )
                    require(
                        reason in log.read_text()[log_start:],
                        f"negative case {name} did not reach flag enforcement",
                    )
                cases[name] = "accepted" if allowed else "rejected"
                print(json.dumps({"case": name, "result": cases[name]}), flush=True)
            # Reuse the native cold-home, key-plus-password and run0 acceptance
            # against this listener; the installed SSH daemon is untouched.
            result = run(
                [sys.executable, "-W", "error", args.homed_check, "--port", str(port), "--elevation"],
                timeout=240,
            )
            require(not result.stderr, "homed acceptance diagnostics: " + result.stderr)
            print(result.stdout, end="", flush=True)
        finally:
            server.terminate()
            server.wait(timeout=5)
            print(json.dumps({"server_log": log.read_text()}), flush=True)
for name, pid in original_pids.items():
    require(
        run(["systemctl", "show", "-p", "MainPID", "--value", name]).stdout.strip() == pid,
        f"{name} restarted",
    )
print(
    json.dumps({"image": version, "fido2_flags": cases, "scope": "software provider", "cleanup": "complete"})
)
