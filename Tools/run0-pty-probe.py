"""Use only with check-homed-ssh.py: authenticate one disposable homed user's run0."""

import contextlib
import errno
import json
import os
import platform
import pty
import re
import select
import signal
import sys
import termios
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


# This code is transported over SSH without importing an installed Python package.
release = platform.freedesktop_os_release()
require(release.get("IMAGE_ID") == "ParticleVE", "this is not a ParticleVE OS")
number = r"(?:0|[1-9][0-9]{0,5})"
require(
    re.fullmatch(
        rf"{number}\.{number}\.{number}\.{number}-{number}\.{number}", release.get("IMAGE_VERSION", "")
    ),
    "invalid running image version",
)
if os.geteuid() == 0:
    raise SystemExit("run0 acceptance requires the disposable non-root SSH session")
password = json.load(sys.stdin)["password"]
pid, terminal = pty.fork()
if pid == 0:
    os.execv("/usr/bin/run0", ["run0", "/usr/bin/id", "-u"])
output = bytearray()
sent = False
status = None
try:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if select.select([terminal], [], [], 0.1)[0]:
            try:
                chunk = os.read(terminal, 4096)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                # Linux reports PTY EOF as EIO after the slave closes.
                chunk = b""
            output.extend(chunk)
            if len(output) > 65536:
                raise RuntimeError("unexpected unbounded run0 output")
            plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", output)
            if not sent and re.search(rb"password:\s*$", plain, re.I):
                if termios.tcgetattr(terminal)[3] & termios.ECHO:
                    raise RuntimeError("refusing to enter a password while terminal echo is enabled")
                os.write(terminal, password.encode() + b"\n")
                sent = True
        waited, value = os.waitpid(pid, os.WNOHANG)
        if waited:
            status = value
            while select.select([terminal], [], [], 0)[0]:
                try:
                    chunk = os.read(terminal, 4096)
                    if not chunk:
                        break
                    output.extend(chunk)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
            break
    if status is None:
        raise RuntimeError("native run0 authentication did not finish within the acceptance deadline")
finally:
    if status is None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(terminal)
    text = output.decode(errors="replace").replace(password, "[redacted]")
    print(text, flush=True)
plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
# run0 emits native OSC 3008 session markers even on the acceptance PTY.
plain = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", plain)
if os.waitstatus_to_exitcode(status) != 0 or not sent or "0" not in plain.splitlines():
    raise SystemExit("run0 did not authenticate the disposable user and execute as UID 0")
print(json.dumps({"run0": "pass", "authenticated": True, "uid": 0}))
