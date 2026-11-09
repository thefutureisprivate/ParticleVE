#!/usr/bin/python3
"""Native regression: healthy one-second polling must not hit PID1's start limit."""

import argparse
import configparser
import os
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("service", type=Path, help="selected particleve-storage-watch.service")
args = parser.parse_args()
assert os.geteuid() == 0, "run only in a disposable native systemd fixture"
config = configparser.ConfigParser(interpolation=None)
config.optionxform = str
config.read(args.service)
limits = {name: config["Unit"][name] for name in ("StartLimitIntervalSec", "StartLimitBurst")}
assert limits["StartLimitIntervalSec"] not in ("0", "0s") and int(limits["StartLimitBurst"]) > 0
prefix = f"particleve-cadence-{os.getpid()}"
directory = Path("/run/systemd/system")
paths = [
    directory / f"{prefix}-{case}.{kind}" for case in ("default", "selected") for kind in ("service", "timer")
]
assert all(not path.exists() for path in paths), "refusing to replace an existing unit"


def run(*command, check=True):
    return subprocess.run(command, check=check, capture_output=True, text=True)


try:
    for case in ("default", "selected"):
        policy = "" if case == "default" else "".join(f"{key}={value}\n" for key, value in limits.items())
        (directory / f"{prefix}-{case}.service").write_text(
            "[Unit]\nDescription=Inert ParticleVE cadence regression\n"
            + policy
            + "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
        )
        (directory / f"{prefix}-{case}.timer").write_text(
            "[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=1s\nAccuracySec=100ms\n"
        )
    run("restorecon", *(str(path) for path in paths))
    run("systemctl", "daemon-reload")
    run("systemctl", "start", f"{prefix}-default.timer", f"{prefix}-selected.timer")
    time.sleep(25)
    logs = {
        case: run("journalctl", "-b", "--no-pager", "-u", f"{prefix}-{case}.service").stdout
        for case in ("default", "selected")
    }
    assert "start-limit-hit" in logs["default"], "the default-limit control did not reproduce the failure"
    assert "start-limit-hit" not in logs["selected"], logs["selected"]
    count = logs["selected"].count("Deactivated successfully")
    assert count >= 12, f"insufficient healthy native invocations: {count}"
    assert run("systemctl", "is-active", f"{prefix}-selected.timer").stdout.strip() == "active"
    print(
        f"PASS: default cadence reproduced start-limit-hit; selected policy completed {count} healthy starts"
    )
finally:
    run("systemctl", "stop", f"{prefix}-default.timer", f"{prefix}-selected.timer", check=False)
    run("systemctl", "reset-failed", f"{prefix}-default.service", f"{prefix}-selected.service", check=False)
    for path in paths:
        path.unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
