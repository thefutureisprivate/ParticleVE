"""Signal supervision for the native runner, including incomplete unit starts."""

import os
import signal
import subprocess
import time
from pathlib import Path

from .common import Error, require, run
from .confinement import check_tpm_arguments, start_guard
from .vms import cgroup_processes


def supervise(name, command):
    require(command and command[0] == "/usr/bin/systemd-vmspawn", "supervisor requires native vmspawn")
    for argument in ("--register=yes", "--keep-unit", "--machine=" + name):
        require(command.count(argument) == 1, "native vmspawn registration/ownership arguments required")
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signals = (signal.SIGTERM, signal.SIGINT, signal.SIGRTMIN + 4)
    previous = {number: signal.signal(number, stop) for number in signals}
    try:
        start_guard(name)
        check_tpm_arguments(name, command)
        if stopping:
            return 0
        group = next(
            line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")
        )
        environment = os.environ.copy()
        # Native vmspawn owns watchdog pings, while systemd's MainPID is this
        # supervisor. NotifyAccess=all admits those native notifications.
        environment.pop("WATCHDOG_PID", None)
        child = subprocess.Popen(command, env=environment)
        requested = False
        last_error = None
        while True:
            result = child.poll()
            try:
                live = []
                for entry in cgroup_processes(group):
                    try:
                        kind = Path(f"/proc/{entry['pid']}/attr/current").read_text().split(":")[2]
                    except FileNotFoundError, ProcessLookupError:
                        continue
                    if kind in ("svirt_t", "swtpm_t"):
                        live.append(entry)
                if result is not None and not live:
                    return result if result >= 0 else 128 - result
                if stopping and not requested:
                    response = run(["machinectl", "poweroff", "--", name], check=False, timeout=15)
                    requested = response.returncode == 0
                    if not requested and last_error != "not registered":
                        print(
                            "Waiting for native VM registration or owner-assisted graceful shutdown",
                            flush=True,
                        )
                        last_error = "not registered"
            except (Error, OSError, ValueError, IndexError) as exc:
                if str(exc) != last_error:
                    print(f"Cannot confirm graceful VM exit; waiting for owner assistance: {exc}", flush=True)
                    last_error = str(exc)
            time.sleep(1)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
