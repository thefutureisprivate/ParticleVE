#!/usr/bin/python3
"""Exercise admitted-member counters during replacement on a private Btrfs mirror.

Run as root only in a disposable native host with Btrfs-backed /var/tmp. The
probe creates three loop/linear devices; injected I/O errors affect only those
devices. No installed member, admission witness, or VM is changed.
"""

import errno
import fcntl
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from particleve.admission import member_errors
from particleve.common import require, run

require(os.geteuid() == 0, "run only in a disposable native host")
directory = Path(tempfile.mkdtemp(prefix="particleve-counter-", dir="/var/tmp"))
mount = directory / "mount"
mount.mkdir()
fsid = str(uuid.uuid4())
record = {"btrfs_uuid": fsid}
prefix = "pve-counter-" + directory.name.removeprefix("particleve-counter-")
loops = []
tables = {}
mounted = False
copy = None
result = {"filesystem_uuid": fsid, "replacement_samples": 0}


def command(*args):
    return run(list(args), timeout=60).stdout.strip()


def write(path, blocks):
    with path.open("xb") as stream:
        for _ in range(blocks):
            stream.write(b"counter acceptance\n".ljust(4 * 1024**2, b"x"))
        stream.flush()
        os.fsync(stream.fileno())


try:
    for role in ("old", "survivor", "new"):
        raw = directory / f"{role}.raw"
        raw.touch(exist_ok=False)
        command("chattr", "+C", str(raw))
        with raw.open("r+b") as stream:
            stream.truncate(768 * 1024**2)
        loop = command("losetup", "--find", "--show", "--direct-io=on", str(raw))
        require(re.fullmatch(r"/dev/loop[0-9]+", loop), "invalid test loop device")
        loops.append((loop, raw))
        require(
            Path("/sys/class/block", Path(loop).name, "loop/backing_file").read_text().strip() == str(raw),
            "test loop ownership changed",
        )
        name = f"{prefix}-{role}"
        table = f"0 {command('blockdev', '--getsz', loop)} linear {loop} 0"
        command("dmsetup", "create", name, "--table", table)
        tables[name] = table
    old, survivor, new = (f"/dev/mapper/{prefix}-{role}" for role in ("old", "survivor", "new"))
    command("mkfs.btrfs", "--force", "--uuid", fsid, "--data", "raid1", "--metadata", "raid1", old, survivor)
    command("mount", "-o", "noatime,subvolid=5", old, str(mount))
    mounted = True
    write(mount / "seed", 8)
    show = command("btrfs", "filesystem", "show", "--raw", str(mount))
    require(re.search(r"devid\s+1\b[^\n]*path " + re.escape(old) + r"$", show, re.M), "wrong copy source")
    require(re.search(r"devid\s+2\b[^\n]*path " + re.escape(survivor) + r"$", show, re.M), "wrong survivor")
    require(member_errors(record, mount, survivor) == (0,) * 5, "private mirror starts with errors")
    devinfo = Path("/sys/fs/btrfs", fsid, "devinfo")
    # Rate-limit only this private copy so the device-0 lifetime is observable.
    (devinfo / "1/scrub_speed_max").write_text(str(16 * 1024**2))
    with (directory / "replace.log").open("wb") as log:
        copy = subprocess.Popen(
            ["btrfs", "replace", "start", "-B", "1", new, str(mount)], stdout=log, stderr=subprocess.STDOUT
        )
        deadline = time.monotonic() + 180
        observed_target = False
        while copy.poll() is None:
            require(
                time.monotonic() < deadline, f"copy still active; retain {directory} for owner inspection"
            )
            observed_target |= (devinfo / "0").exists()
            require(
                member_errors(record, mount, survivor) == (0,) * 5, "survivor observation failed during copy"
            )
            result["replacement_samples"] += 1
            time.sleep(0.01)
        require(copy.returncode == 0, (directory / "replace.log").read_text())
    require(
        observed_target and result["replacement_samples"] >= 2, "replacement target lifetime was not covered"
    )
    require(member_errors(record, mount, survivor) == (0,) * 5, "survivor observation failed after copy")
    fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        stale_target = bytearray(1032)
        struct.pack_into("=QQQ", stale_target, 0, 0, 5, 0)
        try:
            fcntl.ioctl(fd, 0xC4089434, stale_target, True)
        except OSError as exc:
            require(exc.errno == errno.ENODEV, "unexpected retired-target error")
        else:
            raise RuntimeError("retired replacement target still supplied counters")
    finally:
        os.close(fd)
    result["retired_device_zero_returns_enodev"] = True
    result["survivor_clear_before_during_and_after_copy"] = True
    name = f"{prefix}-survivor"
    sectors = tables[name].split()[1]
    command("dmsetup", "suspend", "--noflush", "--nolockfs", name)
    try:
        command("dmsetup", "reload", name, "--table", f"0 {sectors} error")
        command("dmsetup", "resume", name)
        try:
            write(mount / "fault", 2)
        except OSError as exc:
            result["fault_write_errno"] = exc.errno
    finally:
        command("dmsetup", "suspend", "--noflush", "--nolockfs", name)
        command("dmsetup", "reload", name, "--table", tables[name])
        command("dmsetup", "resume", name)
    counters = member_errors(record, mount, survivor)
    require(any(counters), "injected admitted-member I/O fault was hidden")
    result["injected_member_error_counters"] = counters
    require(member_errors(record, mount, survivor) == counters, "counter observation reset persistent errors")
    result["error_counters_not_reset"] = True
finally:
    # An observation deadline is not evidence of copy completion. Preserve all
    # owned resources if its native process is still live; never cancel it here.
    if copy is None or copy.poll() is not None:
        if mounted:
            command("umount", str(mount))
        for name in reversed(tables):
            command("dmsetup", "remove", name)
        for loop, raw in reversed(loops):
            require(
                Path("/sys/class/block", Path(loop).name, "loop/backing_file").read_text().strip()
                == str(raw),
                "refusing to detach a changed loop device",
            )
            command("losetup", "--detach", loop)
        shutil.rmtree(directory)
        result["private_devices_and_files_removed"] = True
    else:
        print(json.dumps({"retained_directory": str(directory), "live_copy_pid": copy.pid}), flush=True)
print(json.dumps(result), flush=True)
