"""One-way BPF policy and paired JIT probes; run only in a disposable QEMU VM."""

import argparse
import ctypes
import errno
import hashlib
import json
import os
import platform
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

BPF = 321  # Supported x86-64 syscall ABI.
BPF_LOCK = Path("/proc/sys/kernel/unprivileged_bpf_disabled")
JIT = Path("/proc/sys/net/core/bpf_jit_harden")
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


def call(command, attr):
    # attr owns all pointed-to buffers for the duration of this synchronous call.
    ctypes.set_errno(0)
    result = LIBC.syscall(BPF, command, ctypes.byref(attr), ctypes.sizeof(attr))
    return result, ctypes.get_errno()


def program():
    # Packet length keeps constants dependent on runtime input. No helper,
    # kernel pointer, attachment, external packet, or persistent BPF object.
    instructions = [struct.pack("=BBhi", 0x61, 0x10, 0, 0)]
    for number in range(64):
        instructions.append(struct.pack("=BBhi", 0xA4, 0, 0, 104729 * (number + 1)))
    instructions.extend([struct.pack("=BBhi", 0x54, 0, 0, 255), struct.pack("=BBhi", 0x95, 0, 0, 0)])
    code = ctypes.create_string_buffer(b"".join(instructions))
    license_buffer = ctypes.create_string_buffer(b"GPL\0")
    log = ctypes.create_string_buffer(65536)
    attr = ctypes.create_string_buffer(144)
    struct.pack_into(
        "=IIQQIIQ",
        attr,
        0,
        1,
        len(instructions),
        ctypes.addressof(code),
        ctypes.addressof(license_buffer),
        1,
        len(log),
        ctypes.addressof(log),
    )
    fd, error = call(5, attr)  # BPF_PROG_LOAD, socket filter.
    return fd, error, log.value.decode(errors="replace")


def measure(fd, repeats):
    packet = ctypes.create_string_buffer(bytes(range(64)))
    output = ctypes.create_string_buffer(256)
    attr = ctypes.create_string_buffer(80)
    struct.pack_into(
        "=IIIIQQII",
        attr,
        0,
        fd,
        0,
        64,
        len(output),
        ctypes.addressof(packet),
        ctypes.addressof(output),
        repeats,
        0,
    )
    start = time.monotonic_ns()
    result, error = call(10, attr)  # BPF_PROG_TEST_RUN, repeat inside kernel.
    wall = time.monotonic_ns() - start
    assert result == 0, (result, error)
    return {
        "duration_ns": struct.unpack_from("=I", attr, 36)[0],
        "retval": struct.unpack_from("=I", attr, 4)[0],
        "wall_ns": wall,
    }


def run(args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=45).stdout


def worker():
    status = Path("/proc/self/status").read_text().splitlines()
    assert os.getuid() == 65534 and os.getgroups() == []
    assert all(int(line.split()[1], 16) == 0 for line in status if line.startswith("Cap"))
    fd, error, _ = program()
    if fd >= 0:
        os.close(fd)
    assert fd == -1 and error == errno.EPERM, (fd, error)
    # Classic seccomp remains available to a zero-capability process. This
    # filter denies getppid only; its lifetime is confined to this child.
    instructions = b"".join(
        struct.pack("=HBBI", *row)
        for row in [
            (0x20, 0, 0, 0),
            (0x15, 0, 1, 110),
            (0x06, 0, 0, 0x50000 | errno.EPERM),
            (0x06, 0, 0, 0x7FFF0000),
        ]
    )
    code = ctypes.create_string_buffer(instructions)

    class Filter(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("code", ctypes.c_void_p)]

    fprog = Filter(4, ctypes.addressof(code))
    assert LIBC.prctl(38, 1, 0, 0, 0) == 0
    assert LIBC.prctl(22, 2, ctypes.byref(fprog), 0, 0) == 0
    ctypes.set_errno(0)
    assert LIBC.syscall(110) == -1 and ctypes.get_errno() == errno.EPERM
    assert LIBC.syscall(39) == os.getpid()
    print(json.dumps({"unprivileged_bpf": "EPERM", "classic_seccomp": "passed"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-uuid", required=True)
    parser.add_argument("--allow-one-way-bpf-lock", action="store_true", required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.machine() == "x86_64"
    assert Path("/sys/class/dmi/id/product_uuid").read_text().strip() == args.fixture_uuid
    assert "QEMU" in Path("/sys/class/dmi/id/sys_vendor").read_text()
    assert not args.output.exists(), "preserve earlier evidence; choose a new output"
    cmdline = Path("/proc/cmdline").read_text()
    enforcement = Path("/sys/module/module/parameters/sig_enforce").read_text().strip()
    observation = {"operation": "kernel-boot-policy", "cmdline": cmdline, "enforcement": enforcement}
    checked = subprocess.run(
        [str(args.driver.resolve())],
        input=json.dumps(observation) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert "ok" in json.loads(checked.stdout), checked.stdout
    config = Path("/usr/lib/modules", platform.release(), "config").read_text().splitlines()
    assert "CONFIG_BPF_JIT_ALWAYS_ON=y" in config and "CONFIG_BPF_LSM=y" in config
    original = {
        "unprivileged_bpf_disabled": BPF_LOCK.read_text().strip(),
        "bpf_jit_harden": JIT.read_text().strip(),
    }
    # Apply the actual shared asset twice, as initrd and installed OS do. The
    # selected kernel permits idempotent 1 -> 1 but rejects 1 -> 0 and 1 -> 2.
    for _ in range(2):
        run(
            [
                "/usr/lib/systemd/systemd-sysctl",
                "--prefix=/kernel/unprivileged_bpf_disabled",
                "--prefix=/net/core/bpf_jit_harden",
                str(args.policy.resolve()),
            ]
        )
    assert BPF_LOCK.read_text().strip() == "1" and JIT.read_text().strip() == "2"
    for value in ["0", "2"]:
        try:
            BPF_LOCK.write_text(value)
        except PermissionError:
            pass
        else:
            raise AssertionError("one-way BPF lock was cleared")
        assert BPF_LOCK.read_text().strip() == "1"
    child = run(
        [
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            sys.executable,
            "-c",
            Path(__file__).read_text(),
            "--worker",
        ]
    )
    rows = []
    started = time.monotonic()
    try:
        # Alternate order within paired blocks to expose drift. Fresh programs
        # are necessary: changing this knob does not rewrite existing JIT code.
        for block in range(12):
            for value in ["0", "2"] if block % 2 == 0 else ["2", "0"]:
                assert time.monotonic() - started < 120, "benchmark deadline"
                JIT.write_text(value)
                fd, error, verifier_log = program()
                assert fd >= 0, (value, error, verifier_log)
                try:
                    measure(fd, 10000)
                    samples = [measure(fd, 1000000) for _ in range(3)]
                    assert len({s["retval"] for s in samples}) == 1
                    rows.append(
                        {
                            "block": block,
                            "harden": int(value),
                            "samples": samples,
                            "median_ns": statistics.median(s["duration_ns"] for s in samples),
                        }
                    )
                finally:
                    os.close(fd)
    finally:
        JIT.write_text("2")
    assert len({s["retval"] for row in rows for s in row["samples"]}) == 1
    ratios = [
        next(r["median_ns"] for r in rows if r["block"] == b and r["harden"] == 2)
        / next(r["median_ns"] for r in rows if r["block"] == b and r["harden"] == 0)
        for b in range(12)
    ]
    result = {
        "schema": 1,
        "result": "passed",
        "scope": "native component policy and BPF-only microbenchmark; no whole-VM performance claim",
        "kernel": platform.release(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "fixture_uuid": args.fixture_uuid,
        "original": original,
        "module_enforcement": enforcement,
        "module_command_line": [s for s in cmdline.split() if s.startswith("module.sig_enforce=")],
        "policy_sha256": hashlib.sha256(args.policy.read_bytes()).hexdigest(),
        "driver_sha256": hashlib.sha256(args.driver.read_bytes()).hexdigest(),
        "idempotent_policy": True,
        "one_way_lock": True,
        "unprivileged": json.loads(child),
        "samples": rows,
        "paired_hardened_over_baseline_median": statistics.median(ratios),
        "paired_ratio_range": [min(ratios), max(ratios)],
        "elapsed_seconds": time.monotonic() - started,
        "final": {
            "unprivileged_bpf_disabled": BPF_LOCK.read_text().strip(),
            "bpf_jit_harden": JIT.read_text().strip(),
        },
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "samples"}))


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        worker()
    else:
        main()
