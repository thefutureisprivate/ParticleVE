"""Reversible interface probes, only on a selected disposable QEMU host."""

import argparse
import json
import os
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--installation-uuid", required=True)
args = parser.parse_args()
assert os.geteuid() == 0
assert os.uname().machine == "x86_64"
assert (
    json.loads(Path("/var/lib/particleve/installation.json").read_text())["installation_uuid"]
    == args.installation_uuid
)
assert "QEMU" in Path("/sys/class/dmi/id/sys_vendor").read_text()

WORKER = r"""
import array, ctypes, errno, fcntl, json, os, pty, stat, struct, sys
from pathlib import Path

libc = ctypes.CDLL(None, use_errno=True)
kind = sys.argv[1]
if os.getuid() != 0:
    status = Path("/proc/self/status").read_text().splitlines()
    assert all(
        int(line.split()[1], 16) == 0
        for line in status
        if line.split(":")[0] in ("CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh")
    )
    assert os.getgroups() == []
if kind == "perf":
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=IIQ", attr, 0, 1, 128, 9)
    struct.pack_into("=Q", attr, 40, 1 | (1 << 5) | (1 << 6))
    fd = libc.syscall(298, ctypes.byref(attr), 0, -1, -1, 8)
    result = {"fd": fd >= 0, "errno": ctypes.get_errno() if fd < 0 else 0}
    if fd >= 0:
        os.close(fd)
elif kind == "ptrace":
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        value = libc.ptrace(0, 0, None, None)
        os.write(
            w, json.dumps({"allowed": value == 0, "errno": ctypes.get_errno() if value < 0 else 0}).encode()
        )
        os._exit(0)
    os.close(w)
    result = json.loads(os.read(r, 4096))
    os.close(r)
    os.waitpid(pid, 0)
elif kind == "ldisc":
    master, slave = pty.openpty()
    try:
        # The supported PPS discipline supplies a harmless PTY autoload control.
        fcntl.ioctl(slave, 0x5423, array.array("i", [18]))
        result = {"allowed": True, "errno": 0}
    except OSError as exc:
        result = {"allowed": False, "errno": exc.errno}
    finally:
        os.close(master)
        os.close(slave)
elif kind == "memfd":
    result = {}
    for name, flag in [("default", 0), ("exec", 0x10), ("nx", 0x8)]:
        fd = os.memfd_create("particleve-inert-" + name, flag | os.MFD_CLOEXEC)
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        seals = fcntl.fcntl(fd, 1034)
        try:
            os.fchmod(fd, 0o700)
            change = True
        except OSError as exc:
            assert exc.errno == errno.EPERM
            change = False
        result[name] = {
            "executable": bool(mode & 0o111),
            "seal_exec": bool(seals & 0x20),
            "chmod_exec": change,
        }
        os.close(fd)
elif kind == "userfaultfd":
    result = {}
    for name, flags in [("kernel_faults", 0), ("user_mode_only", 1)]:
        fd = libc.syscall(323, flags | os.O_CLOEXEC | os.O_NONBLOCK)
        result[name] = {"fd": fd >= 0, "errno": ctypes.get_errno() if fd < 0 else 0}
        if fd >= 0:
            os.close(fd)
elif kind == "kexec":
    # These invalid requests cannot supply a replacement kernel. When present,
    # the one-way disabled bit is asserted before either syscall is attempted.
    config = set((Path("/usr/lib/modules") / os.uname().release / "config").read_text().splitlines())
    core = "CONFIG_KEXEC_CORE=y" in config
    knob = Path("/proc/sys/kernel/kexec_load_disabled")
    if core:
        assert knob.read_text().strip() == "1"
    else:
        assert not knob.exists() and not knob.is_symlink()
    result = {"core_compiled_in": core, "syscalls": {}}
    for name, number, arguments in (
        ("KEXEC", 246, (0, 0, ctypes.c_void_p(), -1)),
        ("KEXEC_FILE", 320, (-1, -1, 0, ctypes.c_void_p(), 0)),
    ):
        ctypes.set_errno(0)
        value = libc.syscall(number, *arguments)
        error = ctypes.get_errno()
        enabled = "CONFIG_" + name + "=y" in config
        assert value == -1 and error == (errno.EPERM if enabled else errno.ENOSYS), (name, value, error)
        result["syscalls"][name] = {"compiled_in": enabled, "errno": error}
else:
    raise AssertionError(kind)
print(json.dumps(result))
"""


def worker(kind, *, root=False):
    command = ["python3", "-c", WORKER, kind]
    if not root:
        command = [
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            *command,
        ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=15, check=True)
    assert not result.stderr, result.stderr
    return json.loads(result.stdout)


def path(name):
    return Path("/proc/sys") / name.replace(".", "/")


values = {
    "kernel.yama.ptrace_scope": "2",
    "kernel.kptr_restrict": "2",
    "dev.tty.ldisc_autoload": "0",
    "vm.memfd_noexec": "1",
    "vm.mmap_rnd_bits": "32",
    "vm.mmap_rnd_compat_bits": "16",
    "fs.protected_fifos": "2",
    "fs.protected_regular": "2",
}
original = {name: path(name).read_text() for name in values | {"kernel.perf_event_paranoid": ""}}
assert not Path("/sys/module/pps_ldisc").exists()
try:
    before = {name: worker(name) for name in ("perf", "ptrace", "memfd", "userfaultfd")}
    print(json.dumps({"before": before, "kexec": worker("kexec", root=True)}), flush=True)
    # Establish the positive control only in this disposable host. The current
    # policy may already disable autoloading; restore its value in finally.
    path("dev.tty.ldisc_autoload").write_text("1")
    baseline = worker("ldisc")
    assert baseline == {"allowed": True, "errno": 0}, baseline
    assert Path("/sys/module/pps_ldisc").exists()
    subprocess.run(["modprobe", "-r", "pps_ldisc"], check=True)
    assert not Path("/sys/module/pps_ldisc").exists()
    path("kernel.perf_event_paranoid").write_text("3")
    perf3 = worker("perf")
    path("kernel.perf_event_paranoid").write_text(original["kernel.perf_event_paranoid"])
    for name, value in values.items():
        path(name).write_text(value)
        assert path(name).read_text().strip() == value
    after = {name: worker(name) for name in ("perf", "ptrace", "memfd", "userfaultfd", "ldisc")}
    assert after["ptrace"] == {"allowed": False, "errno": 1}, after
    assert worker("ptrace", root=True) == {"allowed": True, "errno": 0}
    assert after["ldisc"] == {"allowed": False, "errno": 1}, after
    assert not Path("/sys/module/pps_ldisc").exists()
    assert after["memfd"]["default"] == {"executable": False, "seal_exec": True, "chmod_exec": False}, after
    assert after["memfd"]["nx"] == after["memfd"]["default"]
    assert after["memfd"]["exec"]["executable"]
    subprocess.run(["modprobe", "pps_ldisc"], check=True)
    assert worker("ldisc") == {"allowed": True, "errno": 0}
    subprocess.run(["modprobe", "-r", "pps_ldisc"], check=True)
    print(
        json.dumps(
            {"after": after, "perf3": perf3, "privileged_ptrace": "pass", "privileged_ldisc_load": "pass"}
        ),
        flush=True,
    )
finally:
    if Path("/sys/module/pps_ldisc").exists():
        subprocess.run(["modprobe", "-r", "pps_ldisc"], check=True)
    for name, value in original.items():
        path(name).write_text(value)
        assert path(name).read_text() == value, name
    print(
        json.dumps(
            {
                "sysctl_restore": "exact",
                "temporary_ldisc_unloaded": not Path("/sys/module/pps_ldisc").exists(),
            }
        ),
        flush=True,
    )
