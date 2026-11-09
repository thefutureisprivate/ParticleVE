"""Effective stock-kernel interface policy; no process memory is read."""

import stat
from pathlib import Path

from .common import require

# The file in sysctl.d owns changed settings. The remaining entries assert
# selected Fedora defaults rather than claiming newly enabled protections.
SYSCTLS = {
    "kernel.unprivileged_bpf_disabled": "2",
    "kernel.perf_event_paranoid": "2",
    "vm.unprivileged_userfaultfd": "0",
    "kernel.yama.ptrace_scope": "2",
    "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1",
    "kernel.kexec_load_disabled": "1",
    "dev.tty.ldisc_autoload": "0",
    "vm.memfd_noexec": "1",
    "vm.mmap_rnd_bits": "32",
    "vm.mmap_rnd_compat_bits": "16",
    "vm.mmap_min_addr": "65536",
    "fs.protected_fifos": "2",
    "fs.protected_regular": "2",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
    "kernel.randomize_va_space": "2",
}


def kernel_support(values):
    require(values.get("SECURITY_YAMA") == "y", "kernel Yama policy support is missing")
    for name, expected in (("ARCH_MMAP_RND_BITS_MAX", 32), ("ARCH_MMAP_RND_COMPAT_BITS_MAX", 16)):
        value = values.get(name, "")
        require(
            value.isdecimal() and int(value) >= expected, "kernel ASLR entropy support is missing: " + name
        )
    if values.get("DEVMEM") == "y":
        require(
            values.get("STRICT_DEVMEM") == values.get("IO_STRICT_DEVMEM") == "y",
            "raw physical memory lacks strict kernel restrictions",
        )
    require(values.get("DEVKMEM") != "y", "legacy kernel memory device is enabled")
    return {
        "yama": True,
        "mmap_rnd_bits_max": int(values["ARCH_MMAP_RND_BITS_MAX"]),
        "mmap_rnd_compat_bits_max": int(values["ARCH_MMAP_RND_COMPAT_BITS_MAX"]),
        "strict_devmem": values.get("DEVMEM") == "y",
        "legacy_kmem": False,
    }


def baseline(*, proc=Path("/proc"), dev=Path("/dev")):
    for name, expected in SYSCTLS.items():
        path = proc / "sys" / name.replace(".", "/")
        require(path.read_text().strip() == expected, "kernel runtime policy drift: " + name)
    require(not (dev / "kmem").exists() and not (dev / "kmem").is_symlink(), "legacy kmem device exists")
    interfaces = {}
    for name in ("mem", "userfaultfd"):
        try:
            value = (dev / name).lstat()
        except FileNotFoundError:
            interfaces[name] = False
            continue
        require(
            stat.S_ISCHR(value.st_mode)
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_uid == value.st_gid == 0,
            "raw kernel interface is not a root-only character device: " + name,
        )
        interfaces[name] = True
    try:
        kcore = (proc / "kcore").lstat()
    except FileNotFoundError:
        kcore_present = False
    else:
        require(
            stat.S_ISREG(kcore.st_mode)
            and stat.S_IMODE(kcore.st_mode) == 0o400
            and kcore.st_uid == kcore.st_gid == 0,
            "kernel core interface is not root-only read-only",
        )
        kcore_present = True
    return {"sysctls": dict(SYSCTLS), "root_only_devices": interfaces, "root_only_kcore": kcore_present}
