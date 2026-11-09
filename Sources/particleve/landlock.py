"""Mandatory post-handoff filesystem restrictions for the x86-64 TLS sender."""

import ctypes
import os
from pathlib import Path

from .common import require

# Linux x86-64 UAPI. This project has no other supported host syscall ABI.
CREATE_RULESET = 444
RESTRICT_SELF = 446
CLOSE_RANGE = 436
MIN_ABI = 5
# Data writes, removal/creation, links/renames, truncation and device ioctls.
# Read/execute access and existing stdout/stderr pipes remain usable. Metadata
# operations such as chmod are not a Landlock filesystem right.
FS_WRITES = (1 << 1) | sum(1 << bit for bit in range(4, 16))


def _libc():
    require(os.uname().machine == "x86_64", "unsupported host syscall ABI")
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    library.syscall.argtypes = (ctypes.c_long,)
    return library


def abi_version():
    abi = _libc().syscall(CREATE_RULESET, ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint32(1))
    require(abi >= MIN_ABI, "Landlock ABI 5 or newer must be enabled")
    return abi


def confine_filesystem():
    require(len(list(Path("/proc/self/task").iterdir())) == 1, "sender must be single-threaded at handoff")
    abi = abi_version()
    library = _libc()
    # Existing descriptors are outside Landlock's path-opening checks. Only the
    # sealed input and the inherited diagnostic pipes belong to this protocol.
    require(
        library.syscall(CLOSE_RANGE, ctypes.c_uint(3), ctypes.c_uint(0xFFFFFFFF), ctypes.c_uint(0)) == 0,
        "cannot close inherited sender descriptors",
    )
    attributes = ctypes.c_uint64(FS_WRITES)
    fd = library.syscall(
        CREATE_RULESET,
        ctypes.byref(attributes),
        ctypes.c_size_t(ctypes.sizeof(attributes)),
        ctypes.c_uint32(0),
    )
    require(fd >= 0, "cannot create sender filesystem ruleset")
    try:
        require(
            library.syscall(RESTRICT_SELF, ctypes.c_int(fd), ctypes.c_uint32(0)) == 0,
            "cannot enforce sender filesystem ruleset",
        )
    finally:
        os.close(fd)
    return abi
