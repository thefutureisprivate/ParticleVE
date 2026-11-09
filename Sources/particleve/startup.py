"""Bound and inspect persistent host startup inputs without following writable links.

The owner and privileged configuration managers are trusted. This policy protects
their startup inputs from ordinary services; it is not an offline root-compromise
detector or a replacement for retiring older, unguarded signed images.
"""

import errno
import hashlib
import os
import posixpath
import re
import stat
from pathlib import Path

from .common import digest, read_json, require, run

MAX_FILES = 4096
MAX_BYTES = 16 * 1024**2
MAX_FILE = 4 * 1024**2
IGNORED = {"etc/.pwd.lock", "etc/.updated"}
ACCOUNT_DATA = {"etc/passwd", "etc/group", "etc/shadow", "etc/gshadow", "etc/particleve/report-token"}
HOST_KEY = re.compile(r"etc/ssh/ssh_host_(?:ecdsa|ed25519|rsa)_key(?:\.pub)?\Z")
# These hooks may be absent, empty, or links into the signed factory. Local code
# is supplied in an OS image, rather than executable/interpreted configuration.
FROZEN = (
    "etc/selinux",
    "etc/audit",
    "etc/authselect",
    "etc/security",
    "etc/pam.d",
    "etc/nsswitch.conf",
    "etc/environment",
    "etc/profile",
    "etc/profile.d",
    "etc/bashrc",
    "etc/bash.bashrc",
    "etc/ld.so.conf",
    "etc/ld.so.conf.d",
    "etc/ld.so.preload",
    "etc/modprobe.d",
    "etc/udev",
    "etc/polkit-1/rules.d",
    "etc/dbus-1",
    "etc/rc.d",
    "etc/rc.local",
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "etc/cron.weekly",
    "etc/cron.monthly",
    "etc/crontab",
    "etc/systemd/system-generators",
    "etc/systemd/user-generators",
    "etc/systemd/system-environment-generators",
    "etc/systemd/system.control",
    "etc/systemd/system.attached",
)
VM_DROPIN = re.compile(
    r"etc/systemd/system/systemd-vmspawn@[A-Za-z0-9_][A-Za-z0-9_.-]*\.service\.d/"
    r"[A-Za-z0-9_-][A-Za-z0-9_.-]*\.conf\Z"
)
CONSOLE_DROPIN = re.compile(
    r"etc/systemd/system/(?:getty\.target\.d/50-particleve-console\.conf|"
    r"serial-getty@ttyS[0-9]+\.service\.d/50-particleve\.conf)\Z"
)


def _metadata(info, path):
    require(info.st_uid == 0, f"startup input is not owned by root: /{path}")
    require(
        stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022,
        f"startup input is writable by another account: /{path}",
    )
    require(
        stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_ISREG(info.st_mode),
        f"special file in startup configuration: /{path}",
    )
    require(not stat.S_ISREG(info.st_mode) or info.st_nlink == 1, f"hard-linked startup input: /{path}")
    return {"path": path, "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}


def _acl(fd, path):
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.getxattr(fd, name)
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                continue
            raise
        require(False, f"unreviewed ACL on startup input: /{path}")


def inventory(root=Path("/")):
    """Return hashes and metadata, never configuration/credential contents.

    Descriptor-relative O_NOFOLLOW traversal also works on the read-only root
    probe in the signed initrd, before the installed PID 1 reads writable /etc.
    """
    rows = []
    total = 0

    def visit(parent, name, path):
        nonlocal total
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        row = _metadata(info, path)
        require(len(rows) < MAX_FILES, "startup inventory exceeds its entry limit")
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(name, dir_fd=parent)
            normalized = posixpath.normpath(posixpath.join("/" + posixpath.dirname(path), target))
            special = {
                "etc/mtab": "/proc/self/mounts",
                "etc/resolv.conf": "/run/systemd/resolve/stub-resolv.conf",
            }
            require(
                normalized.startswith("/usr/")
                or normalized == "/dev/null"
                or normalized == special.get(path),
                f"startup link escapes verified usr: /{path}",
            )
            rows.append(row | {"kind": "symlink", "target": target})
            return
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        metadata_only = path in ACCOUNT_DATA or HOST_KEY.fullmatch(path) or path in IGNORED
        if metadata_only and stat.S_ISREG(info.st_mode):
            # Inspect authentication data without reading secrets or requiring
            # DAC_OVERRIDE for mode-000 shadow files. Account/login policy has
            # its own guard; routine sysusers/credential updates are not code.
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
        if stat.S_ISDIR(info.st_mode):
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            require(
                (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid)
                == (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid),
                "startup input changed during inspection",
            )
            _acl(Path("/proc/self/fd") / str(fd) if metadata_only else fd, path)
            if stat.S_ISDIR(info.st_mode):
                rows.append(row | {"kind": "directory"})
                with os.scandir(fd) as entries:
                    names = []
                    for entry in entries:
                        require(len(names) < MAX_FILES, "startup directory exceeds its entry limit")
                        names.append(entry.name)
                for child in sorted(names):
                    visit(fd, child, path + "/" + child)
                return
            require(not info.st_mode & 0o111, f"executable in writable startup configuration: /{path}")
            if path in IGNORED:
                return
            if metadata_only:
                rows.append(row | {"kind": "account-or-credential-data"})
                return
            require(
                not any(path == prefix or path.startswith(prefix + "/") for prefix in FROZEN),
                f"startup hook must originate from verified usr: /{path}",
            )
            require(
                not path.startswith("etc/systemd/system/")
                or VM_DROPIN.fullmatch(path)
                or CONSOLE_DROPIN.fullmatch(path),
                f"only native VM or generated console drop-ins may be regular local units: /{path}",
            )
            require(info.st_size <= MAX_FILE, f"startup file exceeds its size limit: /{path}")
            data = bytearray()
            while block := os.read(fd, min(65536, MAX_FILE + 1 - len(data))):
                data.extend(block)
                require(len(data) <= MAX_FILE, f"growing startup file: /{path}")
            total += len(data)
            require(total <= MAX_BYTES, "startup inventory exceeds its byte limit")
            require(len(data) == info.st_size, "startup input changed during inspection")
            if path == "etc/ld.so.cache":
                # The generated cache changes with /usr. Check its effective
                # library paths separately, without binding a stale package list.
                rows.append(row | {"kind": "verified-usr-library-cache"})
            else:
                rows.append(row | {"kind": "file", "sha256": hashlib.sha256(data).hexdigest()})
        finally:
            os.close(fd)

    rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _metadata(os.fstat(rootfd), "")
        _acl(rootfd, "")
        for name in ("bin", "sbin", "lib", "lib64"):
            info = os.stat(name, dir_fd=rootfd, follow_symlinks=False)
            _metadata(info, name)
            require(
                stat.S_ISLNK(info.st_mode)
                and os.readlink(name, dir_fd=rootfd) in ("usr/" + name, "/usr/" + name),
                f"traditional code path is not an alias into verified usr: /{name}",
            )
        visit(rootfd, "etc", "etc")
    finally:
        os.close(rootfd)
    _library_cache(root)
    result = {"schema": 1, "inputs": rows}
    return result | {"sha256": digest(result)}


def _library_cache(root):
    # Freshly installed roots may not have run ldconfig yet. The loader's
    # standard library directories are the verified aliases checked above.
    try:
        os.stat(Path(root) / "etc/ld.so.cache", follow_symlinks=False)
    except FileNotFoundError:
        return
    result = run(
        ["/usr/bin/env", "LC_ALL=C", "/usr/sbin/ldconfig", "-p", "-C", str(Path(root) / "etc/ld.so.cache")]
    )
    require(not result.stderr.strip(), "library cache inspection produced diagnostics")
    lines = result.stdout.splitlines()
    require(lines and re.fullmatch(r"[0-9]+ libs found in cache .+", lines[0]), "invalid library cache")
    for line in lines[1:]:
        if line.startswith("Cache generated by: ldconfig "):
            continue
        require(" => " in line, "unrecognized library cache entry")
        path = line.rsplit(" => ", 1)[1]
        require(
            posixpath.normpath(path) == path
            and path.startswith(("/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/")),
            "library cache loads from writable state",
        )


def check(root=Path("/")):
    observed = inventory(root)
    approved = _commissioning(root)
    if approved is not None:
        require(type(approved) is dict, "invalid commissioning record")
        require(
            approved.get("startup_policy_sha256") == observed["sha256"],
            "persistent startup configuration changed or lacks approval; recovery/recommissioning required",
        )
    return observed


def _commissioning(root):
    descriptors = [os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)]
    try:
        path = ""
        for name in ("var", "lib", "particleve", "commissioned.json"):
            path = posixpath.join(path, name)
            directory = name != "commissioned.json"
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if directory:
                flags |= os.O_DIRECTORY
            try:
                fd = os.open(name, flags, dir_fd=descriptors[-1])
            except FileNotFoundError:
                return None
            descriptors.append(fd)
            info = os.fstat(fd)
            _metadata(info, path)
            _acl(fd, path)
            if not directory:
                require(
                    stat.S_ISREG(info.st_mode) and info.st_size <= 65536,
                    "commissioning record is not a bounded regular file",
                )
                return read_json(Path("/proc/self/fd") / str(fd))
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
