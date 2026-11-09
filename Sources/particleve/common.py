"""Durable state and bounded, shell-free subprocesses."""

import contextlib
import fcntl
import json
import os
import selectors
import subprocess
import tempfile
import time
from pathlib import Path


class Error(Exception):
    """An actionable configuration or platform failure."""


class Deferred(Error):
    """A maintenance action must leave the host running."""


def require(condition, message):
    if not condition:
        raise Error(message)


def require_active_services(*units):
    # is-active with several names succeeds when any one is active.
    for unit in units:
        result = run(["systemctl", "is-active", "--quiet", unit], check=False)
        require(result.returncode == 0, f"required service is not active: {unit}")


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def read_json(path):
    try:
        return json.loads(Path(path).read_text(), object_pairs_hook=_unique)
    except (OSError, ValueError) as exc:
        raise Error(f"cannot read {path}: {exc}") from exc


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def digest(value):
    import hashlib

    return hashlib.sha256(canonical(value)).hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_json(path, value):
    atomic_write(path, canonical(value))


@contextlib.contextmanager
def lock(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # All commands, including maintenance enter/leave, use this same inode.
    with (directory / "maintenance.lock").open("a+b") as stream:
        os.chmod(stream.name, 0o600)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Deferred("another maintenance operation holds the lock") from exc
        yield


def run(args, *, input=None, timeout=120, check=True):
    try:
        result = subprocess.run(
            [str(arg) for arg in args],
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"{args[0]}: {exc}") from exc
    if check and result.returncode:
        raise Error(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def capture_bounded(args, *, timeout=10, maximum_bytes=65536):
    """Read a diagnostic child's two streams within one byte/time budget."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with subprocess.Popen(
            [str(arg) for arg in args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"},
        ) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    for name in buffers:
                        selector.register(getattr(child, name), selectors.EVENT_READ, name)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        require(remaining > 0, "diagnostic observation exceeded its deadline")
                        for key, _ in selector.select(remaining):
                            data = os.read(key.fd, 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            buffers[key.data].extend(data)
                            require(
                                sum(map(len, buffers.values())) <= maximum_bytes,
                                "diagnostic observation exceeds its size limit",
                            )
                status = child.wait(timeout=max(0.1, deadline - time.monotonic()))
            finally:
                # Never signal the observed daemon, a service cgroup or a VM.
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise Error("diagnostic observation unavailable: " + type(exc).__name__) from exc
    try:
        return subprocess.CompletedProcess(
            args, status, buffers["stdout"].decode("utf-8"), buffers["stderr"].decode("utf-8")
        )
    except UnicodeError as exc:
        raise Error("diagnostic observation is not UTF-8") from exc


def hash_file(path, size=None):
    import hashlib

    result = hashlib.sha256()
    remaining = size
    with Path(path).open("rb", buffering=0) as stream:
        while remaining is None or remaining > 0:
            chunk = stream.read(min(1024 * 1024, remaining) if remaining is not None else 1024 * 1024)
            if not chunk:
                require(remaining in (None, 0), f"short read: {path}")
                break
            result.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return result.hexdigest()


def array_uuid(name):
    fields = dict(
        line.split("=", 1)
        for line in run(["mdadm", "--detail", "--export", f"/dev/md/{name}"]).stdout.splitlines()
        if "=" in line
    )
    require(fields.get("MD_UUID"), f"array UUID unavailable: {name}")
    return fields["MD_UUID"]
