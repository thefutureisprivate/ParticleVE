"""Durable state and bounded, shell-free subprocesses."""

import contextlib
import fcntl
import json
import os
import platform
import ssl
import subprocess
import tempfile
from pathlib import Path


class Error(Exception):
    """An actionable configuration or platform failure."""


class Deferred(Error):
    """A conflicting operation must leave the existing owner undisturbed."""


def require(condition, message):
    if not condition:
        raise Error(message)


def system_tls_context():
    """Use OpenSSL's distribution trust paths, independent of per-tool CA overrides."""
    if platform.freedesktop_os_release().get("ID") == "fedora":
        return ssl.create_default_context(cafile="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    paths = ssl.get_default_verify_paths()
    return ssl.create_default_context(cafile=paths.openssl_cafile, capath=paths.openssl_capath)


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
