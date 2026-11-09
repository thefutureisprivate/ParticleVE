"""Bounded observations tied to one Linux task, including across PID reuse."""

import contextlib
import os
from pathlib import Path

from .common import Error, require

MAX_STATUS = 1024 * 1024
MAX_CMDLINE = 8 * 1024 * 1024
MAX_FDS = 65536
MAX_NAMESPACES = 64


class Process:
    def __init__(self, pid, descriptor):
        self.pid = pid
        self.descriptor = descriptor

    def read_bytes(self, name, maximum=65536):
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.descriptor)
        with os.fdopen(descriptor, "rb") as stream:
            value = stream.read(maximum + 1)
        require(len(value) <= maximum, "process observation exceeds its bound: " + name)
        return value

    def read_text(self, name, maximum=65536):
        try:
            return self.read_bytes(name, maximum).decode("utf-8")
        except UnicodeError as exc:
            raise Error("invalid process observation encoding: " + name) from exc

    def identity(self):
        try:
            # comm may contain whitespace and parentheses; starttime is field
            # 22, counted after the final ')', not after the first word.
            prefix, fields = self.read_text("stat").rsplit(")", 1)
            require(prefix.startswith(f"{self.pid} ("), "process stat PID differs")
            starttime = int(fields.split()[19])
            require(starttime >= 0, "negative process starttime")
            return {"pid": self.pid, "starttime": starttime}
        except (ValueError, IndexError) as exc:
            raise Error(f"cannot parse process identity for PID {self.pid}") from exc

    def status(self):
        result = {}
        for line in self.read_text("status", MAX_STATUS).splitlines():
            key, separator, value = line.partition(":")
            require(separator and key and key not in result, "invalid or duplicate process status field")
            result[key] = value.strip()
        require(result, "empty process status")
        return result

    def arguments(self):
        # argv is mutable process data. Never export it wholesale, even when
        # the executable is trusted: native VM credentials may appear here.
        value = self.read_bytes("cmdline", MAX_CMDLINE).rstrip(b"\0")
        try:
            return value.decode("utf-8").split("\0") if value else []
        except UnicodeError as exc:
            raise Error("invalid process command line encoding") from exc

    def entries(self, name, maximum):
        descriptor = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.descriptor
        )
        try:
            with os.scandir(descriptor) as stream:
                result = []
                for entry in stream:
                    require(len(result) < maximum, "process directory observation exceeds its bound: " + name)
                    result.append(entry.name)
            return result
        finally:
            os.close(descriptor)

    def readlink(self, name):
        return os.readlink(name, dir_fd=self.descriptor)

    def stat(self, name):
        return os.stat(name, dir_fd=self.descriptor)


@contextlib.contextmanager
def observe(pid, *, proc=Path("/proc"), starttime=None):
    require(type(pid) is int and pid > 0, "invalid process PID")
    descriptor = os.open(proc / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        process = Process(pid, descriptor)
        # Linux keeps relative operations on this descriptor tied to the old
        # task after exit/PID reuse. This is not an atomic snapshot of mutable
        # process state. An inventory's starttime also rejects earlier reuse.
        if starttime is not None:
            require(
                process.identity()["starttime"] == starttime, "process identity changed during inspection"
            )
        yield process
    finally:
        os.close(descriptor)
