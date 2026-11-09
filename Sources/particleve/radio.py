"""Installation-selected RFKill policy, enforced without ambient privileges.

The inherited descriptor is the service's only device authority. Keep it open
to inhibit rfkill-input; reconcile ADD/CHANGE events as persistent radios need
not adopt the kernel's global hotplug default. This controls cooperating RFKill
drivers, not arbitrary transmitters or a compromised kernel/root administrator.
"""

import errno
import fcntl
import os
import re
import select
import socket
import stat
import struct
import time
from pathlib import Path

from .common import canonical, digest, read_json, require, run
from .physical import MAX_NODES, Observation

TYPES = ("wlan", "bluetooth", "ultrawideband", "wimax", "wwan", "gps", "fm", "nfc")
EVENT = struct.Struct("=IBBBB")
NOINPUT = 0x5201  # _IO('R', 1), include/uapi/linux/rfkill.h
POLICY_PATH = Path("/etc/particleve/radio-policy.json")
UNIT = "particleve-radio-policy.service"
BLOCK_TIMEOUT = 5


def validate(policy):
    require(
        type(policy) is dict and set(policy) == {"allowed_types"}, "declare the radio allowed_types policy"
    )
    allowed = policy["allowed_types"]
    require(
        type(allowed) is list
        and len(allowed) <= len(TYPES)
        and all(type(name) is str and name in TYPES for name in allowed)
        and len(set(allowed)) == len(allowed),
        "radio allowed_types must be unique canonical RFKill types",
    )
    return policy


def render(policy):
    return {str(POLICY_PATH).lstrip("/"): canonical(validate(policy)).decode()}


def write_event(fd, index, kind, operation, blocked):
    data = EVENT.pack(index, kind, operation, blocked, 0)
    require(os.write(fd, data) == EVENT.size, "incomplete RFKill policy write")


class Control:
    def __init__(self, fd, policy):
        self.fd = fd
        self.allowed = {TYPES.index(name) + 1 for name in validate(policy)["allowed_types"]}
        self.pending = {}

    def initialize(self):
        # Set denied-type defaults before permitting selected types. Avoid an
        # ALL block: restarting this service must not interrupt an allowed NIC.
        # Hardware blocks remain independent of these software-only writes.
        for kind in range(1, len(TYPES) + 1):
            if kind not in self.allowed:
                write_event(self.fd, 0, kind, 3, 1)
        for kind in sorted(self.allowed):
            write_event(self.fd, 0, kind, 3, 0)

    def event(self, data):
        require(len(data) == EVENT.size, "incomplete RFKill event")
        index, kind, operation, soft, hard = EVENT.unpack(data)
        require(
            1 <= kind <= len(TYPES) and operation in (0, 1, 2) and soft in (0, 1) and hard in (0, 1),
            "unknown RFKill event",
        )
        if operation == 1 or soft:
            self.pending.pop(index, None)
        elif kind not in self.allowed:
            # A hard block is independent. Require the software block as well
            # so releasing a physical switch cannot enable a denied transmitter.
            self.block(index, kind)

    def block(self, index, kind):
        self.pending.setdefault(index, time.monotonic())
        require(len(self.pending) <= MAX_NODES, "too many pending RFKill blocks")
        write_event(self.fd, index, kind, 2, 1)

    def reconcile(self, *, sysfs=Path("/sys")):
        # RFKill silently drops events after its per-descriptor queue fills.
        # Independently inspect live state so lost ADD/CHANGE/ACK/DEL events
        # cannot leave a denied device enabled or a stale pending acknowledgment.
        radios = Observation(sysfs).radios()
        require(radios["sysfs_present"], "RFKill class is unavailable")
        unblocked = set()
        for radio in radios["devices"]:
            match = re.fullmatch(r"rfkill([0-9]+)", radio["node"])
            require(match and int(match[1]) <= 0xFFFFFFFF and radio["type"] in TYPES, "unknown RFKill device")
            kind = TYPES.index(radio["type"]) + 1
            if kind not in self.allowed and not radio["soft_blocked"]:
                index = int(match[1])
                unblocked.add(index)
                self.block(index, kind)
        self.pending = {index: started for index, started in self.pending.items() if index in unblocked}

    def drain(self):
        # Bound each batch so a stream of device changes cannot starve the
        # readiness deadline or service watchdog. The descriptor stays nonblocking.
        for _ in range(256):
            try:
                data = os.read(self.fd, EVENT.size)
            except BlockingIOError:
                return True
            require(data, "RFKill event descriptor closed")
            self.event(data)
        return False

    def check_pending(self):
        now = time.monotonic()
        require(
            all(now - started < BLOCK_TIMEOUT for started in self.pending.values()),
            "radio driver did not acknowledge its required software block",
        )


def inherited_descriptor():
    require(os.getuid() != 0 and os.geteuid() != 0, "run radio policy through its unprivileged service")
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    require(
        all(int(status[name].strip(), 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1",
        "radio policy must have no capabilities and no new privileges",
    )
    require(
        os.environ.get("LISTEN_PID") == str(os.getpid())
        and os.environ.get("LISTEN_FDS") == "1"
        and os.environ.get("LISTEN_FDNAMES") == "rfkill-control",
        "radio policy requires exactly one PID1-opened RFKill descriptor",
    )
    fd = 3
    metadata = os.fstat(fd)
    expected = Observation.attribute(Path("/sys/devices/virtual/misc/rfkill/dev"))
    require(
        stat.S_ISCHR(metadata.st_mode)
        and expected == f"{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}"
        and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR,
        "inherited descriptor is not the writable RFKill device",
    )
    os.set_blocking(fd, False)
    os.set_inheritable(fd, False)
    for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        del os.environ[key]
    return fd


def inhibit_input(fd, kernel_config):
    try:
        fcntl.ioctl(fd, NOINPUT)
    except OSError as exc:
        # The ioctl does not exist when the deprecated input handler is compiled
        # out. Accept that precise capability difference, never another failure.
        require(
            exc.errno == errno.ENOTTY
            and "# CONFIG_RFKILL_INPUT is not set" in kernel_config.read_text().splitlines(),
            "cannot inhibit the kernel RFKill input handler",
        )


def serve():
    fd = inherited_descriptor()
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    require(directory == f"/run/credentials/{UNIT}", "radio policy requires its unit credential")
    path = Path(directory) / "radio-policy"
    require(path.stat().st_size <= 1024, "radio policy credential exceeds its bound")
    policy = validate(read_json(path))
    control = Control(fd, policy)
    destination = os.environ.pop("NOTIFY_SOCKET", "")
    require(destination, "radio policy requires service supervision")
    if destination.startswith("@"):
        destination = "\0" + destination[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as notify:
        notify.connect(destination)
        inhibit_input(fd, Path(directory) / "kernel-config")
        control.initialize()
        deadline = time.monotonic() + 10
        last_ping = time.monotonic()
        next_reconcile = time.monotonic()
        ready = False
        while True:
            drained = control.drain()
            if time.monotonic() >= next_reconcile:
                control.reconcile()
                next_reconcile = time.monotonic() + 1
            control.check_pending()
            if not ready:
                require(time.monotonic() < deadline, "radio initialization did not settle")
                if drained and not control.pending:
                    notify.send(f"READY=1\nSTATUS=RFKill policy {digest(policy)}".encode())
                    ready = True
            if time.monotonic() - last_ping >= 5:
                notify.send(b"WATCHDOG=1")
                last_ping = time.monotonic()
            if drained:
                select.select([fd], [], [], 1)


def baseline(
    policy, *, sysfs=Path("/sys"), proc=Path("/proc"), device=Path("/dev/rfkill"), policy_path=POLICY_PATH
):
    validate(policy)
    require(policy_path.read_bytes() == canonical(policy), "radio policy differs from the bound installation")
    require(
        "rfkill.default_state=0" in (proc / "cmdline").read_text().split()
        and Observation.attribute(sysfs / "module/rfkill/parameters/default_state") == "0",
        "RFKill early default is not blocked",
    )
    metadata = device.stat()
    require(
        stat.S_ISCHR(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o600,
        "RFKill device must be writable only by root",
    )
    for unit in ("systemd-rfkill.service", "systemd-rfkill.socket"):
        result = run(["systemctl", "show", "--property=LoadState", "--value", unit])
        require(not result.stderr.strip(), "RFKill inspection diagnostics: " + result.stderr.strip())
        require(result.stdout.strip() == "masked", "native RFKill state restoration is not masked")
    result = run(["systemctl", "show", "--property=ActiveState,SubState,StatusText", UNIT])
    require(not result.stderr.strip(), "RFKill inspection diagnostics: " + result.stderr.strip())
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    require(
        properties
        == {"ActiveState": "active", "SubState": "running", "StatusText": "RFKill policy " + digest(policy)},
        "radio policy service is inactive or using a different configuration",
    )
    radios = Observation(sysfs).radios()
    require(radios["sysfs_present"], "RFKill class is unavailable")
    for radio in radios["devices"]:
        require(radio["type"] in TYPES, "unknown RFKill radio type")
        require(
            radio["type"] in policy["allowed_types"] or radio["soft_blocked"],
            "denied radio lacks its software block: " + radio["node"],
        )
    return {
        "allowed_types": policy["allowed_types"],
        "devices": radios["devices"],
        "early_default_blocked": True,
    }
