"""Firmware-backed Btrfs member admission, before any state device is scanned.

This witness is deliberately outside the mirrored filesystem. An old member
must not authorize itself using its own stale copy of installation.json.
"""

import array
import errno
import fcntl
import itertools
import json
import os
import re
import stat
import struct
import sys
import time
import uuid
from pathlib import Path

from .common import Error, canonical, lock, read_json, require, run, write_json

VARIABLE = Path("/sys/firmware/efi/efivars/ParticleVEStorage-59a481c6-fbbc-4d82-8617-37eae6ebdf21")
# Keep atomic session replacement and the shared lock in one writable runtime
# directory. The monitor must not need write access to the rest of /run.
RUNTIME = Path("/run/particleve-admission")
SESSION = RUNTIME / "session.json"


def validate(record):
    require(
        type(record) is dict and type(record.get("schema")) is int and record["schema"] == 1,
        "unsupported storage witness",
    )
    require(
        set(record)
        == {
            "schema",
            "installation_uuid",
            "btrfs_uuid",
            "members",
            "allowed",
            "active",
            "nonce",
            "wait_seconds",
        },
        "incomplete or unknown storage witness fields",
    )
    for field in ("installation_uuid", "btrfs_uuid", "nonce"):
        require(
            type(record[field]) is str and str(uuid.UUID(record[field])) == record[field],
            "invalid witness UUID",
        )
    require(
        type(record["wait_seconds"]) is int and 5 <= record["wait_seconds"] <= 120, "invalid storage wait"
    )
    require(
        type(record["members"]) is dict and set(record["members"]) == {"a", "b"}, "invalid witness membership"
    )
    require(type(record["active"]) is bool, "invalid witness session state")
    require(
        type(record["allowed"]) is list
        and set(record["allowed"]) <= {"a", "b"}
        and len(set(record["allowed"])) == len(record["allowed"]),
        "invalid authoritative storage members",
    )
    for member in record["members"].values():
        require(
            type(member) is dict and set(member) == {"state", "swap", "esp", "luks"},
            "invalid witness device identity",
        )
        for value in member.values():
            require(type(value) is str and str(uuid.UUID(value)) == value, "invalid witness member UUID")
    return record


def load():
    try:
        data = VARIABLE.read_bytes()
        require(data[:4] == b"\x07\0\0\0", "unexpected storage witness attributes")
        require(len(data) <= 4096, "oversized storage witness")

        def unique(pairs):
            result = dict(pairs)
            require(len(result) == len(pairs), "duplicate storage witness field")
            return result

        return validate(json.loads(data[4:], object_pairs_hook=unique))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Error("storage admission witness unavailable; owner recovery is required") from exc


def _write_existing(record):
    data = b"\x07\0\0\0" + canonical(validate(record))
    require(len(data) <= 4096, "storage witness exceeds firmware variable limit")
    # efivarfs cannot rename variables. One SetVariable operation plus readback
    # is the commit; a failed/malformed write is never inferred to mean 'clean'.
    # Runtime updates may only open the existing witness. They cannot create
    # firmware-variable dentries or reconstruct missing admission authority.
    fd = os.open(VARIABLE, os.O_RDONLY)
    flags = array.array("L", [0])
    try:
        fcntl.ioctl(fd, 0x80086601, flags, True)  # FS_IOC_GETFLAGS
        if flags[0] & 0x10:  # efivarfs marks nonstandard variables immutable.
            writable = array.array("L", [flags[0] & ~0x10])
            fcntl.ioctl(fd, 0x40086602, writable)  # FS_IOC_SETFLAGS
        writer = os.open(VARIABLE, os.O_WRONLY)
        try:
            require(os.write(writer, data) == len(data), "short storage witness write")
        finally:
            os.close(writer)
        # efivarfs has no fsync operation. Its write synchronously invokes
        # firmware SetVariable; successful readback is mandatory below.
    finally:
        if flags[0] & 0x10:
            fcntl.ioctl(fd, 0x40086602, flags)
        os.close(fd)
    require(load() == record, "storage witness write did not persist")


def save(record):
    from .witness import save as isolated_save

    isolated_save(record)


def bindings(manifest):
    return {
        disk["role"]: {
            **{p["role"]: p["uuid"] for p in disk["partitions"] if p["role"] in ("state", "swap", "esp")},
            "luks": disk["state_luks_uuid"],
        }
        for disk in manifest["devices"]
    }


def initialize(manifest):
    require(not VARIABLE.exists(), "existing storage witness requires owner review before reinstall")
    record = {
        "schema": 1,
        "installation_uuid": manifest["installation_uuid"],
        "btrfs_uuid": manifest["btrfs"]["uuid"],
        "members": bindings(manifest),
        "allowed": ["a", "b"],
        "active": False,
        "nonce": str(uuid.uuid4()),
        "wait_seconds": manifest["storage_wait_seconds"],
    }
    # Only the explicitly confirmed fresh installer creates this one dentry.
    # Keep it open until its first write; efivarfs removes empty closed files.
    fd = os.open(VARIABLE, os.O_RDONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_existing(record)
    finally:
        os.close(fd)


def choose(record, present):
    """Pure transition: no device may be opened before the result is durable."""
    validate(record)
    require(
        not record["active"],
        "unclean storage session; select an authoritative survivor in owner recovery",
    )
    allowed = [role for role in record["allowed"] if role in present]
    require(
        allowed, "only quarantined or no storage members are present; rebuild from the authoritative survivor"
    )
    return {**record, "allowed": allowed, "active": True, "nonce": str(uuid.uuid4())}


def disk_sequence(state_uuid):
    partition = Path("/dev/disk/by-partuuid", state_uuid).resolve(strict=True)
    sys = Path("/sys/class/block", partition.name).resolve(strict=True)
    require((sys / "partition").exists(), "state must be a physical disk partition")
    return (sys.parent / "diskseq").read_text().strip()


def begin():
    record = load()
    wait = record["wait_seconds"]
    require(type(wait) is int and 5 <= wait <= 120, "invalid storage admission wait")
    deadline = time.monotonic() + wait
    while True:
        present = [
            role
            for role in record["allowed"]
            if Path("/dev/disk/by-partuuid", record["members"][role]["state"]).exists()
        ]
        if len(present) == len(record["allowed"]) or time.monotonic() >= deadline:
            break
        time.sleep(1)
    selected = choose(record, present)
    sequences = {r: disk_sequence(selected["members"][r]["state"]) for r in selected["allowed"]}
    _write_existing(selected)  # quarantine missing members BEFORE unlock, scan or writable mount
    write_json(SESSION, {"witness": selected, "diskseq": sequences})


def verify_manifest(manifest, *, replacing=None):
    record = load()
    expected = record["members"].copy()
    if replacing and bindings(manifest) != expected:
        require(
            replacing not in record["allowed"] and len(record["allowed"]) == 1,
            "replacement target was not quarantined",
        )
        expected[replacing] = bindings(manifest)[replacing]
    require(
        manifest.get("storage_admission") == "uefi-witness-v1"
        and manifest.get("installation_uuid") == record["installation_uuid"]
        and manifest["btrfs"]["uuid"] == record["btrfs_uuid"]
        and bindings(manifest) == expected,
        "encrypted installation and firmware storage witness disagree",
    )
    return record


def mounted_uuid(target):
    # Linux UAPI BTRFS_IOC_FS_INFO = _IOR(0x94, 31, 1024). Its fsid starts
    # after max_id/num_devices; this queries mounted kernel state, not media.
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        info = bytearray(1024)
        fcntl.ioctl(fd, 0x8400941F, info, True)
        return str(uuid.UUID(bytes=bytes(info[16:32])))
    finally:
        os.close(fd)


def mounts(record):
    table = json.loads(
        run(["findmnt", "--json", "--list", "--types", "btrfs", "--output", "SOURCE,OPTIONS,TARGET"]).stdout
    )
    selected = []
    sources = {Path(f"/dev/mapper/particleve-state-{role}").resolve() for role in record["members"]}
    for mounted in table.get("filesystems", []):
        source = Path(mounted["source"].split("[", 1)[0]).resolve()
        if source not in sources:
            continue  # never probe unrelated mounted storage
        # findmnt's UUID column probes the block device and disappears on I/O
        # failure. Btrfs obtains this identity from the mounted kernel fs_info.
        require(
            mounted_uuid(mounted["target"]) == record["btrfs_uuid"],
            "mounted state filesystem identity changed",
        )
        selected.append(mounted)
    require(selected, "authoritative Btrfs filesystem is not mounted")
    return sorted(selected, key=lambda m: len(m["target"]))


def member_errors(record, target, mapper):
    """Read kernel counters for this mapping without inspecting a replacement target."""
    expected = Path(mapper).resolve(strict=True)
    require(stat.S_ISBLK(expected.stat().st_mode), "storage member is not a block device")
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        # Linux UAPI: FS_INFO is 1024 bytes with fsid at offset 16. Bind all
        # following ioctls to this open filesystem, independently of sysfs paths.
        info = bytearray(1024)
        fcntl.ioctl(fd, 0x8400941F, info, True)
        require(
            str(uuid.UUID(bytes=bytes(info[16:32]))) == record["btrfs_uuid"], "storage filesystem changed"
        )
        directory = Path("/sys/fs/btrfs", record["btrfs_uuid"], "devinfo")
        entries = list(itertools.islice(directory.iterdir(), 4))
        require(1 <= len(entries) <= 3, "unexpected Btrfs device inventory")
        ids = []
        for entry in entries:
            require(re.fullmatch(r"[0-9]{1,20}", entry.name), "invalid Btrfs device ID")
            devid = int(entry.name)
            require(str(devid) == entry.name and devid < 2**64, "invalid Btrfs device ID")
            if devid:
                ids.append(devid)  # Device 0 is the unadmitted replacement target.
        require(len(ids) == len(set(ids)), "duplicate Btrfs device ID")
        matches = []
        for devid in ids:
            # DEV_INFO is a 4096-byte in/out buffer: devid at 0, path at 3072.
            device = bytearray(4096)
            struct.pack_into("=Q", device, 0, devid)
            try:
                fcntl.ioctl(fd, 0xD000941E, device, True)
            except OSError as exc:
                if exc.errno == errno.ENODEV:
                    continue  # An unselected member can disappear during replacement.
                raise
            require(struct.unpack_from("=Q", device)[0] == devid, "Btrfs device identity changed")
            path = bytes(device[3072:])
            require(b"\0" in path, "unterminated Btrfs device path")
            path = path.split(b"\0", 1)[0].decode()
            if path:
                require(Path(path).is_absolute(), "invalid Btrfs device path")
                if Path(path).resolve() == expected:
                    matches.append(devid)
        require(len(matches) == 1, "admitted Btrfs mapping is unavailable or ambiguous")
        # GET_DEV_STATS is 1032 bytes (including its historical padding). Request
        # the five u64 counters with flags=0: this must never reset them. An
        # all-device query races the removal of device 0 at replacement completion.
        stats = bytearray(1032)
        struct.pack_into("=QQQ", stats, 0, matches[0], 5, 0)
        fcntl.ioctl(fd, 0xC4089434, stats, True)
        require(
            struct.unpack_from("=QQQ", stats) == (matches[0], 5, 0),
            "incomplete Btrfs member error inventory",
        )
        return struct.unpack_from("=5Q", stats, 24)
    finally:
        os.close(fd)


def watch():
    """Fence a failed mapping for this boot as well as quarantining future boots.

    A removed disk's kernel object is never rebound by a by-id path returning.
    Transient I/O faults also fence the live dm target: reconnecting hardware
    cannot make the old replica readable again through that mapping.
    """
    with lock(RUNTIME):
        session = read_json(SESSION)
        record = load()
        require(record == session["witness"] and record["active"], "storage session witness changed")
        require(record["allowed"], "no authoritative storage members remain; owner recovery required")
        target = mounts(record)[0]["target"]
        failed = set()
        for role in record["allowed"]:
            try:
                if disk_sequence(record["members"][role]["state"]) != session["diskseq"][role]:
                    failed.add(role)
            except OSError, Error:
                failed.add(role)
            if role in failed:
                continue
            mapper = f"/dev/mapper/particleve-state-{role}"
            if any(member_errors(record, target, mapper)):
                failed.add(role)
        if not failed:
            return {"storage_admission": record["allowed"]}
        new = {
            **record,
            "allowed": [r for r in record["allowed"] if r not in failed],
            "nonce": str(uuid.uuid4()),
        }
        persistence_error = None
        try:
            save(new)  # durable revocation precedes live fencing when possible
        except (Error, OSError) as exc:
            # The existing active marker blocks every unclean boot. Even when
            # NVRAM is full/unwritable, stop reads from the observed bad replica.
            persistence_error = exc
        for role in sorted(failed):
            mapper = f"particleve-state-{role}"
            sectors = run(["blockdev", "--getsz", f"/dev/mapper/{mapper}"]).stdout.strip()
            require(sectors.isdigit() and int(sectors) > 0, "invalid failed mapper geometry")
            run(["dmsetup", "suspend", "--noflush", "--nolockfs", mapper])
            run(["dmsetup", "reload", mapper, "--table", f"0 {sectors} error"])
            # A failed reload MUST leave the mapping suspended. Resuming the
            # old crypt target would make stale replicas readable again.
            run(["dmsetup", "resume", mapper])
        if persistence_error:
            raise Error(f"failed mappings fenced; quarantine persistence failed: {persistence_error}")
        write_json(SESSION, {"witness": new, "diskseq": {r: session["diskseq"][r] for r in new["allowed"]}})
        raise Error(
            "failed storage members fenced and quarantined; stop guests and rebuild in owner maintenance"
        )


def finish():
    """Late system-shutdown hook: clear dirty only AFTER all Btrfs mounts are RO."""
    session = read_json(SESSION)
    record = load()
    require(record == session["witness"], "storage admission changed during this session")
    mounted = mounts(record)
    require(
        all("ro" in m["options"].split(",") for m in mounted),
        "Btrfs is still writable; retaining unclean storage witness",
    )
    run(["btrfs", "device", "stats", "--check", mounted[0]["target"]])
    for role in record["allowed"]:
        require(
            disk_sequence(record["members"][role]["state"]) == session["diskseq"][role],
            "storage member disappeared or returned during this session",
        )
    save({**record, "active": False})


def recover(role, confirmation):
    """Recovery may reduce authority to ONE disk; it can never readmit a peer."""
    record = load()
    require(
        confirmation == record["installation_uuid"],
        "confirm the installation UUID from the reviewed recovery record",
    )
    require(role in record["allowed"], "a quarantined member cannot authorize itself")
    require(
        not Path("/sys/fs/btrfs", record["btrfs_uuid"]).exists(),
        "unmount the installed Btrfs filesystem before selecting a survivor",
    )
    disk_sequence(record["members"][role]["state"])
    _write_existing({**record, "allowed": [role], "active": False, "nonce": str(uuid.uuid4())})


def readmit(manifest, role):
    """Only finalized foreground replacement may introduce the freshly erased member."""
    with lock(RUNTIME):
        _readmit(manifest, role)


def _readmit(manifest, role):
    record = load()
    if role in record["allowed"] and bindings(manifest) == record["members"]:
        require(read_json(SESSION)["witness"] == record, "completed replacement session changed")
        return
    require(
        role not in record["allowed"] and len(record["allowed"]) == 1,
        "replacement requires a quarantined target and one authority",
    )
    require(manifest["installation_uuid"] == record["installation_uuid"], "replacement installation changed")
    updated = bindings(manifest)
    peer = record["allowed"][0]
    require(
        updated[peer] == record["members"][peer]
        and all(updated[role][k] != record["members"][role][k] for k in ("state", "swap", "esp", "luks")),
        "replacement must preserve the survivor and erase the quarantined member",
    )
    new = {**record, "members": updated, "allowed": ["a", "b"], "active": True, "nonce": str(uuid.uuid4())}
    save(new)
    write_json(
        SESSION,
        {"witness": new, "diskseq": {r: disk_sequence(new["members"][r]["state"]) for r in new["allowed"]}},
    )


def main():
    require(os.geteuid() == 0, "storage admission requires root")
    if sys.argv[1:] == ["begin"]:
        begin()
    elif sys.argv[1:] == ["finish"]:
        finish()
    elif sys.argv[1:] == ["watch"]:
        watch()
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify_manifest(read_json(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "startup":
        from .startup import check

        check(Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "recover" and sys.argv[2] in ("a", "b"):
        recover(sys.argv[2], sys.argv[3])
    else:
        raise Error(
            "expected begin, finish, watch, verify MANIFEST, startup ROOT or recover ROLE INSTALLATION_UUID"
        )


def cli():
    try:
        main()
    except (Error, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ParticleVE storage admission: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(cli())
