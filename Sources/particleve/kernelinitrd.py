"""Verify the selected mkosi newc/Zstandard initrd without unpacking foreign paths."""

import hashlib
import json
import re
import stat
import tempfile
from collections import deque
from compression import zstd
from pathlib import Path, PurePosixPath

from .common import Error, hash_file, require, run
from .kernelpayload import MAX_MODULE, METADATA, RECORD, kernel_tree, module_paths, regular, verify
from .kernels import REQUIRED_MODULES, verify_modules
from .provenance import INITRD_BINARIES, identity_path

MAX_INPUT = 512 * 1024**2
MAX_EXPANDED = 1024**3
MAX_ENTRIES = 65536
MAX_ARCHIVES = 16
INDEXES = {
    "modules.alias",
    "modules.alias.bin",
    "modules.builtin.alias.bin",
    "modules.builtin.bin",
    "modules.dep",
    "modules.dep.bin",
    "modules.devname",
    "modules.softdep",
    "modules.symbols",
    "modules.symbols.bin",
    "modules.weakdep",
}
NONZERO = re.compile(rb"[^\0]")


def _archive(data, start, budget, maximum):
    require(start % 4 == 0, "unaligned initrd CPIO archive")
    offset = start
    while True:
        require(offset + 110 <= len(data), "truncated initrd CPIO header")
        header = data[offset : offset + 110]
        require(
            header[:6] == b"070701" and re.fullmatch(rb"[0-9a-fA-F]{104}", header[6:]),
            "initrd requires the selected newc archive format",
        )
        values = [int(header[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        mode, uid, gid, links, size, namesize = (values[i] for i in (1, 2, 3, 4, 6, 11))
        require(1 < namesize <= 4096 and values[12] == 0, "invalid initrd CPIO name or checksum")
        name_end = offset + 110 + namesize
        body = offset + ((110 + namesize + 3) & ~3)
        end = body + ((size + 3) & ~3)
        require(end <= len(data) and end - start <= maximum, "oversized or truncated initrd CPIO entry")
        raw = data[offset + 110 : name_end]
        require(raw.endswith(b"\0"), "unterminated initrd CPIO name")
        raw = raw.rstrip(b"\0")
        require(raw and b"\0" not in raw, "invalid initrd CPIO name")
        name = raw.decode("utf-8")
        require(
            not data[name_end:body].strip(b"\0") and not data[body + size : end].strip(b"\0"),
            "nonzero initrd CPIO padding",
        )
        if name == "TRAILER!!!":
            require(size == 0, "invalid initrd CPIO trailer")
            return end
        name = name.removeprefix("./")
        require(
            name == "."
            or (not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/"))),
            "unsafe initrd CPIO path",
        )
        require(name != "." or (stat.S_ISDIR(mode) and size == 0), "invalid initrd root directory")
        require(stat.S_ISREG(mode) or stat.S_ISLNK(mode) or size == 0, "invalid initrd CPIO file size")
        budget["entries"] += 1
        require(budget["entries"] <= MAX_ENTRIES, "too many initrd entries")
        yield name, mode, uid, gid, links, memoryview(data)[body : body + size]
        offset = end


def entries(data):
    """Read only the formats emitted by the pinned Fedora/mkosi configuration."""
    require(0 < len(data) <= MAX_INPUT, "oversized or empty initrd")
    budget = {"entries": 0, "bytes": 0, "archives": 0}
    offset = 0
    while (found := NONZERO.search(data, offset)) is not None:
        offset = found.start()
        budget["archives"] += 1
        require(budget["archives"] <= MAX_ARCHIVES, "too many initrd archives")
        remaining = MAX_EXPANDED - budget["bytes"]
        if data[offset : offset + 4] == b"\x28\xb5\x2f\xfd":
            decoder = zstd.ZstdDecompressor(options={zstd.DecompressionParameter.window_log_max: 27})
            body = decoder.decompress(memoryview(data)[offset:], max_length=remaining + 1)
            require(decoder.eof and 0 < len(body) <= remaining, "oversized or incomplete initrd compression")
            consumed = len(data) - offset - len(decoder.unused_data)
            end = yield from _archive(body, 0, budget, remaining)
            require(not body[end:].strip(b"\0"), "unexpected data inside compressed initrd archive")
            budget["bytes"] += len(body)
            offset += consumed
        else:
            end = yield from _archive(data, offset, budget, remaining)
            budget["bytes"] += end - offset
            offset = end
    require(budget["archives"] > 0, "initrd contains no archives")


def _policy_files(policy, root):
    require(
        isinstance(policy, dict)
        and set(policy) == {"schema", "files"}
        and policy.get("schema") == 1
        and isinstance(policy.get("files"), dict),
        "invalid initrd policy",
    )
    files = dict(policy["files"])
    identity = identity_path("initrd")
    record = json.loads(regular(Path(root) / identity, 1024**2))
    require(
        isinstance(record, dict)
        and record.get("component") == "initrd"
        and isinstance(record.get("files"), dict)
        and record["files"].keys() == set(INITRD_BINARIES.values()),
        "invalid initrd package record",
    )
    for name, digest in record["files"].items():
        path = Path(root) / name
        require(
            name not in files and path.is_file() and not path.is_symlink(),
            "overlapping or redirected initrd package file",
        )
        require(hash_file(path) == digest, "initrd package payload changed before archive verification")
        files[name] = {
            "kind": "file",
            "mode": stat.S_IMODE(path.stat().st_mode),
            "size": path.stat().st_size,
            "sha256": digest,
        }
    files[identity] = {
        "kind": "file",
        "mode": 0o644,
        "size": (Path(root) / identity).stat().st_size,
        "sha256": hash_file(Path(root) / identity),
    }
    for name in (
        "usr/lib64/libhardened_malloc.so",
        "usr/lib/particleve/source-identities/hardened_malloc.json",
    ):
        path = Path(root) / name
        require(path.is_file() and not path.is_symlink(), "verified allocator payload is missing")
        files[name] = {
            "kind": "file",
            "mode": stat.S_IMODE(path.stat().st_mode),
            "size": path.stat().st_size,
            "sha256": hash_file(path),
        }
    require(1 <= len(files) <= 128, "invalid initrd policy size")
    for name, item in files.items():
        require(
            isinstance(name, str)
            and not name.startswith("/")
            and all(part not in ("", ".", "..") for part in name.split("/"))
            and isinstance(item, dict),
            "invalid initrd policy path",
        )
        require(
            (
                set(item) == {"kind", "target"}
                and item["kind"] == "symlink"
                and isinstance(item["target"], str)
            )
            or (
                set(item) == {"kind", "mode", "size", "sha256"}
                and item["kind"] == "file"
                and type(item["mode"]) is int
                and item["mode"] in (0o644, 0o755)
                and type(item["size"]) is int
                and 0 <= item["size"] <= MAX_MODULE
                and isinstance(item["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            ),
            "invalid initrd policy entry",
        )
    return files


def _resolve(name, symlinks, nodes):
    """Resolve existing parent links as Linux would, without creating any link."""
    if name == ".":
        return name
    pending, resolved, traversed = deque(name.split("/")), [], 0
    while pending:
        part = pending.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        current = "/".join([*resolved, part])
        if not pending:
            return current
        if current in symlinks:
            traversed += 1
            require(traversed <= 40, "initrd path has a symlink cycle")
            target = symlinks[current]
            if target.startswith("/"):
                resolved.clear()
            pending.extendleft(reversed(target.split("/")))
        else:
            require(nodes.get(current) == stat.S_IFDIR, "initrd path parent is not a directory")
            resolved.append(part)
        require(sum(map(len, pending)) + len(pending) <= 4096, "expanded initrd path is too long")
    raise Error("invalid initrd path")


def verify_archive(archive, root, source, certificate, policy, workspace):
    """Check critical files and a signed module subset; never follow archive links."""
    original = kernel_tree(Path(root) / "usr/lib/modules")
    allowed = module_paths(original)
    files = _policy_files(policy, root)
    parents = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}
    parents.update({"usr", "usr/lib", "usr/lib/modules", "usr/lib/modules/" + original.name})
    modules_prefix = "usr/lib/modules/" + original.name + "/"
    module_root = Path(workspace) / "usr/lib/modules" / original.name
    module_root.mkdir(parents=True)
    (Path(workspace) / "lib").symlink_to("usr/lib", target_is_directory=True)
    for name in (*METADATA, RECORD, "vmlinuz"):
        (module_root / name).write_bytes(
            regular(original / name, 256 * 1024**2 if name == "vmlinuz" else MAX_MODULE)
        )
    # The common subset verifier checks the verified userspace kernel/HMAC pair.
    (module_root / ".vmlinuz.hmac").write_bytes(regular(original / ".vmlinuz.hmac", 4096))
    seen, modules, indexes, metadata = set(), set(), {}, set()
    symlinks, nodes = {}, {}
    for name, mode, uid, gid, links, data in entries(regular(archive, MAX_INPUT)):
        normalized = _resolve(name, symlinks, nodes)
        if normalized.startswith("usr/lib/modules/"):
            require(
                normalized == modules_prefix[:-1] or normalized.startswith(modules_prefix),
                "initrd contains a different kernel module tree",
            )
        if normalized in parents or (normalized.startswith("usr/lib/modules/") and stat.S_ISDIR(mode)):
            require(
                stat.S_ISDIR(mode) and uid == gid == 0 and not mode & 0o022,
                "redirected initrd security directory",
            )
        if normalized in files:
            require(normalized not in seen, "duplicate initrd security file")
            seen.add(normalized)
            item = files[normalized]
            require(uid == gid == 0 and links == 1, "aliased or foreign-owned initrd security file")
            if item["kind"] == "symlink":
                require(
                    stat.S_ISLNK(mode) and bytes(data).decode() == item["target"],
                    "initrd security link differs",
                )
            else:
                require(
                    stat.S_ISREG(mode)
                    and stat.S_IMODE(mode) == item["mode"]
                    and len(data) == item["size"]
                    and hashlib.sha256(data).hexdigest() == item["sha256"],
                    "initrd security file differs",
                )
        if stat.S_ISLNK(mode):
            require(0 < len(data) <= 4096, "invalid initrd symlink size")
            target = bytes(data).decode("utf-8")
            require("\0" not in target, "invalid initrd symlink target")
            symlinks[normalized] = target
        else:
            symlinks.pop(normalized, None)
        nodes[normalized] = stat.S_IFMT(mode)
        if not normalized.startswith("usr/lib/modules/") or stat.S_ISDIR(mode):
            continue
        require(normalized.startswith(modules_prefix), "initrd contains a different kernel module tree")
        relative = normalized.removeprefix(modules_prefix)
        require(
            stat.S_ISREG(mode) and links == 1 and uid == gid == 0 and not mode & 0o7022,
            "aliased or unsafe initrd module payload",
        )
        if relative.endswith((".ko", ".ko.xz")):
            require(0 < len(data) <= MAX_MODULE, "oversized or empty initrd module")
            require(
                relative.removesuffix(".xz") in allowed, "initrd module is absent from verified userspace"
            )
            original_module = allowed[relative.removesuffix(".xz")]
            require(
                stat.S_IMODE(mode) == stat.S_IMODE(original_module.stat().st_mode),
                "initrd module mode differs from verified userspace",
            )
            require(
                hashlib.sha256(data).digest() == hashlib.sha256(regular(original_module)).digest(),
                "initrd module differs from verified userspace",
            )
            require(relative not in modules, "duplicate initrd kernel module")
            modules.add(relative)
            target = module_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(data)
        elif relative in INDEXES:
            require(stat.S_IMODE(mode) == 0o644, "unsafe initrd module index mode")
            require(relative not in indexes, "duplicate initrd module index")
            indexes[relative] = hashlib.sha256(data).hexdigest()
        else:
            require(relative not in metadata, "duplicate initrd kernel metadata")
            metadata.add(relative)
            require(
                re.fullmatch(r"modules\.[A-Za-z0-9_.-]+", relative)
                or (
                    re.fullmatch(r"vdso/[A-Za-z0-9_.-]+", relative)
                    and stat.S_ISDIR((original / "vdso").lstat().st_mode)
                ),
                "unreviewed initrd kernel metadata",
            )
            require(
                hashlib.sha256(data).digest() == hashlib.sha256(regular(original / relative)).digest(),
                "initrd kernel metadata differs",
            )
            require(
                stat.S_IMODE(mode) == stat.S_IMODE((original / relative).stat().st_mode),
                "initrd kernel metadata mode differs",
            )
    require(seen == files.keys(), "initrd is missing required admission or recovery files")
    require(modules and indexes.keys() == INDEXES, "initrd module set or dependency indexes are incomplete")
    require(
        set(name for name in METADATA if name.startswith("modules.")) <= metadata,
        "initrd built-in metadata is incomplete",
    )
    result = run(["depmod", "--basedir", workspace, "--all", original.name], timeout=180)
    require(
        not result.stdout.strip() and not result.stderr.strip(), "initrd module indexing produced diagnostics"
    )
    require(
        all(hash_file(module_root / name) == expected for name, expected in indexes.items()),
        "initrd module dependency indexes differ",
    )
    verified = verify(module_root.parent, source, certificate, filtered=True)
    verify_modules(module_root.parent, required=REQUIRED_MODULES - {"kvm_amd", "kvm_intel"})
    return {
        "sha256": hash_file(archive),
        "module_files": len(modules),
        "security_files": len(files),
        "kernel": verified["kernel"],
    }


def verify_uki_initrd(uki, root, source, certificate, policy, workspace):
    require(0 < Path(uki).stat().st_size <= MAX_EXPANDED, "oversized UKI")
    inspection = run(["/usr/lib/systemd/ukify", "--json=short", "inspect", uki])
    require(not inspection.stderr.strip(), "UKI inspection produced diagnostics")
    section = json.loads(inspection.stdout)[".initrd"]
    size = section["size"]
    require(type(size) is int and 0 < size <= MAX_INPUT, "oversized UKI initrd section")
    with tempfile.TemporaryDirectory(prefix=".initrd-verify-", dir=workspace) as temporary:
        work = Path(temporary)
        archive = work / "initrd"
        result = run(["objcopy", "--dump-section", f".initrd={archive}", uki, work / "copy.efi"], timeout=180)
        require(
            not result.stdout.strip() and not result.stderr.strip(),
            "UKI section extraction produced diagnostics",
        )
        (work / "copy.efi").unlink()
        data = regular(archive, MAX_INPUT + 65536)
        require(
            size <= len(data) <= size + 65536 and not data[size:].strip(b"\0"), "invalid UKI initrd padding"
        )
        require(hashlib.sha256(data[:size]).hexdigest() == section["sha256"], "UKI initrd extraction differs")
        with archive.open("r+b") as output:
            output.truncate(size)
        try:
            return verify_archive(archive, root, source, certificate, policy, work / "payload")
        except (OSError, ValueError, KeyError, zstd.ZstdError) as exc:
            raise Error(f"initrd payload verification failed: {exc}") from exc
