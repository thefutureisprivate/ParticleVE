"""Bind native kernel payloads before off-host signing and verify them afterwards.

This standalone build helper records modules after Fedora's debug/strip steps.
OBS may append a PKCS#7 signature and compress a module; neither operation may
change its recorded ELF body. OpenSSL verifies the signature independently.
"""

import argparse
import hashlib
import json
import lzma
import os
import re
import stat
import struct
import subprocess
import tempfile
from pathlib import Path

MAGIC = b"~Module signature appended~\n"
MAX_MODULE = 64 * 1024**2
RECORD = "particleve-kernel.json"
METADATA = ("config", "System.map", "modules.builtin", "modules.builtin.modinfo", "modules.order")


def regular(path, maximum=MAX_MODULE):
    path = Path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
        raise ValueError(f"not a bounded regular kernel payload: {path.name}")
    return path.read_bytes()


def command(arguments, *, expected_stderr=b""):
    result = subprocess.run(
        arguments, capture_output=True, check=True, timeout=60, env={**os.environ, "LC_ALL": "C"}
    )
    if len(result.stdout) > 1024**2 or len(result.stderr) > 65536:
        raise ValueError("oversized native kernel verification result")
    if result.stderr.strip() != expected_stderr:
        raise ValueError("unexpected native kernel verification diagnostic: " + result.stderr[:512].decode())
    return result.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def module_parts(path):
    """Read the selected x86-64 module ABI, with bounded XZ decompression."""
    path = Path(path)
    data = regular(path)
    if path.name.endswith(".ko.xz"):
        # The in-kernel XZ decoder supports CRC32, while liblzma also accepts
        # CRC64 and SHA256. Userspace decompression alone cannot prove this ABI.
        if len(data) < 12 or data[:8] != b"\xfd7zXZ\0\0\x01":
            raise ValueError("kernel XZ modules require the selected CRC32 stream format")
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024**2)
        data = decoder.decompress(data, max_length=MAX_MODULE + 1)
        if len(data) > MAX_MODULE or not decoder.eof or decoder.unused_data:
            raise ValueError("oversized, incomplete or concatenated kernel module")
    elif not path.name.endswith(".ko"):
        raise ValueError("kernel modules require the selected uncompressed or XZ format")
    signature = None
    if data.endswith(MAGIC):
        if len(data) < len(MAGIC) + 12:
            raise ValueError("truncated kernel module signature")
        boundary = len(data) - len(MAGIC) - 12
        algorithm, hash_id, kind, signer, key, padding, length = struct.unpack(
            ">5B3sI", data[boundary : boundary + 12]
        )
        if (algorithm, hash_id, kind, signer, key, padding) != (0, 0, 2, 0, 0, b"\0\0\0"):
            raise ValueError("unsupported kernel module signature header")
        if not 0 < length <= 65536 or boundary - length < 64:
            raise ValueError("invalid kernel module signature size")
        signature, data = data[boundary - length : boundary], data[: boundary - length]
    if (
        len(data) < 64
        or data[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<HHI", data, 16) != (1, 62, 1)
        or data.endswith(MAGIC)
    ):
        raise ValueError("kernel module is not one unsigned x86-64 ELF body")
    return data, signature


def prepare_signing_continuation(path):
    """Carry the kernel's XZ ABI into the separate native OBS signing worker."""
    path = Path(path)
    recipe = regular(path, 1024**2)
    marker = b"\n%install\n"
    environment = b"export XZ_DEFAULTS= XZ_OPT='--check=crc32 --threads=1'\n"
    if recipe.count(marker) != 1 or environment in recipe or b"\0" in recipe:
        raise ValueError("unexpected or already prepared native kernel signing recipe")
    # The native generator compresses modules before loading its final RPM
    # macros. Set this in the outer continuation, before that generator runs.
    path.write_bytes(recipe.replace(marker, marker + environment, 1))


def module_paths(tree):
    result = {}
    for path in tree.rglob("*.ko*"):
        name = path.relative_to(tree).as_posix().removesuffix(".xz")
        if (
            not name.endswith(".ko")
            or not re.fullmatch(r"[A-Za-z0-9_+./-]{1,512}", name)
            or any(part in (".", "..") for part in name.split("/"))
            or name in result
        ):
            raise ValueError("unexpected, duplicate or unsupported kernel module path")
        # lstat also rejects a module symlink rather than following it.
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("kernel module path is not a regular file")
        result[name] = path
        if len(result) > 16384:
            raise ValueError("too many kernel modules")
    if not result:
        raise ValueError("kernel module payload is empty")
    return dict(sorted(result.items()))


def kernel_tree(directory):
    trees = list(Path(directory).iterdir())
    if len(trees) != 1 or trees[0].is_symlink() or not trees[0].is_dir():
        raise ValueError("kernel payload requires exactly one regular module tree")
    if not re.fullmatch(r"[A-Za-z0-9_+.-]{1,128}", trees[0].name):
        raise ValueError("invalid kernel release")
    return trees[0]


def certificate_digest(certificate):
    regular(certificate, 65536)
    der = command(["openssl", "x509", "-in", str(certificate), "-outform", "DER"])
    if not 128 <= len(der) <= 16384:
        raise ValueError("invalid project certificate size")
    return digest(der)


def authenticode(path):
    regular(path, 256 * 1024**2)
    result = command(["pesign", "--hash", "--padding", "--digest-type=sha256", "--in", str(path)])
    hashes = re.findall(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", result)
    if len(hashes) != 1:
        raise ValueError("ambiguous kernel Authenticode digest")
    return hashes[0].decode().lower()


def verify_configuration(tree, selected):
    text = regular(tree / "config").decode()
    if not isinstance(selected, dict) or not 1 <= len(selected) <= 512:
        raise ValueError("invalid selected kernel configuration")
    for symbol, expected in selected.items():
        if not re.fullmatch(r"CONFIG_[A-Z0-9_]{1,96}", symbol):
            raise ValueError("invalid selected kernel configuration symbol")
        values = re.findall(r"^" + symbol + r"=(.*)$", text, re.M)
        disabled = len(re.findall(r"^# " + symbol + r" is not set$", text, re.M))
        # Kconfig omits disabled symbols whose parent dependency is disabled
        # or whose architecture is unavailable. An enabled selection must be
        # present with its exact resolved value.
        if len(values) + disabled > 1 or (values[0] if values else "n") != expected:
            raise ValueError(f"resolved kernel configuration differs: {symbol}")


def record(directory, source_manifest, certificate):
    tree = kernel_tree(directory)
    source = json.loads(regular(source_manifest, 1024**2))
    if source.get("schema") != 1:
        raise ValueError("invalid kernel source manifest")
    verify_configuration(tree, source["configuration"])
    modules = {}
    for name, path in module_paths(tree).items():
        body, signature = module_parts(path)
        if signature is not None or path.suffix != ".ko":
            raise ValueError("record kernel modules before signing and compression")
        modules[name] = digest(body)
    environment = {
        "packages": sorted(
            command(["rpm", "-qa", "--queryformat", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"])
            .decode()
            .splitlines()
        ),
        "tools": {
            name: command([name, *arguments]).decode().splitlines()[0]
            for name, arguments in (
                ("gcc", ["--version"]),
                ("rustc", ["--version"]),
                ("ld", ["--version"]),
                ("pahole", ["--version"]),
                ("openssl", ["version"]),
            )
        },
    }
    value = {
        "schema": 1,
        "kernel": tree.name,
        "source": source,
        "build_environment": environment,
        "signing_certificate_sha256": certificate_digest(certificate),
        "kernel_authenticode_sha256": authenticode(tree / "vmlinuz"),
        "metadata": {name: digest(regular(tree / name)) for name in METADATA},
        "modules": modules,
    }
    destination = tree / RECORD
    if destination.exists() or destination.is_symlink():
        raise ValueError("kernel payload identity already exists")
    destination.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    destination.chmod(0o644)
    return value


def verify(directory, source, certificate, *, filtered=False):
    tree = kernel_tree(directory)
    value = json.loads(regular(tree / RECORD, 4 * 1024**2))
    if (
        set(value)
        != {
            "schema",
            "kernel",
            "source",
            "build_environment",
            "signing_certificate_sha256",
            "kernel_authenticode_sha256",
            "metadata",
            "modules",
        }
        or value["schema"] != 1
        or value["kernel"] != tree.name
        or value["source"] != source
        or value["signing_certificate_sha256"] != certificate_digest(certificate)
        or value["kernel_authenticode_sha256"] != authenticode(tree / "vmlinuz")
        or value["metadata"] != {name: digest(regular(tree / name)) for name in METADATA}
    ):
        raise ValueError("installed kernel does not match the selected source, payload and trust")
    verify_configuration(tree, source["configuration"])
    expected = value["modules"]
    paths = module_paths(tree)
    if (
        not isinstance(expected, dict)
        or not 1 <= len(expected) <= 16384
        or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in expected.values())
        or (not filtered and set(paths) != set(expected))
        or set(paths) - set(expected)
    ):
        raise ValueError("installed kernel module set differs from its build identity")
    command(["sbverify", "--cert", str(certificate), str(tree / "vmlinuz")])
    with tempfile.TemporaryDirectory(prefix="particleve-module-verify-") as temporary:
        directory = Path(temporary)
        body_path, signature_path = directory / "module", directory / "signature"
        for name, path in paths.items():
            body, signature = module_parts(path)
            if digest(body) != expected[name] or signature is None:
                raise ValueError(f"kernel module body differs or signature is missing: {name}")
            body_path.write_bytes(body)
            signature_path.write_bytes(signature)
            command(
                [
                    "openssl",
                    "cms",
                    "-verify",
                    "-binary",
                    "-inform",
                    "DER",
                    "-in",
                    str(signature_path),
                    "-content",
                    str(body_path),
                    "-nointern",
                    "-certfile",
                    str(certificate),
                    "-noverify",
                    "-out",
                    "/dev/null",
                ],
                expected_stderr=b"CMS Verification successful",
            )
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modules", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--filtered", action="store_true")
    parser.add_argument("--prepare-signing-continuation", type=Path)
    args = parser.parse_args()
    if args.prepare_signing_continuation:
        if any((args.modules, args.source_manifest, args.certificate, args.verify, args.filtered)):
            parser.error("signing recipe preparation must be used alone")
        prepare_signing_continuation(args.prepare_signing_continuation)
        raise SystemExit(0)
    if not all((args.modules, args.source_manifest, args.certificate)):
        parser.error("payload record/verification requires modules, source manifest and certificate")
    if args.verify:
        value = verify(
            args.modules,
            json.loads(regular(args.source_manifest, 1024**2)),
            args.certificate,
            filtered=args.filtered,
        )
    else:
        if args.filtered:
            parser.error("--filtered requires --verify")
        value = record(args.modules, args.source_manifest, args.certificate)
    print(json.dumps({"kernel": value["kernel"], "module_files": len(value["modules"])}))
