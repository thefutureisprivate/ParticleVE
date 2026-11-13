"""Prepare the reviewed secureblue policy on immutable Fedora kernel sources.

Upstream shell and RPM recipes are data here. In particular, generating a
Renovate change must not execute either recipe with repository write authority.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
SYMBOL = re.compile(r"CONFIG_[A-Z0-9_]{1,96}")


def regular(path, maximum=16 * 1024**2):
    path = Path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 <= metadata.st_size <= maximum:
        raise ValueError(f"not a bounded regular kernel source: {path.name}")
    return path.read_bytes()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def lookaside(text):
    """Read Fedora's pinned checksum list without interpreting shell or RPM."""
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r"SHA512 \(([^)]+)\) = ([0-9a-f]{128})", line)
        if not match or not FILENAME.fullmatch(match[1]) or match[1] in result:
            raise ValueError("invalid or duplicate Fedora lookaside source")
        result[match[1]] = match[2]
    if not 1 <= len(result) <= 16:
        raise ValueError("invalid Fedora lookaside source count")
    return result


def configuration(script, policy):
    """Extract only the literal config arrays used by the reviewed upstream."""
    if policy.get("schema") != 1 or set(policy) != {
        "schema",
        "overrides",
        "spec_patches",
        "excluded_patches",
        "retained_builtin",
    }:
        raise ValueError("invalid kernel adaptation policy")
    selected = {}
    for name, value in (("enable", "y"), ("disable", "n")):
        arrays = re.findall(r"^configs_to_" + name + r"=\(\n(.*?)^\)\s*$", script, re.M | re.S)
        if len(arrays) != 1:
            raise ValueError(f"secureblue {name} config array changed")
        for line in arrays[0].splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not SYMBOL.fullmatch(line) or line in selected:
                raise ValueError("nonliteral or duplicate secureblue config selection")
            selected[line] = value
    if not 1 <= len(selected) <= 512:
        raise ValueError("invalid secureblue config count")
    overrides = policy["overrides"]
    if not isinstance(overrides, dict):
        raise ValueError("invalid kernel config overrides")
    for symbol, override in overrides.items():
        if (
            not SYMBOL.fullmatch(symbol)
            or not isinstance(override, dict)
            or set(override) != {"value", "reason"}
            or override["value"]
            not in ("y", "m", "n", '""', '"certs/particleve-fedora.pem"', '"kernel.sbat"')
            or not isinstance(override["reason"], str)
            or not 16 <= len(override["reason"]) <= 512
        ):
            raise ValueError("invalid or unexplained kernel config override")
        selected[symbol] = override["value"]
    return dict(sorted(selected.items()))


def config_text(selected):
    return "".join(
        f"# {symbol} is not set\n" if value == "n" else f"{symbol}={value}\n"
        for symbol, value in selected.items()
    )


def fedora_version(spec):
    fields = {}
    for name in ("specrpmversion", "specversion", "pkgrelease", "tarfile_release", "kabiversion"):
        values = re.findall(r"^%define " + name + r" ([0-9][0-9A-Za-z.+~-]{0,63})$", spec, re.M)
        if len(values) != 1:
            raise ValueError(f"Fedora kernel {name} definition changed")
        fields[name] = values[0]
    if fields["specrpmversion"] != fields["specversion"]:
        raise ValueError("Fedora kernel source and package versions differ")
    return fields


def source_manifest(fedora, filenames):
    """Bind every flat Git input and every lookaside archive to its pin."""
    fedora = Path(fedora)
    names = set(filenames)
    if len(names) != len(filenames) or not {"kernel.spec", "kernel-local", "sources"} <= names:
        raise ValueError("incomplete or duplicate Fedora packaging file list")
    if len(names) > 512 or any(name != ".gitignore" and not FILENAME.fullmatch(name) for name in names):
        raise ValueError("Fedora kernel packaging requires reviewed flat filenames")
    archives = lookaside(regular(fedora / "sources").decode())
    if names & set(archives):
        raise ValueError("Fedora Git input collides with a lookaside archive")
    return {
        "git_files": {name: sha256(regular(fedora / name)) for name in sorted(names - {".gitignore"})},
        "git_modes": {name: filenames[name] for name in sorted(names - {".gitignore"})},
        "lookaside_sha512": archives,
    }


def verify_sources(directory, manifest):
    directory = Path(directory)
    expected = set(manifest["git_files"]) - {"sources"} | set(manifest["lookaside_sha512"])
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("source RPM payload differs from the pinned Fedora input set")
    for name in sorted(expected):
        algorithm = "sha512" if name in manifest["lookaside_sha512"] else "sha256"
        wanted = manifest["lookaside_sha512"].get(name) or manifest["git_files"][name]
        path = directory / name
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 512 * 1024**2:
            raise ValueError("nonregular or oversized Fedora source")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, algorithm).hexdigest()
        if actual != wanted:
            raise ValueError(f"Fedora source digest differs: {name}")


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Fedora recipe boundary changed: {old}")
    return text.replace(old, new)


def adapt_spec(spec, manifest):
    """Keep Fedora's build machinery; separate its in-worker signing authority."""
    fields = fedora_version(spec)
    spec = replace_once(spec, "# define buildid .local", "%define buildid .particleve")
    spec = replace_once(spec, "%global signkernel 1\n", "%global signkernel 0\n")
    spec = replace_once(spec, "%global signmodules 1\n", "%global signmodules 0\n")
    # Fedora's log and patch-declaration checks assume the input spec is under
    # _specdir. OBS invokes a sources-directory spec; use the independently
    # authenticated original recipe, without its native counter/VCS rewrites.
    lookup = "%{_specdir}/${RPM_PACKAGE_NAME}.spec"
    if spec.count(lookup) != 2:
        raise ValueError("Fedora recipe lookup boundary changed")
    spec = spec.replace(lookup, "%{SOURCE5003}")
    # Fedora's hmaccalc provider uses AF_ALG, which an OBS worker kernel may
    # omit. Preserve the exact compatibility HMAC format with userspace hashing.
    for arguments in (
        "$InstallName-$KernelVer",
        "$InstallName-virt.efi",
        "$(basename $DtbloaderImage)",
    ):
        spec = replace_once(spec, "sha512hmac " + arguments, "python3 %{SOURCE5010} --hmac-file " + arguments)
    spec = replace_once(spec, "redhat-rpm-config, hmaccalc, bison", "redhat-rpm-config, bison")
    # baseonly removes extra kernel variants/tools, not DWARF/BTF generation.
    spec = "%global _with_baseonly 1\n" + spec
    for number, name in (
        (0, "linux-" + fields["tarfile_release"] + ".tar.xz"),
        (300, "kernel-abi-stablelists-" + fields["kabiversion"] + ".tar.xz"),
        (301, "kernel-kabi-dw-" + fields["kabiversion"] + ".tar.xz"),
    ):
        if name not in manifest["lookaside_sha512"]:
            raise ValueError("Fedora kernel archive selection changed")
        pattern = r"^Source" + str(number) + r": ([^\n]+)$"
        matches = re.findall(pattern, spec, re.M)
        if len(matches) != 1:
            raise ValueError("Fedora source declaration changed")
        checksum = manifest["lookaside_sha512"][name]
        url = f"https://src.fedoraproject.org/repo/pkgs/rpms/kernel/{name}/sha512/{checksum}/{name}"
        spec = re.sub(pattern, f"Source{number}: {url}", spec, count=1, flags=re.M)
    return spec


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def _verify_build_sources(directory, identity, *, obs_delivery=False):
    directory = Path(directory)
    if identity.get("schema") != 1:
        raise ValueError("invalid kernel source identity")
    normalized = []
    for name, value in identity["source_files"].items():
        if not FILENAME.fullmatch(name) or set(value) != {"algorithm", "digest", "mode"}:
            raise ValueError("invalid kernel source filename or digest record")
        algorithm = value["algorithm"]
        if algorithm not in ("sha256", "sha512") or not re.fullmatch(
            "[0-9a-f]{" + str(64 if algorithm == "sha256" else 128) + "}", value["digest"]
        ):
            raise ValueError("invalid kernel source digest")
        path = directory / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 512 * 1024**2:
            raise ValueError("nonregular or oversized kernel build input")
        mode = stat.S_IMODE(metadata.st_mode)
        if value["mode"] not in (0o644, 0o755) or (
            mode != value["mode"] and not (obs_delivery and mode == 0o644 and value["mode"] == 0o755)
        ):
            raise ValueError(f"kernel build input mode differs: {name}")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, algorithm).hexdigest() != value["digest"]:
                raise ValueError(f"kernel build input digest differs: {name}")
        if mode != value["mode"]:
            normalized.append(path)
    return normalized


def verify_build_sources(directory, identity):
    """Inspect authenticated inputs without modifying their recorded Git modes."""
    _verify_build_sources(directory, identity)


def prepare_build_sources(directory, identity):
    """Restore OBS's normalized executable delivery modes after all inputs pass."""
    normalized = _verify_build_sources(directory, identity, obs_delivery=True)
    for path in normalized:
        value = identity["source_files"][path.name]
        # Use a private inode: an OBS source-cache hard link must not acquire
        # executable permission through this package's preparation operation.
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".particleve-source-", delete=False) as copy:
            temporary = Path(copy.name)
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as source:
                    metadata = os.fstat(source.fileno())
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or stat.S_IMODE(metadata.st_mode) != 0o644
                        or not 0 <= metadata.st_size <= 512 * 1024**2
                    ):
                        raise ValueError("kernel input changed before mode restoration")
                    remaining = metadata.st_size
                    digest = hashlib.new(value["algorithm"])
                    while remaining:
                        data = source.read(min(remaining, 1024**2))
                        if not data:
                            raise ValueError("truncated kernel input during mode restoration")
                        copy.write(data)
                        digest.update(data)
                        remaining -= len(data)
                    if source.read(1) or digest.hexdigest() != value["digest"]:
                        raise ValueError("kernel input changed during mode restoration")
                current = path.lstat()
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError("kernel input replaced during mode restoration")
                copy.flush()
                os.fchmod(copy.fileno(), value["mode"])
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
    verify_build_sources(directory, identity)
    return len(normalized)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--verify-sources", type=Path)
    operation.add_argument("--prepare-sources", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    identity = json.loads(regular(args.manifest).decode())
    if args.prepare_sources:
        print(json.dumps({"restored_source_modes": prepare_build_sources(args.prepare_sources, identity)}))
    else:
        verify_build_sources(args.verify_sources, identity)
