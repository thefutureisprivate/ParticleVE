"""Bind separately built RPM payloads to the image's implementation inputs."""

from pathlib import Path

from .common import atomic_write, canonical, digest, hash_file, read_json, require
from .package_sources import COMPONENTS, source_identity
from .package_sources import verify_package as verify_source_package
from .versioning import OBS_RECIPE

TOOLS_MODULES = (
    "__init__",
    "common",
    "config",
    "release",
    "kernels",
    "buildartifacts",
    "layout",
    "contracts",
    "provenance",
    "package_sources",
    "security",
    "processes",
    "landlock",
    "kernelruntime",
    "consoles",
    "versioning",
)
SCRIPTS = {
    "Sources/bin/particleve": "usr/bin/particleve",
    "Sources/bin/particleve-health-sender": "usr/libexec/particleve-health-sender",
    "Sources/bin/particleve-radio-policy": "usr/libexec/particleve-radio-policy",
    "Sources/bin/particleve-witness-write": "usr/libexec/particleve-witness-write",
    "Sources/bin/particleve-storage-admission": "usr/libexec/particleve-storage-admission",
    "Sources/bin/particleve-homed-account": "usr/libexec/particleve-homed-account",
    "Sources/bin/particleve-vm-stop": "usr/libexec/particleve-vm-stop",
    "Sources/bin/particleve-vm-start-guard": "usr/libexec/particleve-vm-start-guard",
    "Sources/bin/particleve-vm-run": "usr/libexec/particleve-vm-run",
    "Sources/bin/particleve-qemu": "usr/libexec/particleve-qemu/qemu",
    "Sources/bin/particleve-swtpm": "usr/libexec/particleve-swtpm/swtpm",
}


def inputs(source):
    source = Path(source)
    files = [
        source / "particleve.version",
        *source.glob("Sources/particleve/*.py"),
        *(source / name for name in SCRIPTS),
        source / "Tools/obs-postoutput",
        source / "Tools/package-identity.py",
        source / OBS_RECIPE,
        source / ".obs/particleve/security-policy.json",
        source / ".obs/particleve/selinux/particleve_vmspawn.te",
        source / ".obs/particleve/selinux/particleve_vmspawn.fc",
        source / ".obs/particleve/selinux/particleve_witness.te",
        source / ".obs/particleve/selinux/particleve_witness.fc",
        *source.glob("mkosi.extra/usr/lib/particleve/trust/*"),
    ]
    # Compiled policy is a payload, not a source input.
    return sorted({p.relative_to(source).as_posix() for p in files if p.suffix != ".pp"})


def implementation_digest(source):
    source = Path(source)
    hashes = {}
    for name in inputs(source):
        path = source / name
        require(path.is_file() and not path.is_symlink(), f"missing implementation input: {name}")
        hashes[name] = hash_file(path)
    return digest(hashes)


def payload(source, component):
    source = Path(source)
    if component == "integration":
        files = {target: name for name, target in SCRIPTS.items()}
        files.update(
            {
                "usr/lib/particleve/particleve/" + p.name: str(p.relative_to(source))
                for p in source.glob("Sources/particleve/*.py")
            }
        )
        files.update(
            {
                "usr/lib/particleve/trust/" + p.name: str(p.relative_to(source))
                for p in source.glob("mkosi.extra/usr/lib/particleve/trust/*")
            }
        )
        files["usr/lib/particleve/particleve_vmspawn.pp"] = None
        files["usr/lib/particleve/particleve_witness.pp"] = None
        files["usr/lib/particleve/security-policy.json"] = ".obs/particleve/security-policy.json"
        return files
    require(component == "build-tools", "unknown implementation package component")
    return {
        **{
            "usr/lib/particleve-build/particleve/" + name + ".py": "Sources/particleve/" + name + ".py"
            for name in TOOLS_MODULES
        },
        "usr/libexec/particleve-obs-postoutput": "Tools/obs-postoutput",
    }


def identity_path(component):
    require(component in ("integration", "build-tools"), "unknown implementation package component")
    directory = "usr/lib/particleve" if component == "integration" else "usr/lib/particleve-build"
    return directory + "/package-identity.json"


def record_package(root, source, component):
    root, source = Path(root), Path(source)
    files = {}
    for target, origin in payload(source, component).items():
        path = root / target
        require(path.is_file() and not path.is_symlink(), f"missing package payload: {target}")
        files[target] = hash_file(path)
        if origin:
            require(
                files[target] == hash_file(source / origin), f"package payload differs from source: {target}"
            )
    record = {
        "schema": 1,
        "component": component,
        "implementation_sha256": implementation_digest(source),
        "files": files,
    }
    atomic_write(root / identity_path(component), canonical(record), 0o644)
    return record


def verify_package(root, component, expected, *, source=None):
    root = Path(root)
    record = read_json(root / identity_path(component))
    require(record.get("schema") == 1 and record.get("component") == component, "invalid package identity")
    require(
        record.get("implementation_sha256") == expected,
        f"{component} RPM does not match the image implementation inputs",
    )
    require(isinstance(record.get("files"), dict) and record["files"], "empty package payload identity")
    if source is not None:
        require(
            set(record["files"]) == set(payload(source, component)), "incomplete package payload identity"
        )
    for name, value in record["files"].items():
        require(name.startswith("usr/") and ".." not in Path(name).parts, "invalid package payload path")
        path = root / name
        require(
            path.is_file() and not path.is_symlink() and hash_file(path) == value,
            f"installed {component} payload does not match its identity: {name}",
        )
    return record


def upstream_inputs(source):
    return {component: source_identity(source, component) for component in COMPONENTS}


def verify_upstream_package(root, component, expected):
    from .common import Error

    try:
        return verify_source_package(root, component, expected)
    except (OSError, ValueError, KeyError) as exc:
        raise Error(f"upstream package verification failed: {exc}") from exc
