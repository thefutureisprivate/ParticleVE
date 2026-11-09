#!/usr/bin/python3
"""Export a USBGuard evaluation bundle inside a disposable Fedora container.

First install usbguard and python3 with DNF package signature checking enabled.
This script installs nothing, starts no daemon and never accesses USB devices.
The bundle's installed-file checks are not independent attestation of its builder.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def command(*args):
    return subprocess.check_output(args, text=True).strip()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if not (Path("/run/.containerenv").exists() or Path("/.dockerenv").exists()):
    raise RuntimeError("export only inside the disposable build container")
output = args.output.absolute()
if output.exists() or output.is_symlink():
    raise RuntimeError("refusing to replace an existing bundle")
binaries = [Path("/usr/sbin/usbguard-daemon"), Path("/usr/bin/usbguard")]
for path in binaries:
    if not path.is_file():
        raise RuntimeError("missing Fedora runtime: " + str(path))
ldd = command("ldd", *map(str, binaries))
libraries = {Path(name) for name in re.findall(r"/[^ ()\n]+\.so[^ ()\n]*", ldd)}
if not any(path.name == "ld-linux-x86-64.so.2" for path in libraries):
    raise RuntimeError("the x86-64 runtime loader was not resolved")
files = {path: str(path).lstrip("/") for path in binaries}
files.update({path: "lib64/" + path.name for path in libraries})
for name in ("/usr/lib/systemd/system/usbguard.service", "/etc/usbguard/usbguard-daemon.conf"):
    files[Path(name)] = name.lstrip("/")
payload = {}
packages = set()
for path, member in sorted(files.items()):
    resolved = path.resolve(strict=True)
    package = command("rpm", "-qf", "--qf", "%{NEVRA}", str(resolved))
    metadata = command(
        "rpm", "-qf", "--qf", "%{FILEDIGESTALGO}\n[%{FILENAMES}|%{FILEDIGESTS}\n]", str(resolved)
    ).splitlines()
    if metadata[0] != "8":
        raise RuntimeError("review the package's file-digest algorithm before export")
    # Fedora RPM headers can name the same merged-/usr file through /lib64.
    # Match the resolved payload, excluding the empty digest of a symlink.
    expected = {
        digest
        for name, digest in (line.split("|", 1) for line in metadata[1:])
        if digest and Path(name).resolve() == resolved
    }
    data = resolved.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected != {digest}:
        raise RuntimeError("file differs from installed RPM metadata: " + str(resolved))
    payload[member] = {
        "data": data,
        "mode": resolved.stat().st_mode & 0o777,
        "source": str(path),
        "sha256": digest,
        "rpm": package,
    }
    packages.add(package)
output.mkdir(parents=True, mode=0o755)
identity = {}
for member, item in payload.items():
    path = output / member
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(item["data"])
    path.chmod(item["mode"])
    identity[member] = {key: value for key, value in item.items() if key not in ("data", "mode")}
package_headers = command(
    "rpm", "-q", "--qf", "%{NEVRA}|%{SOURCERPM}|%{RSAHEADER:pgpsig}\n", *sorted(packages)
)
(output / "identity.json").write_text(
    json.dumps({"files": identity, "packages": package_headers.splitlines()}, indent=2) + "\n"
)
print(
    json.dumps(
        {
            "files": len(identity),
            "bytes": sum(len(item["data"]) for item in payload.values()),
            "packages": sorted(packages),
        },
        sort_keys=True,
    )
)
