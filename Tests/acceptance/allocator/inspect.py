"""Inspect local allocator source/binary RPMs after normal Fedora RPM processing.

Run as an ordinary user in the disposable build environment. This verifies local
evaluation inputs and bytes, not OBS signatures or verified-image delivery.
"""

import argparse
import hashlib
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(*arguments):
    return subprocess.check_output(arguments, text=True, stderr=subprocess.STDOUT, timeout=30)


def extract(rpm, target):
    target.mkdir()
    archive = target / "input.rpm.tar"
    with archive.open("xb") as output:
        subprocess.run(
            ["rpm2archive", "--nocompression", str(rpm.resolve())],
            stdout=output,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
    with tarfile.open(archive) as source:
        require(sum(member.size for member in source.getmembers()) < 16 * 1024**2, "unexpected RPM size")
        source.extractall(target / "files", filter="data")
    return target / "files"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpm", type=Path, required=True)
    parser.add_argument("--source-rpm", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new public inspection record")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    pin = json.loads((here / "source.json").read_text())
    require(not command("rpm", "-qp", "--scripts", str(args.rpm)).strip(), "unexpected RPM scriptlet")
    require(not command("rpm", "-qp", "--triggers", str(args.rpm)).strip(), "unexpected RPM trigger")
    files = command("rpm", "-qpl", str(args.rpm)).splitlines()
    require(files and all(name.startswith("/usr/") for name in files), "payload outside /usr")
    require(
        not any(word in name for name in files for word in ("preload", "sysctl", "systemd")),
        "global policy payload",
    )
    with tempfile.TemporaryDirectory(prefix="particleve-allocator-inspect-") as temporary:
        root = Path(temporary)
        source = extract(args.source_rpm, root / "source")
        for name in ("source.json", "rpm.spec", "chacha-output-pointer.patch", "chacha-boundaries.c"):
            require(
                (source / name).read_bytes() == (here / name).read_bytes(), f"source RPM mismatch: {name}"
            )
        require(
            digest(source / f"hardened_malloc-{pin['version']}.tar.xz") == pin["archive_sha256"],
            "upstream source archive mismatch",
        )
        payload = extract(args.rpm, root / "binary")
        require(
            (payload / "usr/share/hardened_malloc/source.json").read_bytes()
            == (here / "source.json").read_bytes(),
            "installed source pin mismatch",
        )
        libraries = {}
        for name in ("libhardened_malloc.so", "libhardened_malloc-light.so"):
            library = payload / "usr/lib64" / name
            header = command("readelf", "-hW", str(library))
            segments = command("readelf", "-lW", str(library))
            dynamic = command("readelf", "-dW", str(library))
            notes = command("readelf", "-nW", str(library))
            require(
                "DYN (Shared object file)" in header and "Advanced Micro Devices X86-64" in header,
                "unexpected ELF target",
            )
            require("GNU_RELRO" in segments and "BIND_NOW" in dynamic, "missing RELRO/NOW")
            stack = next(line for line in segments.splitlines() if "GNU_STACK" in line)
            require(" RW " in stack and " RWE " not in stack, "executable ELF stack")
            require(
                not any(tag in dynamic for tag in ("(TEXTREL)", "(RPATH)", "(RUNPATH)")),
                "unexpected dynamic loading policy",
            )
            require("x86-64-v3" not in notes and "x86-64-v4" not in notes, "ELF exceeds CPU baseline")
            libraries[name] = {
                "sha256": digest(library),
                "bytes": library.stat().st_size,
                "header": header,
                "segments": segments,
                "dynamic": dynamic,
                "notes": notes,
            }
    record = {
        "scope": __doc__,
        "rpm_sha256": digest(args.rpm),
        "source_rpm_sha256": digest(args.source_rpm),
        "rpm_digest_check": command("rpm", "--checksig", "--nosignature", str(args.rpm)),
        "source_rpm_digest_check": command("rpm", "--checksig", "--nosignature", str(args.source_rpm)),
        "metadata": command("rpm", "-qp", "--qf", "%{NEVRA}\n%{LICENSE}\n", str(args.rpm)),
        "files": files,
        "libraries": libraries,
        "source": pin,
        "recipe_sha256": digest(here / "rpm.spec"),
        "global_policy_files": False,
    }
    with args.output.open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")
    print(json.dumps({"status": "pass", "rpm_sha256": record["rpm_sha256"], "libraries": list(libraries)}))


if __name__ == "__main__":
    main()
