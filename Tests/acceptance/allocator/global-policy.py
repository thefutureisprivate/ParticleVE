"""Check native preload-link labeling without changing an installed host's link.

Run as root in an explicitly selected disposable SELinux-enforcing QEMU VM.
The reviewed contract driver is staged under /run, never installed as a host API.
This probes the real Rust initrd preparation path on temporary roots. It does
not establish first-boot ordering, authentication, workload I/O or performance.
"""

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-uuid", required=True)
    parser.add_argument("--runtime-driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "run as root in the selected disposable VM")
    require("QEMU" in Path("/sys/class/dmi/id/sys_vendor").read_text(), "use a QEMU fixture")
    require(
        Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == args.fixture_uuid.lower(),
        "fixture UUID differs",
    )
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "SELinux must enforce")
    driver = args.runtime_driver.resolve(strict=True)
    metadata = driver.stat()
    require(
        driver.is_relative_to("/run")
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0
        and os.access(driver, os.X_OK),
        "stage the owned compiled driver under /run",
    )
    with driver.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "use the native compiled contract driver")
    require(not args.output.exists(), "preserve earlier evidence; choose a new output")

    def invoke(root):
        result = subprocess.run(
            [str(driver)],
            input=json.dumps({"operation": "allocator-native-prepare-root", "root": str(root)}) + "\n",
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        require(not result.stderr and len(result.stdout) < 65536, "unexpected driver diagnostics")
        return json.loads(result.stdout)

    def context(path):
        return os.getxattr(path, "security.selinux", follow_symlinks=False).removesuffix(b"\0")

    target = Path("/usr/lib/particleve/ld.so.preload")
    library = Path("/usr/lib64/libhardened_malloc.so")
    before = {str(path): digest(path) for path in (target, library)}
    host_link = Path("/etc/ld.so.preload")
    host_before = (host_link.lstat().st_ino, host_link.readlink(), context(host_link))
    checks = []
    with tempfile.TemporaryDirectory(prefix="particleve-preload-label-", dir="/run") as temporary:
        root = Path(temporary)
        directory = root / "etc"
        directory.mkdir(mode=0o755)
        link = directory / "ld.so.preload"
        require(invoke(root) == {"ok": None}, "native preparation failed")
        require(link.is_symlink() and link.readlink() == target, "unexpected preload link")
        require(context(link) == b"system_u:object_r:etc_t:s0", "new link lacks Fedora's label")
        checks.append("new owned link labeled before preparation completes")
        inode = link.lstat().st_ino
        require(invoke(root) == {"ok": None}, "idempotent preparation failed")
        require(link.lstat().st_ino == inode, "existing link was replaced")
        require(context(link) == b"system_u:object_r:etc_t:s0", "existing link lost its label")
        checks.append("existing owned link retained and labeled")
        link.unlink()
        link.write_bytes(b"owner configuration\n")
        inode, label = link.lstat().st_ino, context(link)
        require("error" in invoke(root), "conflicting regular file was accepted")
        require(
            link.read_bytes() == b"owner configuration\n"
            and link.lstat().st_ino == inode
            and context(link) == label,
            "conflicting owner file was changed",
        )
        checks.append("conflicting owner file and label preserved")
        link.unlink()
        link.symlink_to("/var/lib/owner-preload")
        inode, label = link.lstat().st_ino, context(link)
        require("error" in invoke(root), "conflicting symlink was accepted")
        require(
            link.readlink() == Path("/var/lib/owner-preload")
            and link.lstat().st_ino == inode
            and context(link) == label,
            "conflicting owner symlink was changed",
        )
        checks.append("conflicting owner symlink and label preserved")
        # Cover the read-only boot-health check without changing the real /etc.
        # The child alone sees this temporary etc in its private mount namespace.
        link.unlink()
        link.symlink_to(target)
        bad_context = context(link)
        require(bad_context != b"system_u:object_r:etc_t:s0", "negative fixture is already labeled")
        code = (
            "import json,subprocess,sys;"
            "subprocess.run(['mount','--no-mtab','--bind',sys.argv[1],'/etc'],"
            "check=True,timeout=10);"
            "r=subprocess.run([sys.argv[2]],input=json.dumps({'operation':'allocator-host-policy'})"
            "+'\\n',capture_output=True,text=True,check=True,timeout=15);"
            "assert not r.stderr and len(r.stdout)<65536;print(r.stdout,end='')"
        )
        result = subprocess.run(
            [
                "unshare",
                "--mount",
                "--propagation=private",
                "--",
                "python3",
                "-c",
                code,
                str(directory),
                str(driver),
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        require(not result.stderr and len(result.stdout) < 65536, "unexpected namespace diagnostics")
        rejection = json.loads(result.stdout)
        require(
            "unexpected SELinux label" in rejection.get("error", ""),
            "boot health accepted the incorrectly labeled preload link",
        )
        require(context(link) == bad_context, "read-only boot health relabeled the link")
        checks.append("boot health rejects an incorrectly labeled link without repair")
    require(before == {str(path): digest(path) for path in (target, library)}, "verified targets changed")
    require(
        host_before == (host_link.lstat().st_ino, host_link.readlink(), context(host_link)),
        "installed preload link changed",
    )
    record = {
        "result": "pass",
        "fixture_uuid": args.fixture_uuid,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "image": platform.freedesktop_os_release()["IMAGE_VERSION"],
        "kernel": platform.release(),
        "driver_sha256": digest(driver),
        "checks": checks,
        "SELinux": "Enforcing",
        "verified_target_hashes_unchanged": before,
        "installed_preload_link_unchanged": True,
        "scope": __doc__,
    }
    with args.output.open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
