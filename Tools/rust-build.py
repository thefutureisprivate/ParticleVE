#!/usr/bin/python3
"""Run Rust checks in an explicit, offline Fedora compiler container.

Only public build inputs are copied into the disposable source mount. In
particular, the repository's acceptance disks, credentials and Git directory
never enter the compiler container.
"""

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="immutable local compiler image ID")
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--podman-root", type=Path, required=True)
    parser.add_argument("--podman-runroot", type=Path, required=True)
    parser.add_argument("command", choices=("check", "build", "test", "clippy", "fmt"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not all(character in "0123456789abcdef" for character in args.image) or len(args.image) != 64:
        parser.error("--image must be a complete immutable image ID")
    source = Path(__file__).resolve().parent.parent
    for directory in (args.cargo_home, args.target):
        directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="particleve-rust-source-") as temporary:
        staging = Path(temporary)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "particleve.version"):
            shutil.copy2(source / name, staging / name)
        for name in ("build.rs",):
            if (source / name).is_file():
                shutil.copy2(source / name, staging / name)
        shutil.copytree(source / "Sources/runtime", staging / "Sources/runtime")
        policy = Path("Sources/particleve/runtime-policy.json")
        (staging / policy).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / policy, staging / policy)
        if (source / "Tests/runtime").exists():
            shutil.copytree(source / "Tests/runtime", staging / "Tests/runtime")
        command = [
            "podman",
            "--root",
            str(args.podman_root),
            "--runroot",
            str(args.podman_runroot),
            "--storage-driver",
            "vfs",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--security-opt=label=disable",
            "--userns=keep-id",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--pids-limit=256",
            "--memory=3g",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m",
            "--volume",
            f"{staging}:/work:ro",
            "--volume",
            f"{args.toolchain.resolve()}:/rust:ro",
            "--volume",
            f"{args.cargo_home.resolve()}:/cargo:rw",
            "--volume",
            f"{args.target.resolve()}:/target:rw",
            "--workdir=/work",
            "--env=PATH=/rust/bin:/usr/bin:/bin",
            "--env=CARGO_HOME=/cargo",
            "--env=CARGO_TARGET_DIR=/target",
            "--env=RUSTC=/rust/bin/rustc",
            "--env=CARGO_BUILD_JOBS=2",
            "--env=CARGO_INCREMENTAL=0",
            "--env=RUSTFLAGS=-Dwarnings -Ctarget-cpu=x86-64-v2 -Cforce-frame-pointers=yes "
            "-Clink-arg=-Wl,-z,relro,-z,now --remap-path-prefix=/work=.",
            "--entrypoint=/rust/bin/cargo",
            args.image,
            args.command,
        ]
        if args.command != "fmt":
            command += [flag for flag in ("--offline", "--locked") if flag not in args.arguments]
        command += args.arguments
        raise SystemExit(subprocess.run(command, check=False).returncode)


if __name__ == "__main__":
    main()
