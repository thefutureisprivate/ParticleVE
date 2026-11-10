"""Prepare pinned allocator evaluation sources with system TLS and signed-tag verification."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from Tools.sourcegit import environment, fetch, git


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new public source directory for RPM/OBS")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    pin = json.loads((here / "source.json").read_text())
    require(
        pin["schema"] == 1 and pin["version"].isdigit() and len(pin["version"]) == 10,
        "invalid allocator source pin",
    )
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="particleve-allocator-fetch-") as temporary:
        source = Path(temporary)
        subprocess.run(
            ["/usr/bin/git", "init", "--quiet", str(source)], check=True, env=environment(), timeout=15
        )
        fetch(source, pin["url"], "refs/tags/" + pin["version"])
        require(
            git(source, "rev-parse", "FETCH_HEAD").stdout.strip() == pin["tag_object"],
            "release tag object mismatch",
        )
        require(
            git(source, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip() == pin["revision"],
            "release commit mismatch",
        )
        verification = git(
            source,
            "-c",
            "gpg.ssh.allowedSignersFile=" + str(here / "source.allowed_signers"),
            "verify-tag",
            pin["tag_object"],
        )
        require(
            pin["signer"] in verification.stderr and pin["signer_fingerprint"] in verification.stderr,
            "unexpected release signer",
        )
        require(
            int(git(source, "show", "-s", "--format=%ct", pin["revision"]).stdout) == pin["source_epoch"],
            "source epoch mismatch",
        )
        archive = output / f"hardened_malloc-{pin['version']}.tar.xz"
        # Ignore workstation Git attributes/config and xz option overrides.
        env = environment() | {"XZ_DEFAULTS": "", "XZ_OPT": ""}
        with (
            archive.open("xb") as destination,
            subprocess.Popen(
                [
                    "/usr/bin/git",
                    "-C",
                    str(source),
                    "archive",
                    "--format=tar",
                    f"--prefix=hardened_malloc-{pin['version']}/",
                    pin["revision"],
                ],
                env=env,
                stdout=subprocess.PIPE,
            ) as producer,
        ):
            try:
                subprocess.run(
                    ["xz", "--threads=1", "--check=crc64", "-6", "-c"],
                    stdin=producer.stdout,
                    stdout=destination,
                    env=env,
                    check=True,
                    timeout=30,
                )
            finally:
                producer.stdout.close()
            require(producer.wait(timeout=15) == 0, "source archive command failed")
        require(
            hashlib.sha256(archive.read_bytes()).hexdigest() == pin["archive_sha256"],
            "source archive digest mismatch",
        )
        (output / "verified-tag.txt").write_text(git(source, "cat-file", "-p", pin["tag_object"]).stdout)
    for name in (
        "source.json",
        "source.allowed_signers",
        "rpm.spec",
        "chacha-output-pointer.patch",
        "chacha-boundaries.c",
    ):
        shutil.copy2(here / name, output / name)
    print(
        json.dumps(
            {
                "version": pin["version"],
                "revision": pin["revision"],
                "source_tag_verified": True,
                "archive_sha256": pin["archive_sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
