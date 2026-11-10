#!/usr/bin/python3
"""Probe actual Landlock confinement in one disposable, unprivileged-policy child.

This is an explicit native probe, not an automatic unittest: the selected host
kernel must expose Landlock ABI 5 or newer. Only caller-owned temporary files
are used, and the parent retains its ordinary policy for cleanup.
"""

import argparse
import errno
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runtime-driver", type=Path, required=True)
args = parser.parse_args()
if os.geteuid() == 0:
    parser.error("run this probe as an unprivileged user")
driver = args.runtime_driver.resolve(strict=True)
with tempfile.TemporaryDirectory(prefix="particleve-landlock-probe-") as temporary:
    directory = Path(temporary).resolve()
    directory.chmod(0o700)
    inherited_path = directory / "inherited"
    inherited_path.write_bytes(b"public inherited fixture")
    with inherited_path.open("rb") as inherited:
        response = subprocess.run(
            [str(driver)],
            input=json.dumps(
                {
                    "operation": "landlock-handoff-probe",
                    "directory": str(directory),
                    "inherited_fd": inherited.fileno(),
                }
            )
            + "\n",
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
            pass_fds=(inherited.fileno(),),
        )
        assert not response.stderr, response.stderr
        result = json.loads(response.stdout)
        assert set(result) == {"ok"}, result
        report = result["ok"]
        assert report["landlock_abi"] >= 5, report
        assert report["descriptor_closed"] and report["read_permitted"] and report["retained_contents"], (
            report
        )
        assert report["denied"] == dict.fromkeys(
            ("write_open", "create", "rename", "unlink", "mkdir"), errno.EACCES
        ), report
        # The child closed only its inherited copy; the parent still owns this FD.
        assert os.fstat(inherited.fileno()).st_size == len(b"public inherited fixture")
    assert not (directory / "new-file").exists() and not (directory / "new-directory").exists()
    print(
        json.dumps(
            {
                "result": "pass",
                "probe": report,
                "runtime_driver": str(driver),
                "runtime_driver_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
            },
            sort_keys=True,
        )
    )
