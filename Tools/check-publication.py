#!/usr/bin/python3
"""Emit bounded publication health for an existing external monitor; never deploy or promote."""

import argparse
import json
import os
import stat
from datetime import UTC, datetime
from http.client import HTTPException
from pathlib import Path
from xml.etree.ElementTree import ParseError

from particleve.common import Error, lock, read_json, require, write_json
from Tools.publication import collect

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--site", type=Path, default=Path(".obs/site.json"))
parser.add_argument("--grace-seconds", type=int, default=7200)
parser.add_argument(
    "--state-dir", type=Path, required=True, help="private observer state outside the build service"
)
args = parser.parse_args()
try:
    site = read_json(args.site)
    trust = Path(site["trust_directory"])
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = args.state_dir.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
        "publication observer state requires its own private directory",
    )
    with lock(args.state_dir):
        state = args.state_dir / "publication.json"
        if state.exists() or state.is_symlink():
            info = state.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and not info.st_mode & 0o077
                and info.st_nlink == 1
                and info.st_size <= 65536,
                "publication observer state is not a bounded private regular file",
            )
        result = collect(
            site,
            trust / "releases.gpg",
            trust / "secure-boot.crt",
            grace_seconds=args.grace_seconds,
            previous=read_json(state) if state.exists() else None,
        )
        write_json(state, result)
except (Error, OSError, ValueError, KeyError, TypeError, ParseError, HTTPException) as exc:
    result = {
        "schema": 1,
        "observed_at": datetime.now(UTC).isoformat(),
        "result": "unavailable",
        "detail": str(exc)[:512],
    }
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["result"] in ("pass", "pending") else 1)
