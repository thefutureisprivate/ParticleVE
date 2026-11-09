#!/usr/bin/python3
"""Run in the existing external receiver against its own last-receipt file."""

import argparse
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from particleve.common import Error, read_json, require
from Tools.heartbeat import freshness

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--receipt", required=True)
parser.add_argument("--installation-uuid", required=True)
parser.add_argument("--maximum-age-seconds", type=int, default=900)
args = parser.parse_args()
try:
    info = Path(args.receipt).lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and not info.st_mode & 0o022
        and info.st_nlink == 1
        and info.st_size <= 128 * 1024,
        "receiver receipt must be a bounded regular file controlled by the receiver user",
    )
    result = freshness(
        read_json(args.receipt),
        args.installation_uuid,
        now=datetime.now(UTC),
        maximum_age_seconds=args.maximum_age_seconds,
    )
except (Error, OSError, ValueError, TypeError, KeyError) as exc:
    result = {"fresh": False, "detail": str(exc)[:256]}
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["fresh"] else 1)
