"""Retain upstream homed/PAM and require homed for non-root interactive accounts."""

import json
from pathlib import Path

from .common import require, run


def homed_record(username):
    require(username and not username.startswith("-") and "\n" not in username, "invalid login name")
    result = run(
        ["userdbctl", "--service=io.systemd.Home", "--with-nss=no", "--output=json", "user", username],
        timeout=15,
    )
    record = json.loads(result.stdout)
    require(
        isinstance(record, dict) and record["userName"] == username, "login account is not managed by homed"
    )
    require(record.get("disposition", "regular") == "regular", "not a regular homed login account")
    return record


def authorize_login(username):
    if username != "root":
        homed_record(username)


def check():
    # NSS enumeration includes homed records. Audit only the classic local database.
    rows = [line.split(":") for line in Path("/etc/passwd").read_text().splitlines() if line]
    require(all(len(row) == 7 for row in rows), "malformed local passwd database")
    shells = {
        line.strip()
        for line in Path("/etc/shells").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    classic = [
        row[0]
        for row in rows
        if row[0] != "root"
        and row[6] not in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false")
        and (1000 <= int(row[2]) < 60000 or row[6] in shells)
    ]
    require(
        not classic,
        "non-root login accounts must be created with homectl, not useradd: " + ", ".join(classic),
    )
    run(["homectl", "list", "--no-pager"], timeout=15)
    return {"non_root_logins": "homed", "ssh_keys": "upstream userdb records", "root_home": "/root"}
