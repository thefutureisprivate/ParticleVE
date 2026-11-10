#!/usr/bin/python3
"""Verify the compiled startup helper against an explicit root-owned descriptor/ACL contract.

Run only in an isolated uid-0 fixture with PVE_RUNTIME_DRIVER naming the reviewed
compiled test driver. This probe never imports a Python runtime implementation.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from particleve.common import canonical, write_json

assert os.geteuid() == os.getegid() == 0, "use an isolated uid-0/gid-0 disposable test container"
os.umask(0o022)
driver = Path(os.environ["PVE_RUNTIME_DRIVER"]).resolve(strict=True)
checks = []


def observed(root, *, approved=False, rejected=None):
    result = subprocess.run(
        [str(driver)],
        input=json.dumps(
            {"operation": "startup-check" if approved else "startup-inventory", "root": str(root)}
        )
        + "\n",
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
    )
    assert not result.stderr, result.stderr
    actual = json.loads(result.stdout)
    if rejected is not None:
        assert set(actual) == {"error"} and rejected in actual["error"], actual
        return None
    assert set(actual) == {"ok"}, actual
    report = actual["ok"]
    assert set(report) == {"schema", "inputs", "sha256"} and report["schema"] == 1, report
    unsigned = {"schema": 1, "inputs": report["inputs"]}
    assert report["sha256"] == hashlib.sha256(canonical(unsigned)).hexdigest(), report
    assert len({row["path"] for row in report["inputs"]}) == len(report["inputs"]), report
    return report


def row(path, kind, mode, **extra):
    return {"path": path, "uid": 0, "gid": 0, "mode": mode, "kind": kind, **extra}


with tempfile.TemporaryDirectory(prefix="particleve-startup-contract-") as temporary:
    root = Path(temporary)
    (root / "etc/particleve").mkdir(parents=True)
    for name in ("bin", "sbin", "lib", "lib64"):
        (root / name).symlink_to("usr/" + name)
    settings = root / "etc/particleve/host.json"
    settings.write_text('{"site":"owned"}\n')
    shadow = root / "etc/shadow"
    shadow.write_text("credential bytes must never enter the inventory")
    shadow.chmod(0)
    token = root / "etc/particleve/report-token"
    token.write_text("first private test token")
    token.chmod(0o400)
    expected = {
        "schema": 1,
        "inputs": [
            row("etc", "directory", 0o755),
            row("etc/particleve", "directory", 0o755),
            row(
                "etc/particleve/host.json",
                "file",
                0o644,
                sha256=hashlib.sha256(settings.read_bytes()).hexdigest(),
            ),
            row("etc/particleve/report-token", "account-or-credential-data", 0o400),
            row("etc/shadow", "account-or-credential-data", 0),
        ],
    }
    expected["sha256"] = hashlib.sha256(canonical(expected)).hexdigest()
    before = observed(root)
    assert before == expected, (before, expected)
    assert "credential bytes" not in json.dumps(before)
    token.chmod(0o600)
    token.write_text("rotated private test token")
    token.chmod(0o400)
    assert observed(root) == before
    checks.append("descriptor inventory bytes, hashes and credential metadata")
    dropin = root / "etc/systemd/system/systemd-vmspawn@guest.service.d/80-approved.conf"
    dropin.parent.mkdir(parents=True)
    dropin.write_text("[Service]\nMemoryMax=1G\n")
    link = root / "etc/systemd/system/machines.target.wants/systemd-vmspawn@guest.service"
    link.parent.mkdir()
    link.symlink_to("/usr/lib/systemd/system/systemd-vmspawn@.service")
    reviewed = observed(root)
    rows = {entry["path"]: entry for entry in reviewed["inputs"]}
    assert rows[dropin.relative_to(root).as_posix()] == row(
        dropin.relative_to(root).as_posix(),
        "file",
        0o644,
        sha256=hashlib.sha256(dropin.read_bytes()).hexdigest(),
    )
    assert rows[link.relative_to(root).as_posix()] == row(
        link.relative_to(root).as_posix(),
        "symlink",
        0o777,
        target="/usr/lib/systemd/system/systemd-vmspawn@.service",
    )
    assert reviewed["sha256"] != before["sha256"]
    receipt = root / "var/lib/particleve/commissioned.json"
    write_json(receipt, {"startup_policy_sha256": reviewed["sha256"]})
    assert observed(root, approved=True) == reviewed
    settings.write_text('{"site":"changed"}\n')
    observed(root, approved=True, rejected="startup configuration changed")
    settings.write_text('{"site":"owned"}\n')
    assert observed(root, approved=True) == reviewed
    receipt.parent.chmod(0o777)
    observed(root, approved=True, rejected="writable by another account")
    receipt.parent.chmod(0o700)
    write_json(receipt, {"old": "commissioning record"})
    unchanged = receipt.read_bytes()
    observed(root, approved=True, rejected="lacks approval")
    assert receipt.read_bytes() == unchanged
    receipt.unlink()
    receipt.symlink_to("/usr/share/factory/etc/os-release")
    observed(root, approved=True, rejected="symbolic links")
    write_json(receipt, {"startup_policy_sha256": reviewed["sha256"]})
    (root / "etc").chmod(0o775)
    observed(root, rejected="writable by another account")
    (root / "etc").chmod(0o755)
    checks.append(
        "commissioned startup policy, missing approval, symlink receipt and writable parent refusal"
    )
    for target in ("/var/lib/machines/code", "../../run/code", "/usr/../var/code"):
        escape = root / "etc/escape"
        escape.symlink_to(target)
        observed(root, rejected="escapes verified usr")
        escape.unlink()
    for name in (
        "etc/pam.d/sshd",
        "etc/ld.so.preload",
        "etc/modprobe.d/execute.conf",
        "etc/polkit-1/rules.d/99-injected.rules",
        "etc/udev/rules.d/99-injected.rules",
        "etc/systemd/system-generators/injected",
        "etc/systemd/system.control/sshd.service.d/50-injected.conf",
        "etc/systemd/system/injected.service",
        "etc/systemd/system/serial-getty@ttyS1.service.d/90-extra.conf",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("injected startup hook")
        observed(
            root,
            rejected="startup hook" if not name.startswith("etc/systemd/system/") else "regular local units",
        )
        path.unlink()
    trusted = root / "etc/trusted-link"
    trusted.symlink_to("/usr/share/factory/etc/profile")
    trusted_row = next(entry for entry in observed(root)["inputs"] if entry["path"] == "etc/trusted-link")
    assert trusted_row == row("etc/trusted-link", "symlink", 0o777, target="/usr/share/factory/etc/profile")
    trusted.unlink()
    for name in (
        "etc/systemd/system/getty.target.d/50-particleve-console.conf",
        "etc/systemd/system/serial-getty@ttyS1.service.d/50-particleve.conf",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# reviewed generated console policy\n")
        assert any(entry["path"] == name and entry["kind"] == "file" for entry in observed(root)["inputs"])
        path.unlink()
    alias = root / "lib64"
    alias.unlink()
    alias.symlink_to("var/lib")
    observed(root, rejected="traditional code path")
    alias.unlink()
    alias.symlink_to("usr/lib64")
    extra = root / "etc/host-setting"
    extra.write_text("owned data")
    duplicate = root / "etc/hardlink"
    os.link(extra, duplicate)
    observed(root, rejected="hard-linked")
    duplicate.unlink()
    extra.chmod(0o755)
    observed(root, rejected="executable")
    extra.unlink()
    os.mkfifo(extra)
    observed(root, rejected="special file")
    extra.unlink()
    checks.append("symlink escape, mutable hooks, hardlink, executable and FIFO refusal")
    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", *entry)
        for entry in (
            (1, 6, 0xFFFFFFFF),
            (2, 4, 1234),
            (4, 4, 0xFFFFFFFF),
            (16, 4, 0xFFFFFFFF),
            (32, 4, 0xFFFFFFFF),
        )
    )
    os.setxattr(settings, "system.posix_acl_access", acl)
    observed(root, rejected="unreviewed ACL")
    os.removexattr(settings, "system.posix_acl_access")
    checks.append("actual named-user POSIX ACL refusal")
    shutil.copyfile("/etc/ld.so.cache", root / "etc/ld.so.cache")
    cached = observed(root)
    cache_row = next(entry for entry in cached["inputs"] if entry["path"] == "etc/ld.so.cache")
    assert cache_row == row("etc/ld.so.cache", "verified-usr-library-cache", 0o644)
    checks.append("native ldconfig cache paths restricted to verified usr aliases")
    for name, target in (
        ("etc/pki/ca-trust/extracted", "/run/particleve-ca-trust/extracted"),
        ("etc/pki/tls/certs", "/run/particleve-ca-trust/extracted/pem/directory-hash"),
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
    anchor = root / "etc/pki/ca-trust/source/anchors/local.pem"
    anchor.parent.mkdir(parents=True)
    anchor.write_text("owner-reviewed public CA input")
    ca_inventory = observed(root)
    write_json(receipt, {"startup_policy_sha256": ca_inventory["sha256"]})
    assert observed(root, approved=True) == ca_inventory
    generated = root / "run/particleve-ca-trust/extracted/pem/tls-ca-bundle.pem"
    generated.parent.mkdir(parents=True)
    generated.write_text("new active image's generated CA view")
    assert observed(root, approved=True) == ca_inventory
    anchor.write_text("changed local CA authority")
    observed(root, approved=True, rejected="startup configuration changed")
    anchor.write_text("owner-reviewed public CA input")
    alias = root / "etc/pki/tls/certs"
    alias.unlink()
    alias.symlink_to("/run/unreviewed-certs")
    observed(root, rejected="escapes verified usr")
    alias.unlink()
    alias.symlink_to("/run/particleve-ca-trust/extracted/pem/directory-hash")
    unexpected = root / "etc/pki/alternate-certs"
    unexpected.symlink_to("/run/particleve-ca-trust/extracted")
    observed(root, rejected="escapes verified usr")
    unexpected.unlink()
    assert observed(root, approved=True) == ca_inventory
    checks.append("only native generated-CA aliases may leave usr; local CA authority remains bound")
print(
    json.dumps(
        {
            "result": "pass",
            "checks": checks,
            "runtime_driver": str(driver),
            "runtime_driver_sha256": hashlib.sha256(driver.read_bytes()).hexdigest(),
        }
    )
)
