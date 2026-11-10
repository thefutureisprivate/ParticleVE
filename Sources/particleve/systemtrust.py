"""Build the native Fedora trust layout without persisting generated CA views."""

import re
import shutil
import tempfile
from pathlib import Path

from .common import require, run

DIRECTORIES = (
    "",
    "ca-trust",
    "ca-trust/source",
    "ca-trust/source/anchors",
    "ca-trust/source/blocklist",
    "tls",
)
OUTPUTS = {
    "ca-trust/extracted": "/run/particleve-ca-trust/extracted",
    "tls/certs": "/run/particleve-ca-trust/extracted/pem/directory-hash",
}


def layout(pki):
    """Keep package defaults in verified /usr and only local trust inputs in /etc."""
    pki = Path(pki)
    lines = ["# Generated from the selected Fedora PKI package layout; do not edit."]
    for name in DIRECTORIES:
        path = pki / name
        require(path.is_dir() and not path.is_symlink(), "unexpected native PKI directory: " + name)
        lines.append(f"d /etc/pki{'/' + name if name else ''} 0755 root root -")
        if name in ("ca-trust/source/anchors", "ca-trust/source/blocklist"):
            require(not list(path.iterdir()), "image packages must not supply installation-local CA inputs")
            continue
        for child in sorted(path.iterdir()):
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", child.name), "unsupported PKI package filename")
            relative = child.relative_to(pki).as_posix()
            if relative in DIRECTORIES or relative in OUTPUTS:
                continue
            require(child.is_symlink() or child.is_file() or child.is_dir(), "special file in package PKI")
            lines.append(f"L /etc/pki/{relative} - - - - /usr/share/factory/etc/pki/{relative}")
    for name, target in OUTPUTS.items():
        require((pki / name).is_dir(), "missing native generated CA view: " + name)
        lines.append(f"L /etc/pki/{name} - - - - {target}")
    return "\n".join(lines) + "\n"


def write_layout(root):
    root = Path(root)
    (root / "usr/lib/tmpfiles.d/particleve-ca-trust.conf").write_text(layout(root / "etc/pki"))


def check_layout(root):
    root = Path(root)
    require(
        (root / "usr/lib/tmpfiles.d/particleve-ca-trust.conf").read_text()
        == layout(root / "usr/share/factory/etc/pki"),
        "system CA layout differs from the active image's native PKI inputs",
    )
    require(
        not any(
            line.split()[1:2] == ["/etc/pki"]
            for line in (root / "usr/lib/tmpfiles.d/etc.conf").read_text().splitlines()
            if line and not line.startswith("#")
        ),
        "generic factory link shadows the writable local CA inputs",
    )
    # Exercise all image tmpfiles inputs together: another package's rule must
    # not shadow this layout when a fresh writable root is materialized.
    with tempfile.TemporaryDirectory(prefix="particleve-ca-layout-") as temporary:
        probe = Path(temporary)
        shutil.copytree(root / "usr/lib/tmpfiles.d", probe / "usr/lib/tmpfiles.d", symlinks=True)
        shutil.copytree(
            root / "usr/share/factory/etc/pki", probe / "usr/share/factory/etc/pki", symlinks=True
        )
        run(["systemd-tmpfiles", f"--root={probe}", "--create", "--prefix=/etc/pki"])
        for name in DIRECTORIES:
            path = probe / "etc/pki" / name
            require(path.is_dir() and not path.is_symlink(), "local CA source directory was shadowed")
            require(path.stat().st_mode & 0o022 == 0, "local CA source permits unprivileged writes")
        for name, target in OUTPUTS.items():
            require((probe / "etc/pki" / name).readlink() == Path(target), "wrong shared CA view alias")
