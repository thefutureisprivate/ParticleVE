"""Resolve a published Fedora kernel SRPM to its immutable, verified Git inputs."""

import hashlib
import re
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xmlrpc.client
from pathlib import Path

from particleve.common import require, run
from particleve.kernelbuild import FILENAME, source_manifest, verify_sources
from Tools.kernel_source import source_files
from Tools.trust import system_tls_context

MAX_RPM = 512 * 1024**2
MAX_ARCHIVE = 1024**3
MAX_PADDING = 64 * 1024


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    max_repeats = 2
    max_redirections = 4

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        require(
            target.scheme == "https" and target.username is None and target.password is None,
            "Fedora source redirects require HTTPS without URL credentials",
        )
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=system_tls_context()), HTTPSRedirect()
    )


def chunks(response, maximum, seconds):
    deadline, size = time.monotonic() + seconds, 0
    while True:
        require(time.monotonic() < deadline, "Fedora source transfer exceeded its deadline")
        block = response.read1(min(1024**2, maximum - size + 1))
        if not block:
            return
        size += len(block)
        require(size <= maximum, "oversized Fedora source response")
        yield block


def version(fields, fedora):
    require(isinstance(fedora, str) and re.fullmatch(r"[1-9][0-9]{1,2}", fedora), "invalid Fedora release")
    require(isinstance(fields, dict), "missing Fedora kernel version")
    release, upstream = fields.get("pkgrelease"), fields.get("specrpmversion")
    require(
        isinstance(upstream, str)
        and re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,3}", upstream)
        and isinstance(release, str)
        and re.fullmatch(r"[0-9]{1,8}", release),
        "kernel updates require a stable Fedora version and package revision",
    )
    return upstream + "-" + release + ".fc" + fedora


def resolve(selected, fedora):
    """Koji identifies the commit; a signed SRPM separately verifies its contents."""
    require(
        isinstance(selected, str)
        and re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,3}-[0-9]{1,8}\.fc" + re.escape(fedora), selected),
        "invalid published Fedora kernel coordinate",
    )
    nvr = "kernel-" + selected
    request = urllib.request.Request(
        "https://koji.fedoraproject.org/kojihub",
        data=xmlrpc.client.dumps((nvr,), methodname="getBuild").encode(),
        headers={"Content-Type": "text/xml"},
    )
    with opener().open(request, timeout=60) as response:
        data = b"".join(chunks(response, 128 * 1024, 60))
    require(
        len(data) <= 128 * 1024 and b"<!DOCTYPE" not in data.upper() and b"\0" not in data,
        "oversized or unsafe Koji response",
    )
    values, _ = xmlrpc.client.loads(data.decode("utf-8"))
    require(len(values) == 1 and isinstance(values[0], dict), "missing Koji kernel build")
    build = values[0]
    require(isinstance(build.get("source"), str), "missing Koji source identity")
    source = urllib.parse.urlsplit(build["source"])
    require(
        build.get("nvr") == nvr
        and build.get("name") == "kernel"
        and type(build.get("state")) is int
        and build["state"] == 1
        and source.scheme == "git+https"
        and source.netloc == "src.fedoraproject.org"
        and source.path == "/rpms/kernel.git"
        and not source.query
        and re.fullmatch(r"[0-9a-f]{40}", source.fragment),
        "Koji build is not the completed Fedora kernel from the approved Git repository",
    )
    upstream, release = selected.rsplit("-", 1)
    require(
        build.get("version") == upstream and build.get("release") == release, "Koji build version differs"
    )
    return {"version": build["version"], "release": build["release"], "revision": source.fragment}


def download(build, fedora, directory):
    """Only the release and stable-updates repositories establish publication."""
    filename = "kernel-" + build["version"] + "-" + build["release"] + ".src.rpm"
    require(FILENAME.fullmatch(filename), "unsafe Fedora source RPM filename")
    bases = (
        f"https://dl.fedoraproject.org/pub/fedora/linux/updates/{fedora}/Everything/source/tree/",
        f"https://dl.fedoraproject.org/pub/fedora/linux/releases/{fedora}/Everything/source/tree/",
    )
    path = Path(directory) / filename
    for base in bases:
        try:
            response = opener().open(base + "Packages/k/" + filename, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                error.close()
                continue
            raise
        size = 0
        with response, path.open("xb") as output:
            for block in chunks(response, MAX_RPM, 300):
                size += len(block)
                output.write(block)
        require(size > 0, "empty Fedora source RPM")
        return path
    raise ValueError("requested kernel SRPM is absent from Fedora release and stable updates")


def verify_rpm(package, build, key, directory):
    """Use only the native selected-release key, never the caller's RPM keyring."""
    key = Path(key).resolve(strict=True)
    require(key.is_file() and key.stat().st_size <= 1024**2, "invalid native Fedora RPM key")
    database = Path(directory) / "rpmdb"
    database.mkdir(mode=0o700)
    run(["rpmkeys", "--dbpath", database, "--import", key], timeout=60)
    checked = run(["rpmkeys", "--dbpath", database, "--checksig", "--verbose", package], timeout=60)
    require(
        not checked.stderr.strip()
        and len(checked.stdout) <= 65536
        and re.search(r"(?im)^.*Signature.*: OK\s*$", checked.stdout)
        and not any(word in checked.stdout for word in ("NOKEY", "NOT OK", "UNTRUSTED")),
        "Fedora kernel source RPM lacks a valid signature from the selected release key",
    )
    metadata = run(
        [
            "rpm",
            "--dbpath",
            database,
            "-qp",
            "--queryformat",
            "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{SOURCEPACKAGE}\n",
            package,
        ],
        timeout=60,
    )
    require(
        not metadata.stderr.strip()
        # A source RPM retains the builder's ARCH header. SOURCEPACKAGE is the
        # native tag that distinguishes source packages from signed binaries.
        and metadata.stdout.splitlines() == ["kernel", build["version"], build["release"], "1"],
        "signed Fedora source RPM has another package identity",
    )


def extract(archive, destination):
    """Read only bounded, flat regular SRPM members; never materialize links."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    seen, total = set(), 0
    with Path(archive).open("rb") as stream:
        while True:
            header = stream.read(110)
            require(len(header) == 110 and header[:6] == b"070701", "invalid Fedora source cpio header")
            require(re.fullmatch(rb"[0-9a-fA-F]{104}", header[6:]), "invalid source cpio fields")
            fields = [int(header[n : n + 8], 16) for n in range(6, 110, 8)]
            mode, links, size, namesize = fields[1], fields[4], fields[6], fields[11]
            require(fields[12] == 0, "unexpected source cpio checksum")
            require(1 <= namesize <= 131 and size <= MAX_RPM, "oversized source cpio member")
            raw = stream.read(namesize)
            require(
                len(raw) == namesize and raw[-1:] == b"\0" and b"\0" not in raw[:-1],
                "invalid source filename",
            )
            # Native rpm2cpio prefixes flat members with './'. Normalize only
            # that one prefix; the filename check still forbids every directory.
            name = raw[:-1].decode("ascii").removeprefix("./")
            require(
                len(stream.read(-(110 + namesize) % 4)) == -(110 + namesize) % 4, "short source name padding"
            )
            if name == "TRAILER!!!":
                require(size == 0, "source cpio trailer has contents")
                tail = stream.read(MAX_PADDING + 1)
                require(len(tail) <= MAX_PADDING and not any(tail), "unexpected source cpio tail")
                break
            total += size
            require(
                FILENAME.fullmatch(name)
                and name not in seen
                and len(seen) < 512
                and total <= MAX_ARCHIVE
                and stat.S_ISREG(mode)
                and links == 1,
                "unsafe, duplicate or oversized Fedora source member",
            )
            seen.add(name)
            with (destination / name).open("xb") as output:
                left = size
                while left:
                    data = stream.read(min(left, 1024**2))
                    require(bool(data), "truncated Fedora source member")
                    output.write(data)
                    left -= len(data)
            require(len(stream.read(-size % 4)) == -size % 4, "short source data padding")


def verify_published(build, fedora, tree, directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    package = download(build, fedora, directory)
    key = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{fedora}-primary")
    verify_rpm(package, build, key, directory)
    archive = directory / "source.cpio"
    # rpm2cpio is a native decoder, not a recipe execution. Bound its output and
    # CPU before exec; parsing never creates symlinks, devices or executable files.
    with archive.open("xb") as output:
        result = subprocess.run(
            ["prlimit", f"--fsize={MAX_ARCHIVE}", "--cpu=120", "--", "rpm2cpio", str(package)],
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=180,
            check=True,
        )
    require(not result.stderr.strip(), "native Fedora source extraction produced diagnostics")
    extracted = directory / "sources"
    extract(archive, extracted)
    names = source_files(tree, build["revision"])
    verify_sources(extracted, source_manifest(tree, names))
    with package.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "revision": build["revision"],
        "nvr": "kernel-" + build["version"] + "-" + build["release"],
        "srpm_sha256": checksum,
    }
