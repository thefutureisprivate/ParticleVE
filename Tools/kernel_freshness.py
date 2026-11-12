"""Observe kernel upstreams independently of the updater, without selecting sources."""

import hashlib
import io
import json
import re
import xmlrpc.client
from compression import zstd
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from xml.etree import ElementTree

from particleve.common import Error, require
from Tools import fedora_kernel
from Tools.kernel_source import pins
from Tools.sourcegit import git

REPO = "http://linux.duke.edu/metadata/repo"
COMMON = "http://linux.duke.edu/metadata/common"
MAX_PRIMARY = 64 * 1024**2
MAX_OPEN = 256 * 1024**2
UPSTREAMS = {"fedora-kernel:upstream", "secureblue-kernel:upstream"}


def read(url, maximum):
    with fedora_kernel.opener().open(url, timeout=15) as response:
        require(response.status == 200, "upstream observation requires HTTP 200")
        return b"".join(fedora_kernel.chunks(response, maximum, 45))


def xml(data):
    require(b"\0" not in data and b"<!DOCTYPE" not in data.upper(), "unsafe repository XML")
    return ElementTree.fromstring(data)


def primary_record(data):
    require(0 < len(data) <= 128 * 1024, "oversized Fedora metadata index")
    records = xml(data).findall(f"{{{REPO}}}data[@type='primary']")
    require(len(records) == 1, "missing or duplicate Fedora primary metadata")
    record = {}
    for name in ("checksum", "open-checksum", "size", "open-size", "location"):
        nodes = records[0].findall(f"{{{REPO}}}{name}")
        require(len(nodes) == 1, "missing or duplicate Fedora metadata field")
        node = nodes[0]
        if name.endswith("checksum"):
            require(
                node.get("type") == "sha256" and re.fullmatch(r"[0-9a-f]{64}", node.text or ""),
                "unsupported Fedora metadata checksum",
            )
            record[name] = node.text
        elif name in ("size", "open-size"):
            value = node.text or ""
            maximum = MAX_PRIMARY if name == "size" else MAX_OPEN
            require(re.fullmatch(r"[0-9]{1,10}", value), "invalid Fedora metadata size")
            require(0 < int(value) <= maximum, "oversized Fedora metadata")
            record[name] = int(value)
        else:
            record[name] = node.get("href")
    require(
        record["location"] == "repodata/" + record["checksum"] + "-primary.xml.zst",
        "unexpected Fedora primary metadata location",
    )
    return record


def kernel_versions(data, fedora):
    """Stream flat package records; ignore non-stable versions as Renovate does."""
    require(
        0 < len(data) <= MAX_OPEN and b"\0" not in data and b"<!DOCTYPE" not in data.upper(),
        "oversized or unsafe Fedora primary XML",
    )
    parser = ElementTree.iterparse(io.BytesIO(data), events=("start", "end"))
    depth, count, root, found = 0, 0, None, []
    for event, node in parser:
        if event == "start":
            depth += 1
            require(depth <= 16, "excessive Fedora metadata nesting")
            if root is None:
                root = node
                require(node.tag == f"{{{COMMON}}}metadata", "unexpected Fedora metadata root")
            continue
        if node.tag == f"{{{COMMON}}}package":
            require(depth == 2, "nested Fedora package record")
            count += 1
            require(count <= 100000, "too many Fedora package records")
            if node.findtext(f"{{{COMMON}}}name") == "kernel":
                fields = node.findall(f"{{{COMMON}}}version")
                require(
                    len(fields) == 1
                    and node.findtext(f"{{{COMMON}}}arch") == "src"
                    and fields[0].get("epoch") == "0",
                    "unexpected Fedora kernel package metadata",
                )
                upstream, release = fields[0].get("ver", ""), fields[0].get("rel", "")
                if re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,3}", upstream) and re.fullmatch(
                    r"[0-9]{1,8}\.fc" + re.escape(fedora), release
                ):
                    found.append(upstream + "-" + release)
                    require(len(found) <= 32, "too many published Fedora kernel versions")
            node.clear()
            root.clear()
        depth -= 1
    require(root is not None and depth == 0, "incomplete Fedora metadata")
    return found


def repository_versions(base, fedora):
    record = primary_record(read(base + "repodata/repomd.xml", 128 * 1024))
    compressed = read(base + record["location"], record["size"])
    require(
        len(compressed) == record["size"] and hashlib.sha256(compressed).hexdigest() == record["checksum"],
        "Fedora primary metadata checksum or size differs",
    )
    decoder = zstd.ZstdDecompressor(options={zstd.DecompressionParameter.window_log_max: 27})
    try:
        data = decoder.decompress(compressed, max_length=record["open-size"] + 1)
    except zstd.ZstdError as exc:
        raise Error("invalid compressed Fedora metadata") from exc
    require(
        decoder.eof
        and not decoder.unused_data
        and len(data) == record["open-size"]
        and hashlib.sha256(data).hexdigest() == record["open-checksum"],
        "Fedora expanded metadata checksum, size or framing differs",
    )
    return kernel_versions(data, fedora)


def latest_fedora(fedora):
    fedora_kernel.version({"specrpmversion": "1.0", "pkgrelease": "1"}, fedora)
    bases = (
        f"https://dl.fedoraproject.org/pub/fedora/linux/releases/{fedora}/Everything/source/tree/",
        f"https://dl.fedoraproject.org/pub/fedora/linux/updates/{fedora}/Everything/source/tree/",
    )
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda base: repository_versions(base, fedora), bases))
    versions = [value for result in results for value in result]
    require(versions, "Fedora repositories contain no supported stable kernel")

    def key(value):
        upstream, release = value.split("-")
        # Only epoch-zero numeric stable versions and package counters are
        # accepted above, so this ordering matches the restricted RPM contract.
        return tuple(map(int, upstream.split("."))), int(release.split(".")[0])

    return max(versions, key=key)


def advertised(pin):
    url, branch = pin["url"], "refs/heads/" + pin["branch"]
    require(git(Path.cwd(), "ls-remote", "--get-url", url).stdout.strip() == url, "source URL rewrite")
    result = git(Path.cwd(), "ls-remote", "--refs", url, branch, remote=url)
    require(
        not result.stderr.strip()
        and re.fullmatch(r"[0-9a-f]{40}\t" + re.escape(branch) + r"\n?", result.stdout),
        "missing or ambiguous upstream branch identity",
    )
    return result.stdout.split()[0]


def observe(lock, manifest):
    require(
        isinstance(lock, dict) and lock.get("fedora") == "45" and isinstance(manifest, dict),
        "kernel observation requires the supported source policy",
    )
    selected_pins = pins(lock)
    require(
        manifest.get("schema") == 1 and manifest.get("upstream") == selected_pins,
        "selected kernel manifest differs from the observed source lock",
    )
    selected = fedora_kernel.version(manifest["fedora_version"], lock["fedora"])
    with ThreadPoolExecutor(max_workers=2) as workers:
        fedora = workers.submit(latest_fedora, lock["fedora"])
        secureblue = workers.submit(advertised, lock["sources"]["secureblue_kernel"])
        latest, tip = fedora.result(), secureblue.result()
    try:
        published = fedora_kernel.resolve(latest, lock["fedora"])
    except xmlrpc.client.Error as exc:
        raise Error("Koji kernel source observation is unavailable") from exc
    return {
        "fedora-kernel:upstream": {
            "selected": selected + "@" + lock["sources"]["fedora_kernel"]["revision"],
            "available": latest + "@" + published["revision"],
        },
        "secureblue-kernel:upstream": {
            "selected": lock["sources"]["secureblue_kernel"]["revision"],
            "available": tip,
        },
    }


def collect(repository, commit):
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        and re.fullmatch(r"[0-9a-f]{40}", commit),
        "invalid observed repository source identity",
    )
    base = f"https://raw.githubusercontent.com/{repository}/{commit}/"
    with ThreadPoolExecutor(max_workers=2) as workers:
        lock = workers.submit(read, base + "sources.lock.json", 65536)
        manifest = workers.submit(read, base + ".obs/kernel/kernel.inputs.json", 1024**2)

        def unique(pairs):
            result = {}
            for name, value in pairs:
                require(name not in result, "duplicate observed source JSON key")
                result[name] = value
            return result

        return observe(
            json.loads(lock.result(), object_pairs_hook=unique),
            json.loads(manifest.result(), object_pairs_hook=unique),
        )
