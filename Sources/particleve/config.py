"""Validate shared version, count and URL inputs for image/publication tooling."""

import re
from urllib.parse import urlsplit

from .common import require
from .versioning import VERSION

VERITY_SIGNATURE_SIZE = 1024 * 1024


def version_key(value):
    match = VERSION.fullmatch(value)
    require(
        match and int(match[1]) > 0, "version must use FEDORA.PVE_MAJOR.PVE_MINOR.PVE_PATCH-CHECKIN.BUILD"
    )
    # PVE_ plus the version must fit a native GPT label (36 UTF-16 code units).
    require(len(value) <= 32, "version exceeds the native GPT label limit")
    return tuple(map(int, match.groups()))


def integer(value, minimum, label):
    require(type(value) is int and value >= minimum, f"{label} must be an integer >= {minimum}")
    return value


def https_url(value):
    parsed = urlsplit(value)
    require(
        parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password,
        "feed must be an HTTPS URL without credentials",
    )
    require(not parsed.query and not parsed.fragment and not re.search(r"[\s%\\]", value), "invalid feed URL")
    require(not parsed.hostname.endswith((".invalid", ".example")), "configure the real ParticleVE feed")
    return value.rstrip("/")
