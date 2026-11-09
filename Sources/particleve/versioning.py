"""Canonical PVE source versions and OBS build identities."""

import argparse
import re
from pathlib import Path

NUMBER = r"(?:0|[1-9][0-9]{0,5})"
SOURCE_VERSION = re.compile(rf"({NUMBER})\.({NUMBER})\.({NUMBER})\.({NUMBER})\Z")
OBS_COUNTERS = re.compile(rf"({NUMBER})\.({NUMBER})\Z")
VERSION = re.compile(rf"({NUMBER})\.({NUMBER})\.({NUMBER})\.({NUMBER})-({NUMBER})\.({NUMBER})\Z")


def source_key(value):
    match = SOURCE_VERSION.fullmatch(value)
    if not match or int(match[1]) == 0:
        raise ValueError("source version must be FEDORA_MAJOR.PVE_MAJOR.PVE_MINOR.PVE_PATCH")
    return tuple(map(int, match.groups()))


def read_version(root):
    path = Path(root) / "particleve.version"
    if path.stat().st_size > 64:
        raise ValueError("source version file is too large")
    value = path.read_text().strip()
    source_key(value)
    return value


def bump(value, part, *, owner_approved=False, fedora=None):
    fields = list(source_key(value))
    if part == "major" and not owner_approved:
        raise ValueError("PVE major changes require the owner's explicit approval")
    if part == "fedora":
        if type(fedora) is not int or fedora <= fields[0]:
            raise ValueError("select a newer Fedora major")
        fields = [fedora, fields[1], 0, 0]
    elif part in ("major", "minor", "patch"):
        index = {"major": 1, "minor": 2, "patch": 3}[part]
        fields[index] += 1
        fields[index + 1 :] = [0] * (3 - index)
    else:
        raise ValueError("unknown version component")
    result = ".".join(map(str, fields))
    source_key(result)
    return result


def mkosi_args(arguments):
    """Compose the full identity before upstream mkosi parses configuration.

    OBS supplies the two counters on every signing round. The source marker
    travels with continuation sources so all rounds retain the same identity.
    """
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--directory", "-C", type=Path, default=Path.cwd())
    parser.add_argument("--image-version")
    options, _ = parser.parse_known_args(arguments)
    if not (options.directory / "particleve.version").exists() or options.image_version is None:
        return list(arguments)
    source = read_version(options.directory)
    value = options.image_version
    if OBS_COUNTERS.fullmatch(value):
        value = source + "-" + value
    elif not VERSION.fullmatch(value) or value.rsplit("-", 1)[0] != source:
        raise ValueError("mkosi image version differs from its PVE source version")
    result = list(arguments)
    for index, argument in enumerate(result):
        if argument.startswith("--image-version="):
            result[index] = "--image-version=" + value
        elif argument == "--image-version":
            result[index + 1] = value
    return result
