"""Canonical PVE source versions and OBS build identities."""

import argparse
import re
from pathlib import Path

NUMBER = r"(?:0|[1-9][0-9]{0,5})"
SOURCE_VERSION = re.compile(rf"({NUMBER})\.({NUMBER})\.({NUMBER})\.({NUMBER})\Z")
OBS_COUNTERS = re.compile(rf"({NUMBER})\.({NUMBER})\Z")
VERSION = re.compile(rf"({NUMBER})\.({NUMBER})\.({NUMBER})\.({NUMBER})-({NUMBER})\.({NUMBER})\Z")
OBS_RECIPE = Path(".obs/particleve/particleve.spec")


def image_version():
    """Read the running image identity for externally executed Python probes."""
    values = dict(
        line.split("=", 1) for line in Path("/usr/lib/os-release").read_text().splitlines() if "=" in line
    )
    if values.get("IMAGE_ID", "").strip('"') != "ParticleVE":
        raise ValueError("this is not a ParticleVE OS")
    version = values["IMAGE_VERSION"].strip('"')
    if not VERSION.fullmatch(version):
        raise ValueError("invalid running image version")
    return version


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


def verify_obs_sources(directory, source, *, rpm=False):
    """Keep the Git-managed OBS recipe consistent with the full source archive.

    Explicitly prepared local sources have no SCM-bridge identity to compare.
    The bridge commit covers only its packaging subdirectory, so compare the
    recipe itself: a racing source version must not borrow an older counter.
    """
    if not (directory / "_scmsync.obsinfo").exists():
        return

    def recipe(path):
        with path.open("rb") as file:
            data = file.read(65537)
        if len(data) > 65536:
            raise ValueError("OBS recipe is too large")
        return data

    native = recipe(directory / OBS_RECIPE.name)
    if rpm:
        # OBS substitutes dependencies and the native Release before rpmbuild.
        # Version still owns the check-in counter. The image worker receives the
        # unmodified recipe and must additionally compare every original byte.
        versions = re.findall(r"^Version:[ \t]+(\S+)[ \t]*$", native.decode(), re.M)
        if len(versions) != 1:
            raise ValueError("native RPM recipe must declare exactly one PVE version")
        source_key(versions[0])
        if versions[0] != read_version(source):
            raise ValueError("native RPM recipe differs from the PVE source version")
        return
    if native != recipe(source / OBS_RECIPE):
        raise ValueError("OBS recipe differs from the PVE source archive")


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
    verify_obs_sources(options.directory.parent, options.directory)
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
