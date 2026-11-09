"""Explicit, crash-resumable rebinding of operational policy under maintenance."""

import copy
from pathlib import Path

from .common import Error, digest, lock, read_json, require, run, sync_dir, write_json
from .config import validate
from .coordinator import Coordinator

RESOURCE_FIELDS = {"reserve_mib", "reserve_percent", "metadata_max_percent"}


def fixed_settings(config):
    result = copy.deepcopy(config)
    result.pop("maintenance")
    result.pop("minimum_ram_mib")
    result.pop("resources")
    for name in RESOURCE_FIELDS:
        result["storage"].pop(name)
    return result


def invalidate(directory):
    directory = Path(directory)
    (directory / "commissioned.json").unlink(missing_ok=True)
    sync_dir(directory)
    run(["systemctl", "disable", "--now", "systemd-sysupdate-update.timer", "particleve-maintenance.timer"])


def disable_automation(directory):
    with lock(directory):
        invalidate(directory)
    return {"automation_enabled": False}


def binding_status(config_file, directory):
    directory = Path(directory)
    manifest = read_json(directory / "installation.json")
    state = Coordinator(directory, None).load()
    result = {
        "state": state,
        "installation_sha256": digest(manifest),
        "commissioned": (directory / "commissioned.json").exists(),
        "reconfiguration_pending": (directory / "reconfiguration.json").exists(),
    }
    try:
        current = validate(read_json(config_file), publication=True)
        actual = digest(current)
        result["config_binding"] = {
            "valid": actual == manifest["config_sha256"],
            "expected": manifest["config_sha256"],
            "actual": actual,
        }
    except (Error, ValueError, KeyError, TypeError, OSError) as exc:
        result["config_binding"] = {"valid": False, "error": str(exc)}
    return result


def reconfigure(directory, destination, previous=None, proposed=None, *, confirmation=None, resume=False):
    directory, destination = Path(directory), Path(destination).absolute()
    with lock(directory):
        journal = directory / "reconfiguration.json"
        interrupted = read_json(journal) if journal.exists() else None
        if resume:
            require(previous is None and proposed is None, "journal recovery does not accept new inputs")
            require(interrupted is not None, "no interrupted reconfiguration to resume")
            require(
                "previous_config" in interrupted, "reconfiguration journal lacks its previous configuration"
            )
            previous, proposed = interrupted["previous_config"], interrupted["proposed_config"]
        require(
            previous is not None and proposed is not None, "supply the previous and proposed configurations"
        )
        previous, proposed = validate(previous, publication=True), validate(proposed, publication=True)
        require(digest(previous) != digest(proposed), "no operational policy change was proposed")
        require(
            fixed_settings(previous) == fixed_settings(proposed),
            "reconfiguration permits operational policy only; "
            "disk/layout, identity, trust, network and access settings are fixed",
        )
        state = Coordinator(directory, None).load()
        require(
            state["maintenance"] and not state["pending"],
            "persistent maintenance and no pending OS transaction are required",
        )
        require(
            not (directory / "replacement.json").exists(), "finish disk replacement before reconfiguration"
        )
        installed = read_json(directory / "installation.json")
        old = interrupted["previous_manifest"] if interrupted else installed
        require(
            old["config_sha256"] == digest(previous),
            "previous configuration does not match its installation binding",
        )
        new = {**old, "config_sha256": digest(proposed)}
        require(installed in (old, new), "installation changed during reconfiguration")
        require(
            read_json(destination) in (previous, proposed),
            "active configuration differs from the reviewed inputs",
        )
        plan = {
            "schema": 1,
            "configuration_path": str(destination),
            "installation_sha256": digest(old),
            "previous_config_sha256": digest(previous),
            "proposed_config_sha256": digest(proposed),
            "maintenance": proposed["maintenance"],
            "minimum_ram_mib": proposed["minimum_ram_mib"],
            "resources": proposed["resources"],
            "storage_thresholds": {k: proposed["storage"][k] for k in sorted(RESOURCE_FIELDS)},
        }
        transaction = {
            "plan": plan,
            "previous_manifest": old,
            "proposed_manifest": new,
            "previous_config": previous,
            "proposed_config": proposed,
        }
        require(
            not interrupted or interrupted == transaction, "resume the exact reviewed reconfiguration first"
        )
        if confirmation is None:
            return {"plan": plan, "confirmation": digest(plan), "resume": bool(interrupted)}
        require(confirmation == digest(plan), "reconfiguration plan changed")
        write_json(journal, transaction)
        invalidate(directory)
        write_json(destination, proposed)
        write_json(directory / "installation.json", new)
        journal.unlink()
        sync_dir(directory)
        return {
            "action": "reconfigured",
            "installation_sha256": digest(new),
            "automation_enabled": False,
            "next": "validate the policy and recommission; maintenance remains active",
        }
