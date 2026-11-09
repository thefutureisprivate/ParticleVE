import copy
import tempfile
import unittest
from pathlib import Path

from particleve.common import Deferred, digest, hash_file, write_json
from particleve.contracts import PERSISTENT_STATE
from particleve.linux import Linux


class CompatibilityContractTests(unittest.TestCase):
    def test_generic_approval_cannot_authorize_an_unimplemented_host_state_migration(self):
        current = {"persistent_state": copy.deepcopy(PERSISTENT_STATE)}
        previous = copy.deepcopy(current)
        previous["persistent_state"]["host_state"] = "particleve-host-state-v2"
        with tempfile.TemporaryDirectory() as directory:
            backend = Linux.__new__(Linux)
            backend.directory = Path(directory)
            evidence = backend.directory / "evidence.json"
            write_json(evidence, {"claimed": "retained safety"})
            write_json(
                backend.directory / "compatibility.json",
                [
                    {
                        "release_sha256": [digest(previous), digest(current)],
                        "retained_os_safe": True,
                        "approved_by": "owner",
                        "evidence": str(evidence),
                        "evidence_sha256": hash_file(evidence),
                    }
                ],
            )
            for first, second in ((previous, current), (current, previous)):
                with self.subTest(first=first), self.assertRaisesRegex(Deferred, "no migration"):
                    backend.compatibility_approved(first, second)

    def test_routine_package_updates_do_not_change_the_retained_state_interface(self):
        old = {
            "persistent_state": copy.deepcopy(PERSISTENT_STATE),
            "packages": [{"name": "kernel-core", "evr": "old"}],
        }
        new = copy.deepcopy(old)
        new["packages"][0]["evr"] = "new"
        backend = Linux.__new__(Linux)
        backend.compatibility_approved(old, new)

    def test_changed_auxiliary_format_or_unit_contract_still_requires_explicit_approval(self):
        for field in (
            "host_state",
            "vm_tpm",
            "vm_efi",
            "btrfs",
            "vm_unit",
            "storage_admission",
            "bootloaders",
        ):
            old = {"persistent_state": copy.deepcopy(PERSISTENT_STATE)}
            new = copy.deepcopy(old)
            new["persistent_state"][field] += "-changed"
            with tempfile.TemporaryDirectory() as directory, self.subTest(field=field):
                backend = Linux.__new__(Linux)
                backend.directory = Path(directory)
                with self.assertRaises(Deferred):
                    backend.compatibility_approved(old, new)
