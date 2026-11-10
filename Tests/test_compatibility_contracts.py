import copy
import tempfile
from pathlib import Path

from particleve.common import digest, hash_file, write_json
from particleve.contracts import PERSISTENT_STATE
from Tests.runtime import RustDriverTests


class CompatibilityContractTests(RustDriverTests):
    def test_generic_approval_cannot_authorize_an_unimplemented_host_state_migration(self):
        current = {"persistent_state": copy.deepcopy(PERSISTENT_STATE)}
        previous = copy.deepcopy(current)
        previous["persistent_state"]["host_state"] = "particleve-host-state-v2"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            write_json(evidence, {"claimed": "retained safety"})
            write_json(
                root / "compatibility.json",
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
                with self.subTest(first=first):
                    self.assertIn(
                        "no migration",
                        self.request(
                            "compatibility-approved", directory=directory, first=first, second=second
                        )["error"],
                    )

    def test_routine_package_updates_do_not_change_the_retained_state_interface(self):
        old = {
            "persistent_state": copy.deepcopy(PERSISTENT_STATE),
            "packages": [{"name": "kernel-core", "evr": "old"}],
        }
        new = copy.deepcopy(old)
        new["packages"][0]["evr"] = "new"
        with tempfile.TemporaryDirectory() as directory:
            self.evaluate("compatibility-approved", directory=directory, first=old, second=new)

    def test_changed_auxiliary_format_or_unit_contract_still_requires_explicit_approval(self):
        for field in (
            "host_state",
            "boot_console",
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
                self.assertIn(
                    "error",
                    self.request("compatibility-approved", directory=directory, first=old, second=new),
                )
