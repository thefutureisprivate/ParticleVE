import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from particleve.commission import requirements_digest
from particleve.common import Error, digest, write_json
from particleve.linux import Linux


class CommissioningRequirementsTests(unittest.TestCase):
    def test_old_or_changed_approval_cannot_bypass_new_acceptance_requirements(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = Linux.__new__(Linux)
            backend.directory = Path(directory)
            backend.manifest = {"installation": "test"}
            backend.config = {"policy": "test"}
            backend.reporting_policy = Mock(return_value="reporting")
            backend.startup_policy = Mock(return_value="startup")
            record = {
                "installation_sha256": digest(backend.manifest),
                "config_sha256": digest(backend.config),
                "reporting_policy_sha256": "reporting",
                "startup_policy_sha256": "startup",
            }
            path = backend.directory / "commissioned.json"
            for value in (None, "0" * 64):
                candidate = dict(record)
                if value is not None:
                    candidate["acceptance_requirements_sha256"] = value
                write_json(path, candidate)
                before = path.read_bytes()
                with self.subTest(value=value), self.assertRaisesRegex(Error, "acceptance requirements"):
                    backend.check_commissioned()
                self.assertEqual(path.read_bytes(), before)
            backend.reporting_policy.assert_not_called()
            backend.startup_policy.assert_not_called()
            write_json(path, {**record, "acceptance_requirements_sha256": requirements_digest()})
            backend.check_commissioned()
            backend.reporting_policy.assert_called_once()
            backend.startup_policy.assert_called_once()
