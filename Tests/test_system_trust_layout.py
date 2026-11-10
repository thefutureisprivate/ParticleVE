"""The image may not turn package artifacts into installation-local trust."""

import tempfile
import unittest
from pathlib import Path

from particleve.common import Error
from particleve.systemtrust import DIRECTORIES, layout


class SystemTrustLayoutTests(unittest.TestCase):
    def test_packaged_local_anchors_require_an_explicit_design_decision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (*DIRECTORIES, "ca-trust/extracted", "tls/certs"):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / "ca-trust/source/anchors/unknown.pem").write_text("package CA")
            with self.assertRaisesRegex(Error, "installation-local"):
                layout(root)

    def test_native_layout_cannot_redirect_local_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (*DIRECTORIES, "ca-trust/extracted", "tls/certs"):
                (root / name).mkdir(parents=True, exist_ok=True)
            (root / "ca-trust/source/anchors").rmdir()
            (root / "ca-trust/source/anchors").symlink_to(root / "tls")
            with self.assertRaisesRegex(Error, "unexpected native"):
                layout(root)
