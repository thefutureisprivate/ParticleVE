"""Distribution CA roots remain authoritative for Python HTTPS tools."""

import os
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from Tools.trust import system_tls_context, system_tls_environment, system_trust_paths


class SystemTrustTests(unittest.TestCase):
    def test_obs_fedora_identity_uses_the_canonical_native_store(self):
        for release in (
            {"ID": "fedora"},
            {"ID": "generic", "ID_LIKE": "fedora"},
            {"ID": "derivative", "ID_LIKE": "rhel fedora"},
        ):
            with (
                self.subTest(release=release),
                patch("platform.freedesktop_os_release", return_value=release),
            ):
                self.assertEqual(
                    system_trust_paths(),
                    {
                        "cafile": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                        "capath": "/etc/pki/tls/certs",
                    },
                )

    def test_other_distribution_families_retain_openssl_native_paths(self):
        paths = SimpleNamespace(openssl_cafile="/native/roots.pem", openssl_capath="/native/certs")
        for release in ({"ID": "other"}, {"ID": "generic", "ID_LIKE": "notfedora"}):
            with (
                self.subTest(release=release),
                patch("platform.freedesktop_os_release", return_value=release),
                patch("ssl.get_default_verify_paths", return_value=paths),
            ):
                self.assertEqual(
                    system_trust_paths(), {"cafile": "/native/roots.pem", "capath": "/native/certs"}
                )

    def test_cargo_source_and_proxy_trust_ignore_alternate_bundle_overrides(self):
        with patch.dict(
            os.environ,
            {
                "CARGO_HTTP_CAINFO": "/nonexistent/source-ca",
                "CARGO_HTTP_PROXY_CAINFO": "/nonexistent/proxy-ca",
            },
        ):
            environment = system_tls_environment()
        self.assertEqual(environment["CARGO_HTTP_CAINFO"], system_trust_paths()["cafile"])
        self.assertEqual(environment["CARGO_HTTP_PROXY_CAINFO"], system_trust_paths()["cafile"])

    def test_distribution_roots_are_loaded_despite_process_overrides(self):
        with patch.dict(
            os.environ, {"SSL_CERT_FILE": "/nonexistent/tool-ca", "SSL_CERT_DIR": "/nonexistent"}
        ):
            context = system_tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(len(context.get_ca_certs()), 0)

    def test_all_python_https_openers_explicitly_use_the_system_context(self):
        from Tools.publication import request

        with (
            patch("urllib.request.HTTPSHandler") as handler,
            patch("urllib.request.build_opener", side_effect=RuntimeError("stop before network")),
            self.assertRaisesRegex(RuntimeError, "stop before network"),
        ):
            request("https://example.org")
        context = handler.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreater(len(context.get_ca_certs()), 0)
