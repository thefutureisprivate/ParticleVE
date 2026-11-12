"""Distribution CA roots remain authoritative for Python HTTPS tools."""

import os
import ssl
import unittest
from unittest.mock import patch

from Tools.trust import system_tls_context, system_tls_environment, system_trust_paths


class SystemTrustTests(unittest.TestCase):
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
