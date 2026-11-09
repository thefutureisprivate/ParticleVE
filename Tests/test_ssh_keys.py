"""Exercise OpenSSH's public-key parser without a token or private credential."""

import base64
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from particleve import config
from particleve.common import Error
from Tests.fixtures import host

# Public test vectors only: RFC 8032 test 1 and the SEC 2 P-256 generator.
ED25519 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
P256 = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


def string(value):
    return len(value).to_bytes(4, "big") + value


def public(kind, *fields):
    blob = b"".join(string(part) for part in (kind.encode(), *fields))
    return kind + " " + base64.b64encode(blob).decode()


ED = public("ssh-ed25519", ED25519)
SK_ED = public("sk-ssh-ed25519@openssh.com", ED25519, b"ssh:particleve-test")
SK_EC = public("sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", P256, b"ssh:particleve-test")


class SSHKeyTests(unittest.TestCase):
    def test_native_parser_accepts_both_fido2_types_and_owner_recovery(self):
        for key in (ED, SK_ED, SK_EC):
            with self.subTest(kind=key.split()[0]):
                self.assertTrue(config.ssh_key(key))
                self.assertTrue(config.ssh_key(key + " owner primary"))
                candidate = host()
                candidate["admin_ssh_keys"] = [ED, key]
                config.validate(candidate)

    def test_native_parser_rejects_malformed_complete_key_formats(self):
        for key in (ED, SK_ED, SK_EC):
            kind, body = key.split()
            blob = base64.b64decode(body)
            for broken in (blob[:-1], blob + b"\x00", b"\xff\xff\xff\xff" + blob[4:]):
                with self.subTest(kind=kind, blob=broken.hex()):
                    self.assertFalse(config.ssh_key(kind + " " + base64.b64encode(broken).decode()))
        for key in (
            public("ssh-ed25519", ED25519[:-1]),
            public("sk-ssh-ed25519@openssh.com", ED25519),
            public("sk-ssh-ed25519@openssh.com", ED25519[:-1], b"ssh:"),
            public("sk-ecdsa-sha2-nistp256@openssh.com", b"nistp384", P256, b"ssh:"),
            public("sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", b"\x04" + b"\x00" * 64, b"ssh:"),
            "ssh-ed25519 " + SK_ED.split()[1],
        ):
            with self.subTest(key=key):
                self.assertFalse(config.ssh_key(key))

    def test_options_controls_multiline_and_unsupported_types_never_reach_openssh(self):
        for value in (
            None,
            1,
            "",
            " ssh-ed25519 AAAA",
            "ssh-rsa AAAA",
            "sk-ssh-ed25519-cert-v01@openssh.com AAAA",
            "verify-required " + SK_ED,
            "no-touch-required " + SK_ED,
            'command="id" ' + ED,
            ED + "\n" + SK_ED,
            ED + "\rcomment",
            ED + "\x00comment",
            ED + "\x1b[31mcomment",
            ED + "\tcomment",
            ED + "\ud800",
            ED + " " + "x" * 8192,
        ):
            with self.subTest(value=value), patch.object(config, "run") as parser:
                self.assertFalse(config.ssh_key(value))
                parser.assert_not_called()

    def test_parser_uses_only_the_public_blob_and_fails_closed_on_diagnostics(self):
        for returncode, stderr in ((1, ""), (0, "unexpected warning\n"), (1, "invalid key")):
            with (
                self.subTest(returncode=returncode, stderr=stderr),
                patch.object(
                    config, "run", return_value=SimpleNamespace(returncode=returncode, stderr=stderr)
                ) as parser,
            ):
                self.assertFalse(config.ssh_key(SK_ED + " private comment is never forwarded"))
                self.assertEqual(parser.call_args.kwargs["input"], SK_ED + "\n")
                self.assertEqual(parser.call_args.kwargs["timeout"], 2)
        with patch.object(config, "run", side_effect=Error("helper unavailable")), self.assertRaises(Error):
            config.ssh_key(SK_ED)

    def test_owner_key_collection_is_bounded(self):
        for keys in (None, [], ED, {"key": ED}, [ED] * 17):
            candidate = host()
            candidate["admin_ssh_keys"] = keys
            with self.subTest(keys=keys), self.assertRaises(Error):
                config.validate(candidate)


if __name__ == "__main__":
    unittest.main()
