import io
import stat
import tempfile
import unittest
import xmlrpc.client
from pathlib import Path
from unittest.mock import patch

from particleve.common import Error
from Tools import fedora_kernel


def member(name, data=b"", *, mode=stat.S_IFREG | 0o644, links=1):
    encoded = name.encode() + b"\0"
    fields = (1, mode, 0, 0, links, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    return header + encoded + bytes(-(len(header) + len(encoded)) % 4) + data + bytes(-len(data) % 4)


def archive(*members):
    return b"".join(members) + member("TRAILER!!!", mode=0)


class FedoraKernelTests(unittest.TestCase):
    def build(self):
        return {
            "name": "kernel",
            "version": "7.3.3",
            "release": "300.fc45",
            "nvr": "kernel-7.3.3-300.fc45",
            "state": 1,
            "source": "git+https://src.fedoraproject.org/rpms/kernel.git#" + "a" * 40,
        }

    def resolve(self, value):
        data = xmlrpc.client.dumps((value,), methodresponse=True, allow_none=True).encode()
        with patch("Tools.fedora_kernel.opener") as factory:
            factory.return_value.open.return_value = io.BytesIO(data)
            return fedora_kernel.resolve("7.3.3-300.fc45", "45")

    def test_completed_build_requires_exact_package_and_source_authority(self):
        self.assertEqual(
            self.resolve(self.build()), {"version": "7.3.3", "release": "300.fc45", "revision": "a" * 40}
        )
        for key, value in (
            ("name", "another"),
            ("version", "7.3.4"),
            ("release", "300.fc46"),
            ("nvr", "kernel-7.3.4-300.fc45"),
            ("state", 0),
            ("state", True),
            ("source", "git+http://src.fedoraproject.org/rpms/kernel.git#" + "a" * 40),
            ("source", "git+https://unrelated.invalid/rpms/kernel.git#" + "a" * 40),
            ("source", "git+https://src.fedoraproject.org/rpms/kernel.git#f45"),
            ("source", None),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(Error):
                self.resolve(self.build() | {key: value})

    def test_only_stable_selected_fedora_coordinates_are_requests(self):
        self.assertEqual(
            fedora_kernel.version({"specrpmversion": "7.4.0", "pkgrelease": "301"}, "45"), "7.4.0-301.fc45"
        )
        for value in (
            {},
            {"specrpmversion": "7.4-rc1", "pkgrelease": "300"},
            {"specrpmversion": "7.4", "pkgrelease": "../300"},
        ):
            with self.subTest(value=value), self.assertRaises(Error):
                fedora_kernel.version(value, "45")
        for release in ("../45", "045", 45, ""):
            with self.subTest(release=release), self.assertRaises(Error):
                fedora_kernel.version({"specrpmversion": "7.4", "pkgrelease": "300"}, release)

    def test_transport_is_bounded_and_cannot_redirect_to_cleartext_or_credentials(self):
        self.assertEqual(b"".join(fedora_kernel.chunks(io.BytesIO(b"abc"), 3, 1)), b"abc")
        with self.assertRaisesRegex(Error, "oversized"):
            b"".join(fedora_kernel.chunks(io.BytesIO(b"abc"), 2, 1))
        with (
            patch("Tools.fedora_kernel.time.monotonic", side_effect=(0, 2)),
            self.assertRaisesRegex(Error, "deadline"),
        ):
            b"".join(fedora_kernel.chunks(io.BytesIO(b"abc"), 3, 1))
        for target in (
            "http://mirror.example.invalid/source.rpm",
            "https://user:secret@mirror.example.invalid/source.rpm",
        ):
            with self.subTest(target=target), self.assertRaises(Error):
                fedora_kernel.HTTPSRedirect().redirect_request(None, None, 302, "", {}, target)

    def test_source_cpio_only_materializes_bounded_flat_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.cpio"
            source.write_bytes(
                archive(member("./kernel.spec", b"reviewed source", mode=stat.S_IFREG | 0o755))
            )
            fedora_kernel.extract(source, root / "valid")
            self.assertEqual((root / "valid/kernel.spec").read_bytes(), b"reviewed source")
            self.assertFalse((root / "valid/kernel.spec").stat().st_mode & 0o111)
            source.write_bytes(archive(member("padded", b"source")) + bytes(10240))
            fedora_kernel.extract(source, root / "native-padding")
            (root / "outside").write_bytes(b"preserved")
            cases = (
                archive(member("../outside", b"changed")),
                archive(member(str(root / "outside"), b"changed")),
                archive(member("parent/file", b"changed")),
                archive(member("link", b"../outside", mode=stat.S_IFLNK | 0o777)),
                archive(member("hardlink", links=2)),
                archive(member("same"), member("./same")),
                archive(member("device", mode=stat.S_IFCHR | 0o600)),
                archive(member("file", b"contents"))[:-5],
                archive(member("file")) + b"unexpected",
                archive(member("file")) + bytes(fedora_kernel.MAX_PADDING + 1),
                b"070701" + b"x" * 104,
            )
            for number, data in enumerate(cases):
                source.write_bytes(data)
                with self.subTest(number=number), self.assertRaises((Error, UnicodeError)):
                    fedora_kernel.extract(source, root / f"invalid{number}")
                self.assertEqual((root / "outside").read_bytes(), b"preserved")

    def test_unsigned_rpm_digest_success_is_not_a_package_signature(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "public-key"
            key.write_text("public test key")
            success = SimpleNamespace(stdout="package: digests OK\n", stderr="")
            with (
                patch("Tools.fedora_kernel.run", return_value=success),
                self.assertRaisesRegex(Error, "signature"),
            ):
                fedora_kernel.verify_rpm(root / "unsigned.rpm", self.build(), key, root)


if __name__ == "__main__":
    unittest.main()
