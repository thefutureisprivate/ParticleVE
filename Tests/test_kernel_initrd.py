"""Reject ambiguous archive paths and stale early-boot authority before publication."""

import hashlib
import json
import stat
import subprocess
import tempfile
import unittest
from compression import zstd
from pathlib import Path
from unittest.mock import patch

from particleve.common import Error
from particleve.kernelinitrd import INDEXES, entries, verify_archive
from particleve.kernelpayload import METADATA, RECORD, kernel_hmac
from particleve.provenance import INITRD_BINARIES, identity_path


def member(name, data=b"", mode=stat.S_IFREG | 0o644, *, uid=0, links=1):
    name = name.encode() + b"\0"
    fields = [1, mode, uid, 0, links, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    prefix = header + name
    return prefix + b"\0" * (-len(prefix) % 4) + data + b"\0" * (-len(data) % 4)


def archive(parts):
    return b"".join(parts) + member("TRAILER!!!", mode=0)


class InitrdArchiveTests(unittest.TestCase):
    def test_selected_compressed_and_raw_archives_preserve_exact_payloads(self):
        first = zstd.compress(archive([member("one", b"compressed payload")]))
        source = first + b"\0" * (-len(first) % 4) + archive([member("two", b"raw payload")])
        actual = [(name, bytes(data)) for name, *_metadata, data in entries(source)]
        self.assertEqual(actual, [("one", b"compressed payload"), ("two", b"raw payload")])

    def test_empty_truncated_unsafe_and_unselected_encodings_fail_closed(self):
        valid = archive([member("one", b"payload")])
        compressed = zstd.compress(valid)
        for name, source in (
            ("empty", b""),
            ("padding-only", b"\0" * 512),
            ("truncated-header", valid[:100]),
            ("truncated-body", valid[:116]),
            ("missing-trailer", valid[:-110]),
            ("compressed-truncation", compressed[:-4]),
            ("compressed-junk", zstd.compress(valid + b"junk")),
            ("crc", valid.replace(b"070701", b"070702", 1)),
            ("gzip", b"\x1f\x8b" + valid),
            ("absolute", archive([member("/etc/owned")])),
            ("parent", archive([member("a/../owned")])),
            ("empty-part", archive([member("a//owned")])),
            ("root-file", archive([member(".", b"replacement")])),
            ("root-link", archive([member(".", b"elsewhere", stat.S_IFLNK | 0o777)])),
            ("unaligned", b"\0" + valid),
        ):
            with self.subTest(case=name), self.assertRaises((Error, zstd.ZstdError)):
                list(entries(source))

    def test_compression_entry_and_archive_counts_have_hard_limits(self):
        source = archive([member("one", b"x" * 4096)])
        with patch("particleve.kernelinitrd.MAX_EXPANDED", 512), self.assertRaisesRegex(Error, "oversized"):
            list(entries(zstd.compress(source)))
        with patch("particleve.kernelinitrd.MAX_ENTRIES", 1), self.assertRaisesRegex(Error, "too many"):
            list(entries(archive([member("one"), member("two")])))
        with patch("particleve.kernelinitrd.MAX_ARCHIVES", 1), self.assertRaisesRegex(Error, "too many"):
            list(entries(archive([]) + archive([])))


class InitrdAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        tree = self.root / "usr/lib/modules/7.3.3-test.x86_64"
        tree.mkdir(parents=True)
        for name in (*METADATA, RECORD, "vmlinuz"):
            (tree / name).write_bytes(b"independently verified root metadata fixture")
            (tree / name).chmod(0o644)
        (tree / ".vmlinuz.hmac").write_text(kernel_hmac(tree / "vmlinuz"))
        (tree / "one.ko").write_bytes(b"module body independently verified in the native fixture")
        (tree / "one.ko").chmod(0o644)
        files = {}
        for name, target in INITRD_BINARIES.items():
            path = self.root / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("compiled " + name).encode())
            path.chmod(0o755)
            files[target] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.record = json.dumps({"component": "initrd", "files": files}).encode()
        path = self.root / identity_path("initrd")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.record)
        self.policy = {"schema": 1, "files": {}}
        self.parts = []
        directories = set()
        for target in [*INITRD_BINARIES.values(), identity_path("initrd")]:
            directories.update(str(parent) for parent in Path(target).parents if str(parent) != ".")
        self.parts.extend(member(name, mode=stat.S_IFDIR | 0o755, links=2) for name in sorted(directories))
        for target in INITRD_BINARIES.values():
            self.parts.append(member(target, (self.root / target).read_bytes(), stat.S_IFREG | 0o755))
        self.parts.append(member(identity_path("initrd"), self.record))

    def reject(self, parts, message):
        path = self.base / "archive"
        path.write_bytes(archive(parts))
        with (
            patch("particleve.kernelinitrd.run") as command,
            patch("particleve.kernelinitrd.verify") as verify,
            self.assertRaisesRegex(Error, message),
        ):
            verify_archive(
                path,
                self.root,
                {},
                self.base / "unused-certificate",
                self.policy,
                self.base / ("output-" + str(len(list(self.base.glob("output-*"))))),
            )
        command.assert_not_called()
        verify.assert_not_called()

    def test_signed_kernel_hmac_reaches_the_initrd_subset_verifier(self):
        kernel = "7.3.3-test.x86_64"
        original = self.root / "usr/lib/modules" / kernel
        prefix = "usr/lib/modules/" + kernel + "/"
        parts = [
            *self.parts,
            member("usr/lib/modules", mode=stat.S_IFDIR | 0o755, links=2),
            member(prefix[:-1], mode=stat.S_IFDIR | 0o755, links=2),
            member(prefix + "one.ko", (original / "one.ko").read_bytes()),
            *(member(prefix + name, b"native subset index") for name in sorted(INDEXES)),
            *(
                member(prefix + name, (original / name).read_bytes())
                for name in METADATA
                if name.startswith("modules.")
            ),
        ]
        path = self.base / "archive"
        path.write_bytes(archive(parts))
        workspace = self.base / "output"

        def index(arguments, *, timeout):
            self.assertEqual(arguments, ["depmod", "--basedir", workspace, "--all", kernel])
            self.assertEqual(timeout, 180)
            for name in INDEXES:
                (workspace / prefix / name).write_bytes(b"native subset index")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        def verify_subset(directory, source, certificate, *, filtered):
            self.assertTrue(filtered)
            tree = directory / kernel
            self.assertEqual((tree / "vmlinuz").read_bytes(), (original / "vmlinuz").read_bytes())
            self.assertEqual((tree / ".vmlinuz.hmac").read_text(), kernel_hmac(tree / "vmlinuz"))
            return {"kernel": kernel}

        with (
            patch("particleve.kernelinitrd.run", side_effect=index),
            patch("particleve.kernelinitrd.verify", side_effect=verify_subset) as verify,
            patch("particleve.kernelinitrd.verify_modules"),
        ):
            result = verify_archive(path, self.root, {}, self.base / "certificate", self.policy, workspace)
        verify.assert_called_once()
        self.assertEqual(result["module_files"], 1)
        self.assertEqual(result["kernel"], kernel)

    def test_duplicate_and_aliased_helper_overwrites_are_rejected_before_native_tools(self):
        target = next(iter(INITRD_BINARIES.values()))
        data = (self.root / target).read_bytes()
        for extra in (
            [member(target, data, stat.S_IFREG | 0o755)],
            [
                member("alias", b"usr/libexec", stat.S_IFLNK | 0o777),
                member("alias/" + Path(target).name, data, stat.S_IFREG | 0o755),
            ],
        ):
            with self.subTest(entries=len(extra)):
                self.reject([*self.parts, *extra], "duplicate initrd security file")

    def test_redirected_parent_foreign_owner_and_changed_helper_fail_closed(self):
        target = next(iter(INITRD_BINARIES.values()))
        for changed, message in (
            (member(target, b"stale helper", stat.S_IFREG | 0o755), "security file differs"),
            (
                member(target, (self.root / target).read_bytes(), stat.S_IFREG | 0o755, uid=1000),
                "foreign-owned",
            ),
            (member(target, (self.root / target).read_bytes(), stat.S_IFREG | 0o755, links=2), "aliased"),
        ):
            parts = list(self.parts)
            parts[-4] = changed
            self.reject(parts, message)
        self.reject([member("usr", b"elsewhere", stat.S_IFLNK | 0o777)], "security directory")

    def test_foreign_kernel_tree_and_module_links_cannot_be_admitted(self):
        self.reject(
            [
                *self.parts,
                member("usr/lib/modules", mode=stat.S_IFDIR | 0o755, links=2),
                member("usr/lib/modules/foreign", mode=stat.S_IFDIR | 0o755, links=2),
            ],
            "different kernel",
        )
        self.reject(
            [
                *self.parts,
                member("usr/lib/modules", mode=stat.S_IFDIR | 0o755, links=2),
                member("usr/lib/modules/7.3.3-test.x86_64", mode=stat.S_IFDIR | 0o755, links=2),
                member("usr/lib/modules/7.3.3-test.x86_64/one.ko", b"/elsewhere", stat.S_IFLNK | 0o777),
            ],
            "unsafe initrd module payload",
        )

    def test_symlink_cycles_cannot_redirect_a_later_file(self):
        self.reject(
            [
                *self.parts,
                member("a", b"b", stat.S_IFLNK | 0o777),
                member("b", b"a", stat.S_IFLNK | 0o777),
                member("a/file", b"x"),
            ],
            "symlink cycle",
        )
