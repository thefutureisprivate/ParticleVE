import copy
import hashlib
import json
import unittest
from compression import zstd
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from Tools import kernel_freshness as freshness


def metadata(*versions, arch="src", epoch="0"):
    packages = "".join(
        f"<package><name>kernel</name><arch>{arch}</arch>"
        f'<version epoch="{epoch}" ver="{version}" rel="{release}"/></package>'
        for version, release in versions
    )
    return f'<metadata xmlns="{freshness.COMMON}">{packages}</metadata>'.encode()


def repository(data, *, payload=None, open_size=None):
    payload = zstd.compress(data) if payload is None else payload
    checksum = hashlib.sha256(payload).hexdigest()
    size = len(data) if open_size is None else open_size
    index = (
        f'<repomd xmlns="{freshness.REPO}"><data type="primary">'
        f'<checksum type="sha256">{checksum}</checksum>'
        f'<open-checksum type="sha256">{hashlib.sha256(data).hexdigest()}</open-checksum>'
        f'<location href="repodata/{checksum}-primary.xml.zst"/>'
        f"<size>{len(payload)}</size><open-size>{size}</open-size></data></repomd>"
    ).encode()
    return index, payload


class KernelFreshnessTests(unittest.TestCase):
    def test_repository_checks_both_compressed_and_expanded_metadata(self):
        data = metadata(("7.3.3", "300.fc45"))
        index, payload = repository(data)
        with patch("Tools.kernel_freshness.read", side_effect=(index, payload)):
            self.assertEqual(
                freshness.repository_versions("https://example.invalid/", "45"), ["7.3.3-300.fc45"]
            )
        for name, records in (
            ("changed transport", (index, payload[:-1] + bytes([payload[-1] ^ 1]))),
            (
                "changed expanded digest",
                (index.replace(hashlib.sha256(data).hexdigest().encode(), b"f" * 64), payload),
            ),
            ("expansion exceeds declaration", repository(data, open_size=1)),
            ("concatenated frames", repository(data, payload=payload + payload)),
            ("invalid compression", repository(data, payload=b"not a zstandard frame")),
        ):
            with (
                self.subTest(name=name),
                patch("Tools.kernel_freshness.read", side_effect=records),
                self.assertRaises(Error),
            ):
                freshness.repository_versions("https://example.invalid/", "45")

    def test_primary_metadata_refuses_aliases_duplicates_and_oversized_inputs(self):
        index, _ = repository(metadata(("7.3.3", "300.fc45")))
        self.assertGreater(freshness.primary_record(index)["open-size"], 0)
        for data in (
            index.replace(b"repodata/", b"../"),
            index.replace(b"repodata/", b"https://other.invalid/"),
            index.replace(b"</data>", b"<size>1</size></data>"),
            index.replace(b"</data>", b"</data><data type='primary'/>"),
            index.replace(b"<open-size>", b"<open-size>999999999"),
            index.replace(b'<checksum type="sha256">', b'<checksum type="md5">'),
            b'<!DOCTYPE repomd [<!ENTITY x "content">]>' + index,
            index + b"\0",
        ):
            with self.subTest(data=data[:100]), self.assertRaises(Error):
                freshness.primary_record(data)

    def test_source_version_reader_rejects_foreign_or_ambiguous_package_authority(self):
        self.assertEqual(
            freshness.kernel_versions(metadata(("7.4.0", "300.fc45"), ("7.5.0", "0.rc1.fc45")), "45"),
            ["7.4.0-300.fc45"],
        )
        good = metadata(("7.3.3", "300.fc45"))
        for data in (
            metadata(("7.3.3", "300.fc45"), arch="x86_64"),
            metadata(("7.3.3", "300.fc45"), epoch="1"),
            good.replace(b"</package>", b'<version epoch="0" ver="7.4.0" rel="300.fc45"/></package>'),
            good.replace(b"<package>", b"<wrapper><package>").replace(b"</package>", b"</package></wrapper>"),
            good.replace(b"</metadata>", b""),
            b'<!DOCTYPE metadata [<!ENTITY x "content">]>' + good,
            good + b"\0",
        ):
            with self.subTest(data=data[:100]), self.assertRaises((Error, SyntaxError)):
                freshness.kernel_versions(data, "45")

    def test_release_and_updates_merge_uses_numeric_series_and_package_order(self):
        for repositories, expected in (
            ((["7.9.9-300.fc45"], ["7.10.0-300.fc45"]), "7.10.0-300.fc45"),
            ((["7.4.0-300.fc45"], ["7.4.0-301.fc45"]), "7.4.0-301.fc45"),
            ((["7.4.0-300.fc45"], []), "7.4.0-300.fc45"),
        ):
            with patch("Tools.kernel_freshness.repository_versions", side_effect=repositories):
                self.assertEqual(freshness.latest_fedora("45"), expected)
        with patch("Tools.kernel_freshness.repository_versions", return_value=[]), self.assertRaises(Error):
            freshness.latest_fedora("45")

    def test_advertised_commit_uses_only_the_exact_reviewed_branch_and_url(self):
        pin = {"url": "https://github.com/secureblue/kernel.git", "branch": "live"}
        for output, diagnostics, valid in (
            ("a" * 40 + "\trefs/heads/live\n", "", True),
            ("a" * 40 + "\trefs/heads/other\n", "", False),
            (("a" * 40 + "\trefs/heads/live\n") * 2, "", False),
            ("a" * 40 + "\trefs/heads/live\n", "warning", False),
        ):
            with patch(
                "Tools.kernel_freshness.git",
                side_effect=(
                    SimpleNamespace(stdout=pin["url"]),
                    SimpleNamespace(stdout=output, stderr=diagnostics),
                ),
            ) as git:
                if valid:
                    self.assertEqual(freshness.advertised(pin), "a" * 40)
                    self.assertEqual(git.call_args.kwargs["remote"], pin["url"])
                else:
                    with self.assertRaises(Error):
                        freshness.advertised(pin)
        with (
            patch(
                "Tools.kernel_freshness.git", return_value=SimpleNamespace(stdout="https://other.invalid")
            ) as git,
            self.assertRaises(Error),
        ):
            freshness.advertised(pin)
        self.assertEqual(git.call_count, 1)

    def test_observation_compares_the_selected_immutable_inputs_without_changing_them(self):
        lock = json.loads(Path("sources.lock.json").read_text())
        manifest = json.loads(Path(".obs/kernel/kernel.inputs.json").read_text())
        original = copy.deepcopy((lock, manifest))
        with (
            patch("Tools.kernel_freshness.latest_fedora", return_value="7.4.0-301.fc45"),
            patch("Tools.kernel_freshness.advertised", return_value="b" * 40),
            patch("Tools.kernel_freshness.fedora_kernel.resolve", return_value={"revision": "a" * 40}),
        ):
            observed = freshness.observe(lock, manifest)
        self.assertEqual(observed["fedora-kernel:upstream"]["available"], "7.4.0-301.fc45@" + "a" * 40)
        self.assertEqual(observed["secureblue-kernel:upstream"]["available"], "b" * 40)
        self.assertEqual((lock, manifest), original)
        manifest["upstream"]["fedora_kernel"]["revision"] = "c" * 40
        with patch("Tools.kernel_freshness.latest_fedora") as latest, self.assertRaises(Error):
            freshness.observe(lock, manifest)
        latest.assert_not_called()

    def test_source_reads_require_an_immutable_commit_and_unique_json_keys(self):
        with (
            patch("Tools.kernel_freshness.read", return_value=b'{"schema":1,"schema":2}'),
            self.assertRaisesRegex(Error, "duplicate"),
        ):
            freshness.collect("fixture/ParticleVE", "a" * 40)
        with patch("Tools.kernel_freshness.read") as read, self.assertRaises(Error):
            freshness.collect("fixture/ParticleVE", "main")
        read.assert_not_called()
