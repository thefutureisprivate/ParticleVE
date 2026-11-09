import contextlib
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve import bootloaders
from particleve.bootloaders import FIXED, GLOBAL, Loaders, loader_path
from particleve.common import Error, hash_file, read_json, write_json
from particleve.linux import Linux
from Tests.fixtures import release


class LoaderTrialTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.esps = {role: self.root / role for role in ("a", "b")}
        self.backend = Linux.__new__(Linux)
        self.backend.directory = self.root / "state"
        self.backend.cache = self.root / "cache"
        self.backend.esp = lambda role: contextlib.nullcontext(self.esps[role])
        self.esp_uuids = {r: str(uuid.uuid4()) for r in ("a", "b")}
        self.backend.disk = lambda role: {
            "path": str(self.esps[role]),
            "partitions": [{"role": "esp", "uuid": self.esp_uuids[role]}],
        }
        self.backend.current_esp_role = lambda: "a"
        self.backend.boot_id = lambda: "old-boot"
        self.releases = {}
        for version in ("45.0.1.1-1.1", "45.0.1.2-1.1"):
            item = release(version)
            directory = self.backend.cache / version
            directory.mkdir(parents=True)
            for kind, artifact in item["artifacts"].items():
                path = directory / artifact["file"]
                path.write_bytes(f"{kind}-{version}".encode())
                artifact["sha256"] = hash_file(path)
                artifact["size"] = path.stat().st_size
            self.releases[version] = item
        self.loaders = Loaders(self.backend)
        self.loaders.seed(self.releases["45.0.1.1-1.1"])
        state = self.loaders.load()
        state["good"] = state["seed"]
        write_json(self.loaders.path, state)
        self.variables = self.root / "efivars"
        self.variables.mkdir()
        self.enterContext(patch.object(bootloaders, "VARIABLES", self.variables))

    def hashes(self):
        return {(role, name): hash_file(esp / name) for role, esp in self.esps.items() for name in FIXED}

    def queue(self):
        self.backend.expose_boot("a", self.releases["45.0.1.2-1.1"])
        self.backend.expose_boot("b", self.releases["45.0.1.2-1.1"])
        sha = self.releases["45.0.1.2-1.1"]["artifacts"]["bootloader"]["sha256"]
        with patch.object(
            bootloaders,
            "run",
            return_value=SimpleNamespace(stdout=f"Boot00AF* ParticleVE trial {sha}\tHD(...)"),
        ) as command:
            self.loaders.queue(self.releases["45.0.1.2-1.1"])
        self.assertIn("--create-only", command.call_args_list[0].args[0])
        self.assertEqual(command.call_args_list[1].args[0], ["efibootmgr", "--bootnext", "00AF"])
        return sha

    def boot(self, path, entry=0xAF):
        self.backend.boot_id = lambda: "new-boot"
        (self.variables / f"BootCurrent-{GLOBAL}").write_bytes(b"\x07\0\0\0" + entry.to_bytes(2, "little"))
        self.enterContext(patch.object(bootloaders, "executed_path", return_value=path))

    def test_candidate_preparation_preserves_every_known_working_loader(self):
        before = self.hashes()
        self.backend.expose_boot("a", self.releases["45.0.1.2-1.1"])
        self.backend.expose_boot("b", self.releases["45.0.1.2-1.1"])
        self.assertEqual(self.hashes(), before)
        for esp in self.esps.values():
            self.loaders.prove(esp)
            self.assertTrue(
                (
                    esp / loader_path(self.releases["45.0.1.2-1.1"]["artifacts"]["bootloader"]["sha256"])
                ).is_file()
            )

    def test_broken_loader_fallback_cannot_be_promoted_by_healthy_os(self):
        before = self.hashes()
        sha = self.queue()
        # Firmware tried a signed-but-broken candidate, then ran the old fixed
        # loader. Even if it selects the new OS, that does not validate the PE.
        self.boot(FIXED[0], entry=1)
        with patch.object(bootloaders, "run"):
            result = self.loaders.bless()
        self.assertEqual(result["loader"], "quarantined")
        self.assertEqual(self.hashes(), before)
        self.assertIn(sha, read_json(self.loaders.path)["rejected"])
        with patch.object(bootloaders, "run") as commands:
            self.loaders.queue(self.releases["45.0.1.2-1.1"])
        commands.assert_not_called()

    def test_actual_candidate_execution_and_health_blessing_permit_promotion(self):
        sha = self.queue()
        self.boot(loader_path(sha))
        with patch.object(bootloaders, "run"):
            result = self.loaders.bless()
        self.assertEqual(result["loader"], "validated")
        self.assertEqual(set(self.hashes().values()), {sha})
        self.assertIsNone(self.loaders.load()["trial"])
        self.assertEqual(hash_file(self.loaders.directory / f"{sha}.efi"), sha)

    def test_promotion_interruption_preserves_reachable_validated_loader_and_resumes(self):
        sha = self.queue()
        self.boot(loader_path(sha))
        original = bootloaders.atomic_write
        for boundary in range(1, 5):
            with self.subTest(boundary=boundary):
                old = self.releases["45.0.1.1-1.1"]["artifacts"]["bootloader"]["sha256"]
                for esp in self.esps.values():
                    for name in FIXED:
                        original(esp / name, (self.loaders.directory / f"{old}.efi").read_bytes())
                state = self.loaders.load()
                state["good"] = old
                state["trial"] = {"sha256": sha, "entry": "00AF", "role": "a", "boot_id": "old-boot"}
                write_json(self.loaders.path, state)
                count = 0

                def interrupted(path, data, *args, boundary=boundary):
                    nonlocal count
                    if Path(path).as_posix().endswith(FIXED):
                        count += 1
                        if count == boundary:
                            raise OSError("power loss")
                    return original(path, data, *args)

                with (
                    patch.object(bootloaders, "atomic_write", side_effect=interrupted),
                    self.assertRaises(OSError),
                ):
                    self.loaders.bless()
                self.assertTrue(all(h in {old, sha} for h in self.hashes().values()))
                self.assertIn(old, self.hashes().values())
                with patch.object(bootloaders, "run"):
                    self.loaders.bless()
                self.assertEqual(set(self.hashes().values()), {sha})

    def test_reboot_confirmation_failure_clears_only_the_owned_trial(self):
        from particleve.common import Error

        backend = self.backend
        backend.current_version = lambda: "45.0.1.1-1.1"
        backend.local_release = lambda version: self.releases[version]
        with (
            patch(
                "particleve.linux.tempfile.TemporaryDirectory", return_value=contextlib.nullcontext(self.root)
            ),
            patch("particleve.linux.transfers", return_value={}),
            patch("particleve.linux.Loaders") as loaders,
            patch(
                "particleve.linux.run",
                side_effect=[
                    SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=0),
                    Error("job query failed"),
                ],
            ),
            self.assertRaisesRegex(Error, "job query failed"),
        ):
            backend.conditional_reboot("45.0.1.2-1.1")
        loaders.return_value.queue.assert_called_once_with(self.releases["45.0.1.2-1.1"])
        loaders.return_value.cancel.assert_called_once_with()

    def test_foreign_bootnext_is_never_cleared(self):
        self.queue()
        (self.variables / f"BootNext-{GLOBAL}").write_bytes(b"\x07\0\0\0\x12\0")
        with patch.object(bootloaders, "run") as command, self.assertRaisesRegex(Error, "foreign BootNext"):
            self.loaders.cancel()
        command.assert_not_called()

    def test_modified_candidate_or_wrong_executed_path_never_promotes(self):
        sha = self.queue()
        self.boot(loader_path(sha))
        (self.esps["a"] / loader_path(sha)).write_bytes(b"modified")
        before = self.hashes()
        with self.assertRaisesRegex(Error, "recorded hash"):
            self.loaders.bless()
        self.assertEqual(self.hashes(), before)
