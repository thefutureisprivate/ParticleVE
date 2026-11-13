"""Recovery console selection must survive preparation, fallback and profile validation."""

import base64
import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from particleve.common import Error
from particleve.consoles import SERIAL_CONSOLES, uki_profiles
from particleve.release import inspect_uki
from Tests.fixtures import release
from Tests.runtime import RustDriverTests


class ConsoleTests(RustDriverTests):
    def test_only_agreed_signed_choices_are_accepted(self):
        self.assertIsNone(self.evaluate("consoles-profile", config={}))
        self.assertEqual(
            self.evaluate("consoles-profile", config={"console": "console=ttyS0"}), "serial0-115200"
        )
        self.assertEqual(
            self.evaluate("consoles-profile", config={"console": "console=ttyS3,9600n8"}), "serial3-9600"
        )
        for value in (
            "console=ttyS4",
            "console=ttyS0,12345n8",
            "console=ttyS00",
            "console=ttyS0 audit=0",
            None,
        ):
            with self.subTest(value=value):
                self.assertIn("error", self.request("consoles-profile", config={"console": value}))

    def test_runtime_rejects_late_getty_without_the_selected_early_console(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            active = root / "class/tty/console/active"
            active.parent.mkdir(parents=True)
            active.write_text("tty0 ttyS0\n")
            cmdline = root / "cmdline"
            cmdline.write_text("audit=1 console=tty0 console=ttyS0,115200n8\n")
            config = {"console": "console=ttyS0"}
            self.assertEqual(
                self.evaluate("consoles-baseline", config=config, proc=str(root), sys=str(root))["profile"],
                "serial0-115200",
            )
            for arguments, consoles in (
                ("console=tty0", "tty0 ttyS0"),
                ("console=tty0 console=ttyS0,9600n8", "tty0 ttyS0"),
                ("console=tty0 console=ttyS0,115200n8", "tty0"),
                ("console=tty0 console=ttyS0,115200n8", "tty0 ttyS0 ttyS1"),
            ):
                cmdline.write_text(arguments)
                active.write_text(consoles)
                with self.subTest(arguments=arguments, consoles=consoles):
                    self.assertIn(
                        "error",
                        self.request("consoles-baseline", config=config, proc=str(root), sys=str(root)),
                    )

    def test_boot_defaults_select_same_signed_console_for_candidate_and_retained_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            esp = Path(temporary)
            (esp / "loader").mkdir()
            for version, match in (("45.0.2.0-1.1", "45.0.2.0-1.1"), (None, "*")):
                self.evaluate(
                    "linux-default",
                    esp=str(esp),
                    version=version,
                    config={"console": "console=ttyS2,38400n8"},
                )
                text = (esp / "loader/loader.conf").read_text()
                self.assertIn(f"default ParticleVE_{match}_x86-64*.efi@serial2-38400\n", text)
                self.assertEqual(text.count("default "), 1)

    def sections(self):
        manifest = release()
        cmdline = (
            f"usrhash={manifest['usr_root_hash']} audit=1 enforcing=1 zswap.enabled=1 "
            "systemd.ssh_auto=no kvm_intel.nested=0 kvm_amd.nested=0 rfkill.default_state=0 "
            "module.sig_enforce=1 sysctl.kernel.unprivileged_bpf_disabled=1 "
            "sysctl.net.core.bpf_jit_harden=2 console=tty0"
        )
        profiles = []
        for index, item in enumerate([{"Profile": {"ID": "main"}}, *uki_profiles()]):
            p = {
                ".profile": {"text": "\n".join(f'{k}="{v}"' for k, v in item["Profile"].items())},
                ".pcrsig": {
                    "text": json.dumps(
                        {
                            "sha256": [
                                {
                                    "pcrs": [11],
                                    "pol": f"{index:064x}",
                                    "pkfp": "b" * 64,
                                    "sig": base64.b64encode(b"s" * 512).decode(),
                                }
                            ]
                        }
                    )
                },
            }
            if index:
                p[".cmdline"] = {"text": cmdline + " " + SERIAL_CONSOLES[item["Profile"]["ID"]]}
            profiles.append(p)
        return {
            ".osrel": {"text": "IMAGE_ID=ParticleVE\nIMAGE_VERSION=45.0.1.2-1.1"},
            ".cmdline": {"text": cmdline},
            "_profiles": profiles,
        }

    def inspect(self, sections):
        with patch(
            "particleve.release.run", return_value=SimpleNamespace(stdout=json.dumps(sections), stderr="")
        ):
            inspect_uki("test-only.efi", release())

    def test_initrd_policy_reference_distinguishes_the_same_approved_digest(self):
        sections = self.sections()
        signatures = json.loads(sections["_profiles"][0][".pcrsig"]["text"])
        initrd = copy.deepcopy(signatures["sha256"][0])
        initrd["ref"] = "ab" * 32
        signatures["sha256"].append(initrd)
        sections["_profiles"][0][".pcrsig"]["text"] = json.dumps(signatures)
        self.inspect(sections)

    def test_release_checks_every_profile_instead_of_only_the_base(self):
        source = self.sections()
        self.inspect(source)
        for change in (
            "missing-profile",
            "missing-signature",
            "unsigned-policy",
            "weaker-command-line",
            "module-enforcement-override",
            "missing-module-enforcement",
            "module-enforcement-alias",
            "jit-hardening-alias",
            "wrong-console",
            "kernel-override",
            "reordered",
            "duplicate-cmdline",
            "reused-policy",
        ):
            sections = copy.deepcopy(source)
            last = sections["_profiles"][-1]
            if change == "missing-profile":
                sections["_profiles"].pop()
            elif change == "missing-signature":
                del last[".pcrsig"]
            elif change == "unsigned-policy":
                policy = json.loads(last[".pcrsig"]["text"])
                del policy["sha256"][0]["sig"]
                last[".pcrsig"]["text"] = json.dumps(policy)
            elif change == "weaker-command-line":
                last[".cmdline"]["text"] += " enforcing=0"
            elif change == "module-enforcement-override":
                last[".cmdline"]["text"] += " module.sig_enforce=0"
            elif change == "missing-module-enforcement":
                last[".cmdline"]["text"] = last[".cmdline"]["text"].replace("module.sig_enforce=1", "")
            elif change == "module-enforcement-alias":
                sections[".cmdline"]["text"] += " module.sig-enforce=0"
            elif change == "jit-hardening-alias":
                sections[".cmdline"]["text"] += " sysctl.net/core/bpf_jit_harden=0"
            elif change == "wrong-console":
                last[".cmdline"]["text"] = last[".cmdline"]["text"].replace("ttyS3", "ttyS0")
            elif change == "kernel-override":
                last[".linux"] = {"size": 42}
            elif change == "reordered":
                sections["_profiles"][0], sections["_profiles"][1] = (
                    sections["_profiles"][1],
                    sections["_profiles"][0],
                )
            elif change == "duplicate-cmdline":
                last[".cmdline"] = [last[".cmdline"], last[".cmdline"]]
            else:
                last[".pcrsig"] = sections["_profiles"][0][".pcrsig"]
            with self.subTest(change=change), self.assertRaises(Error):
                self.inspect(sections)
