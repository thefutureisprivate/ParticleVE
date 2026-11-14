"""Exercise the compiled launch boundary with explicit native contracts and proc fixtures."""

import tempfile
from pathlib import Path

from Tests.runtime import RustDriverTests

SANDBOX = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
PRIVACY = "mem-merge=off,dump-guest-core=off"
CAPABILITIES = "cap_setfcap cap_setgid cap_setpcap cap_setuid cap_sys_admin cap_sys_resource"
FAMILIES = "AF_UNIX AF_NETLINK AF_INET AF_INET6 AF_PACKET AF_VSOCK"


def unit_properties():
    return {
        "ExecStart": "{ path=/usr/libexec/particleve-vm-run ; argv[]=runner test native; }",
        "ExecStop": "particleve-vm-stop test",
        "KillMode": "mixed",
        "KillSignal": "15",
        "WatchdogSignal": "15",
        "SendSIGKILL": "no",
        "TimeoutStartUSec": "infinity",
        "TimeoutStopUSec": "infinity",
        "TimeoutAbortUSec": "infinity",
        "NotifyAccess": "all",
        "ExitType": "cgroup",
        "CapabilityBoundingSet": CAPABILITIES,
        "SystemCallArchitectures": "native",
        "RestrictAddressFamilies": FAMILIES,
        "LimitCORE": "0",
        "LimitCORESoft": "0",
        "CoredumpFilter": "0x0",
        "IOAccounting": "yes",
        "MemoryAccounting": "yes",
        "TasksAccounting": "yes",
        "MemoryHigh": "1610612736",
        "MemoryMax": "2147483648",
        "TasksMax": "256",
        "OOMPolicy": "kill",
        "OOMScoreAdjust": "0",
    }


class ConfinementTests(RustDriverTests):
    def test_explicit_tpm_identity_is_mandatory(self):
        self.evaluate("vm-tpm-arguments", name="test", arguments=["--tpm=no"])
        for arguments in (
            [],
            ["--tpm=auto"],
            ["--tpm=yes"],
            ["--tpm=yes", "--tpm=no"],
            ["--tpm", "no"],
            ["--tpm=no", "--tpm-state=/var/lib/machines/test/tpm"],
            ["--tpm=yes", "--tpm-state=/var/lib/machines/other/tpm"],
        ):
            with self.subTest(arguments=arguments):
                self.assertIn("error", self.request("vm-tpm-arguments", name="test", arguments=arguments))

    def test_external_unit_cannot_expand_authority_or_remove_lifecycle_protection(self):
        self.evaluate("vm-unit-contract", properties=unit_properties())
        for override in (
            {"ExecStart": "{ path=/usr/bin/systemd-vmspawn ; }"},
            {"ExecStop": ""},
            {"TimeoutStartUSec": "2min"},
            {"TimeoutStopUSec": "2min"},
            {"TimeoutAbortUSec": "2min"},
            {"SendSIGKILL": "yes"},
            {"KillMode": "control-group"},
            {"KillSignal": "9"},
            {"WatchdogSignal": "6"},
            {"CapabilityBoundingSet": "cap_sys_admin cap_sys_ptrace"},
            {"SystemCallArchitectures": ""},
            {"RestrictAddressFamilies": FAMILIES + " AF_ALG"},
            {"RestrictAddressFamilies": "~"},
            {"LimitCORE": "infinity"},
            {"LimitCORESoft": "1024"},
            {"CoredumpFilter": "0x33"},
            {"IOAccounting": "no"},
            {"MemoryAccounting": "no"},
            {"TasksAccounting": "no"},
            {"MemoryHigh": "infinity"},
            {"MemoryMax": "infinity"},
            {"TasksMax": "infinity"},
            {"MemoryHigh": "2147483648"},
            {"MemoryMax": "0"},
            {"OOMPolicy": "stop"},
            {"OOMScoreAdjust": "-1000"},
        ):
            with self.subTest(override=override):
                self.assertIn(
                    "error", self.request("vm-unit-contract", properties=unit_properties() | override)
                )

    def test_qemu_handoff_preserves_native_descriptors_and_enforces_both_sandboxes(self):
        native = ["-add-fd", "fd=7,set=1", "-netdev", "tap,fd=8", "-readconfig", "/run/native.conf"]
        expected = [*native, "-sandbox", SANDBOX, "-machine", PRIVACY]
        self.assertEqual(self.evaluate("qemu-arguments", arguments=native), expected)
        self.assertEqual(self.evaluate("qemu-arguments", arguments=expected), expected)
        for arguments in (
            ["-sandbox", "off"],
            ["-sandbox", "on,spawn=allow"],
            ["-sandbox", "on"],
            ["--sandbox=off"],
            ["-sandbox"],
            ["-sandbox", SANDBOX, "-sandbox", SANDBOX],
        ):
            with self.subTest(arguments=arguments):
                self.assertIn("error", self.request("qemu-arguments", arguments=arguments))
        self.assertEqual(
            self.evaluate("qemu-arguments", arguments=["-machine", "mem-merge=on,dump-guest-core=on"])[-2:],
            ["-machine", PRIVACY],
        )

    def test_mcs_pair_is_exact_and_kernel_adjacent_ranges_are_supported(self):
        for categories, pair in (("c10,c20", [10, 20]), ("c20,c10", [10, 20]), ("c10.c11", [10, 11])):
            self.assertEqual(
                self.evaluate(
                    "vm-context", context="system_u:system_r:svirt_t:s0:" + categories, type="svirt_t"
                ),
                pair,
            )
        for context in (
            "system_u:system_r:unconfined_service_t:s0:c10,c20",
            "system_u:system_r:svirt_t:s0",
            "system_u:system_r:svirt_t:s0:c10",
            "system_u:system_r:svirt_t:s0:c10,c10",
            "system_u:system_r:svirt_t:s0:c0.c1023",
            "system_u:system_r:svirt_t:s0:c0,c1024",
        ):
            with self.subTest(context=context):
                self.assertIn("error", self.request("vm-context", context=context, type="svirt_t"))

    def test_actual_proc_observations_require_matching_categories_and_zero_auxiliary_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            fields = {
                "Seccomp": "2",
                "Seccomp_filters": "4",
                "NoNewPrivs": "1",
                "Groups": "",
                **dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), "0"),
            }
            for pid, domain in enumerate(("particleve_vmspawn_t", "svirt_t", "swtpm_t"), 1):
                path = proc / str(pid)
                (path / "attr").mkdir(parents=True)
                (path / "attr/current").write_text(f"system_u:system_r:{domain}:s0:c10,c20")
                (path / "stat").write_text(f"{pid} (vm) S " + "0 " * 18 + "42\n")
                (path / "status").write_text("\n".join(f"{k}: {v}" for k, v in fields.items()))
                (path / "limits").write_text("Max core file size 0 0 bytes\n")
                (path / "coredump_filter").write_text("00000000\n")
                (path / "maps").write_text(
                    "1000-2000 r-xp 00000000 00:01 5 /usr/lib64/libhardened_malloc.so\n"
                )
            qemu = proc / "2"
            (qemu / "cmdline").write_bytes(
                "\0".join(["qemu", "-sandbox", SANDBOX, "-machine", PRIVACY]).encode()
            )
            (qemu / "smaps").write_text("1000-2000 rw-p 00000000 00:00 0\nKSM: 0 kB\nVmFlags: rd wr\n")
            (qemu / "ksm_stat").write_text("ksm_zero_pages 0\nksm_merging_pages 0\n")
            identities = [{"pid": pid, "starttime": 42} for pid in (1, 2, 3)]
            self.evaluate("vm-verify-processes", proc=str(proc), processes=identities)
            maps = proc / "3/maps"
            original_maps = maps.read_text()
            for invalid in (
                "",
                original_maps.replace("r-xp", "rwxp"),
                original_maps.rstrip() + " (deleted)\n",
            ):
                maps.write_text(invalid)
                with self.subTest(maps=invalid):
                    self.assertIn(
                        "error", self.request("vm-verify-processes", proc=str(proc), processes=identities)
                    )
            maps.write_text(original_maps)
            label = proc / "3/attr/current"
            for context in (
                "system_u:system_r:swtpm_t:s0:c30,c40",
                "system_u:system_r:unconfined_service_t:s0:c10,c20",
            ):
                label.write_text(context)
                self.assertIn(
                    "error", self.request("vm-verify-processes", proc=str(proc), processes=identities)
                )
            label.write_text("system_u:system_r:swtpm_t:s0:c10,c20")
            for mutation in (
                *({key: "1"} for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
                {"NoNewPrivs": "0"},
                {"Seccomp": "0"},
                {"Seccomp_filters": "0"},
                {"Groups": "0"},
            ):
                (proc / "3/status").write_text("\n".join(f"{k}: {v}" for k, v in (fields | mutation).items()))
                with self.subTest(mutation=mutation):
                    self.assertIn(
                        "error", self.request("vm-verify-processes", proc=str(proc), processes=identities)
                    )
