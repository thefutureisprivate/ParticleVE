import os
import resource
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from particleve.common import Error
from particleve.confinement import (
    CONTROLLER,
    CONTROLLER_CAPABILITIES,
    PTY_ALLOC,
    PTY_TYPE,
    QEMU_HANDOFF,
    QEMU_MEMORY_PRIVACY,
    QEMU_PRIVILEGES,
    QEMU_SANDBOX,
    VM_ADDRESS_FAMILIES,
    check_tpm_arguments,
    check_unit_contract,
    context,
    private_directory,
    qemu_arguments,
    qemu_handoff,
    start_guard,
    verify_processes,
    verify_qemu_sandbox,
)
from particleve.processes import observe


class ConfinementTests(unittest.TestCase):
    def test_tpm_identity_requires_an_explicit_persistent_choice(self):
        check_tpm_arguments("test", ["--tpm=no"])
        for command in (
            [],
            ["--tpm=auto"],
            ["--tpm=yes"],
            ["--tpm=yes", "--tpm=no"],
            ["--tpm", "no"],
            ["--tpm=no", "--tpm-state=/var/lib/machines/test/tpm"],
            ["--tpm=yes", "--tpm-state=/var/lib/machines/other/tpm"],
        ):
            with self.subTest(command=command), self.assertRaises(Error):
                check_tpm_arguments("test", command)

    def test_provisioned_tpm_is_only_inspected_and_links_or_shared_state_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "test/tpm"
            state.mkdir(parents=True)
            permanent = state / "tpm2-00.permall"
            content = b"opaque retained identity; never initialize or convert"
            permanent.write_bytes(content)
            permanent.chmod(0o640)
            native_lstat = Path.lstat

            def root_owned(path):
                info = list(native_lstat(path))
                info[4:6] = [0, 0]
                return os.stat_result(info)

            command = ["--tpm=yes", "--tpm-state=" + str(state)]
            with (
                patch("particleve.confinement.MACHINES", root),
                patch("particleve.confinement.private_directory"),
                patch(
                    "particleve.confinement.label", return_value="system_u:object_r:virt_var_lib_t:s0:c1,c2"
                ),
                patch.object(Path, "lstat", root_owned),
            ):
                check_tpm_arguments("test", command)
                self.assertEqual(permanent.read_bytes(), content)
                permanent.chmod(0o644)
                with self.assertRaisesRegex(Error, "private TPM"):
                    check_tpm_arguments("test", command)
                permanent.chmod(0o640)
                alias = state / "shared"
                alias.hardlink_to(permanent)
                with self.assertRaisesRegex(Error, "private TPM"):
                    check_tpm_arguments("test", command)
                alias.unlink()
                permanent.rename(alias)
                permanent.symlink_to(alias)
                with self.assertRaisesRegex(Error, "private TPM"):
                    check_tpm_arguments("test", command)
                self.assertEqual(alias.read_bytes(), content)

    def test_external_unit_cannot_bypass_activation_or_stop_protection(self):
        values = {
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
            "CapabilityBoundingSet": " ".join(sorted(CONTROLLER_CAPABILITIES)),
            "SystemCallArchitectures": "native",
            "RestrictAddressFamilies": " ".join(sorted(VM_ADDRESS_FAMILIES)),
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
        for override in (
            {},
            {"ExecStart": "{ path=/usr/bin/systemd-vmspawn ; }"},
            {"TimeoutStartUSec": "2min"},
            {"SendSIGKILL": "yes"},
            {"KillMode": "control-group"},
            {"CapabilityBoundingSet": "cap_sys_admin cap_sys_ptrace"},
            {"SystemCallArchitectures": ""},
            {"RestrictAddressFamilies": " ".join(sorted(VM_ADDRESS_FAMILIES | {"AF_ALG"}))},
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
            result = "\n".join(k + "=" + v for k, v in (values | override).items())
            with (
                self.subTest(override=override),
                patch("particleve.confinement.run", return_value=SimpleNamespace(stdout=result, stderr="")),
            ):
                if override:
                    with self.assertRaises(Error):
                        check_unit_contract("systemd-vmspawn@test.service")
                else:
                    check_unit_contract("systemd-vmspawn@test.service")

    def test_private_directory_rejects_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(Error, "nonsymlink"):
                private_directory(root / "link")

    def test_collision_rejects_start_before_any_relabel_and_success_only_labels_runtime(self):
        for collision in (False, True):
            with tempfile.TemporaryDirectory() as directory, self.subTest(collision=collision):
                machines = Path(directory) / "machines"
                machines.mkdir()
                (machines / "test").mkdir()
                (machines / "peer").mkdir()
                runtime = Path(directory) / "runtime"
                values = {
                    "/sys/fs/selinux/enforce": "1",
                    "/proc/self/cgroup": "0::/machine.slice/systemd-vmspawn@test.service\n",
                    "/proc/self/attr/current": f"system_u:system_r:{CONTROLLER}:s0:c10,c20",
                }

                def read(path, values=values):
                    return values[str(path)]

                def labels(path, runtime=runtime, collision=collision):
                    if path == runtime / "test":
                        return "system_u:object_r:qemu_var_run_t:s0"
                    pair = "c30,c40" if path.name == "peer" and not collision else "c10,c20"
                    return f"system_u:object_r:virt_var_lib_t:s0:{pair}"

                with (
                    patch("particleve.confinement.os.geteuid", return_value=0),
                    patch("particleve.confinement.os.access", return_value=True),
                    patch("particleve.confinement.shutil.which", return_value=QEMU_HANDOFF),
                    patch("particleve.confinement.check_unit_contract"),
                    patch("particleve.confinement.GATE") as gate,
                    patch("particleve.confinement.MACHINES", machines),
                    patch("particleve.confinement.RUNTIME", runtime),
                    patch(
                        "particleve.confinement.private_directory", return_value=SimpleNamespace(st_ino=256)
                    ),
                    patch("particleve.confinement.label", side_effect=labels),
                    patch.object(Path, "read_text", read),
                    patch("particleve.confinement.os.setxattr") as relabel,
                ):
                    gate.exists.return_value = False
                    if collision:
                        with self.assertRaisesRegex(Error, "already assigned"):
                            start_guard("test")
                        relabel.assert_not_called()
                    else:
                        start_guard("test")
                        self.assertEqual(relabel.call_args.args[0], runtime / "test")
                        self.assertEqual(relabel.call_count, 1)

    def test_handoff_labels_only_quarantined_console_and_preserves_native_arguments(self):
        target = f"system_u:object_r:{PTY_TYPE}:s0:c10,c20"
        selinux = Mock()
        selinux.fgetfilecon.side_effect = [(1, PTY_ALLOC), (1, target), (1, target)]
        selinux.fsetfilecon.return_value = 0
        arguments = ["-add-fd", "fd=7,set=1", "-netdev", "tap,fd=8"]
        with (
            patch.object(Path, "read_text", return_value="0::/machine.slice/systemd-vmspawn@test.service"),
            patch("particleve.confinement.start_guard", return_value=(10, 20)) as guard,
            patch("particleve.confinement.os.isatty", side_effect=[True, True, False]),
            patch.dict("sys.modules", selinux=selinux),
            patch("particleve.confinement.os.execv") as execute,
            patch("particleve.confinement.resource.setrlimit") as limits,
        ):
            qemu_handoff(arguments)
        guard.assert_called_once_with("test")
        selinux.fsetfilecon.assert_called_once_with(0, target)
        execute.assert_called_once_with(
            "/usr/bin/setpriv", [*QEMU_PRIVILEGES, "/usr/bin/qemu-kvm", *qemu_arguments(arguments)]
        )
        limits.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))

    def test_qemu_sandbox_cannot_be_disabled_or_partially_weakened(self):
        for arguments in (
            ["-sandbox", "off"],
            ["-sandbox", "on,spawn=allow"],
            ["-sandbox", "on"],
            ["--sandbox=off"],
            ["-sandbox"],
            ["-sandbox", QEMU_SANDBOX, "-sandbox", QEMU_SANDBOX],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(Error):
                qemu_arguments(arguments)
        protected = qemu_arguments(["-sandbox", QEMU_SANDBOX])
        self.assertEqual(protected, ["-sandbox", QEMU_SANDBOX, "-machine", QEMU_MEMORY_PRIVACY])
        self.assertEqual(qemu_arguments(protected), protected)
        self.assertEqual(qemu_arguments(["-name", "sandbox"])[:2], ["-name", "sandbox"])
        native = ["-readconfig", "/run/native.conf", "-machine", "mem-merge=on,dump-guest-core=on"]
        self.assertEqual(qemu_arguments(native)[-2:], ["-machine", QEMU_MEMORY_PRIVACY])

    def test_effective_seccomp_and_native_sandbox_option_are_both_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            process = proc / "123"
            process.mkdir()
            (process / "limits").write_text("Max core file size        0                    0   bytes\n")
            (process / "coredump_filter").write_text("00000000\n")
            (process / "smaps").write_text("1000-2000 rw-p 00000000 00:00 0\nKSM: 0 kB\nVmFlags: rd wr\n")
            (process / "ksm_stat").write_text("ksm_zero_pages 0\nksm_merging_pages 0\n")
            for mode, filters, nnp, arguments in (
                ("2", "1", "1", qemu_arguments([])),
                ("2", "1", "1", ["-sandbox", QEMU_SANDBOX]),
                ("0", "0", "1", ["-sandbox", QEMU_SANDBOX]),
                ("2", "1", "0", ["-sandbox", QEMU_SANDBOX]),
                ("2", "1", "1", []),
                ("2", "1", "1", ["-sandbox", "off"]),
            ):
                with (
                    self.subTest(mode=mode, filters=filters, arguments=arguments),
                    observe(123, proc=proc) as observation,
                ):
                    (process / "status").write_text(
                        f"Seccomp: {mode}\nSeccomp_filters: {filters}\nNoNewPrivs: {nnp}\n"
                        + "\n".join(
                            f"{field}: 0" for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
                        )
                        + "\nGroups:\n"
                    )
                    (process / "cmdline").write_bytes("\0".join(["qemu", *arguments]).encode())
                    if mode == "2" and nnp == "1" and arguments == qemu_arguments([]):
                        verify_qemu_sandbox(observation)
                    else:
                        with self.assertRaises(Error):
                            verify_qemu_sandbox(observation)
            for field, value in (("CapEff", "1"), ("CapBnd", "1"), ("Groups", "0")):
                (process / "status").write_text(
                    "\n".join(
                        f"{key}: {selected}"
                        for key, selected in (
                            {
                                "Seccomp": "2",
                                "Seccomp_filters": "1",
                                "NoNewPrivs": "1",
                                "Groups": "",
                                **dict.fromkeys(("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), "0"),
                            }
                            | {field: value}
                        ).items()
                    )
                )
                (process / "cmdline").write_bytes("\0".join(["qemu", *qemu_arguments([])]).encode())
                with (
                    self.subTest(field=field),
                    observe(123, proc=proc) as observation,
                    self.assertRaisesRegex(Error, "retained"),
                ):
                    verify_qemu_sandbox(observation)

    def test_handoff_rejects_foreign_unlabelled_and_failed_console_labels(self):
        target = f"system_u:object_r:{PTY_TYPE}:s0:c10,c20"
        for values in (
            [(1, f"system_u:object_r:{PTY_TYPE}:s0:c30,c40")],
            [(1, f"system_u:object_r:{PTY_TYPE}:s0")],
            [(1, "system_u:object_r:devpts_t:s0")],
            [(-1, "")],
            [(1, PTY_ALLOC), (-1, target)],
        ):
            selinux = Mock()
            selinux.fgetfilecon.side_effect = values
            selinux.fsetfilecon.return_value = 0
            with (
                self.subTest(values=values),
                patch.object(Path, "read_text", return_value="0::/systemd-vmspawn@test.service"),
                patch("particleve.confinement.start_guard", return_value=(10, 20)),
                patch("particleve.confinement.os.isatty", return_value=True),
                patch.dict("sys.modules", selinux=selinux),
                patch("particleve.confinement.os.execv") as execute,
                self.assertRaises(Error),
            ):
                qemu_handoff([])
            execute.assert_not_called()
            if values[0][1] != PTY_ALLOC:
                selinux.fsetfilecon.assert_not_called()

    def test_handoff_rejects_foreign_unit_before_labelling_or_execution(self):
        with (
            patch.object(Path, "read_text", return_value="0::/system.slice/foreign.service"),
            patch("particleve.confinement.start_guard") as guard,
            patch("particleve.confinement.os.isatty") as inspect,
            patch("particleve.confinement.os.execv") as execute,
            self.assertRaisesRegex(Error, "owning unit"),
        ):
            qemu_handoff([])
        guard.assert_not_called()
        inspect.assert_not_called()
        execute.assert_not_called()

    def test_launch_rejects_bypassed_handoff_before_storage_inspection(self):
        with (
            patch("particleve.confinement.os.geteuid", return_value=0),
            patch("particleve.confinement.GATE") as gate,
            patch("particleve.confinement.os.access", return_value=True),
            patch("particleve.confinement.shutil.which", return_value="/usr/bin/qemu"),
            patch.object(Path, "read_text", return_value="1"),
            patch("particleve.confinement.private_directory") as inspect,
            self.assertRaisesRegex(Error, "guarded QEMU handoff"),
        ):
            gate.exists.return_value = False
            start_guard("test")
        inspect.assert_not_called()

    def test_mcs_pair_accepts_kernel_canonical_adjacent_range(self):
        for value in ("c10,c20", "c20,c10", "c10.c11"):
            self.assertEqual(
                context(f"system_u:system_r:{CONTROLLER}:s0:{value}\n", CONTROLLER),
                (10, 11) if value == "c10.c11" else (10, 20),
            )

    def test_unconfined_or_shared_category_ranges_are_rejected(self):
        for value in (
            "system_u:system_r:unconfined_service_t:s0:c10,c20",
            f"system_u:system_r:{CONTROLLER}:s0",
            f"system_u:system_r:{CONTROLLER}:s0:c10",
            f"system_u:system_r:{CONTROLLER}:s0:c10,c10",
            f"system_u:system_r:{CONTROLLER}:s0:c0.c1023",
            f"system_u:system_r:{CONTROLLER}:s0:c0,c1024",
        ):
            with self.subTest(value=value), self.assertRaises(Error):
                context(value, CONTROLLER)

    def test_inhibition_precedes_all_launch_inspection_and_relabeling(self):
        with (
            patch("particleve.confinement.os.geteuid", return_value=0),
            patch("particleve.confinement.GATE") as gate,
            patch("particleve.confinement.os.setxattr") as relabel,
            patch.object(Path, "read_text") as read,
            self.assertRaisesRegex(Error, "temporarily inhibited"),
        ):
            gate.exists.return_value = True
            start_guard("test")
        read.assert_not_called()
        relabel.assert_not_called()

    def test_inventory_rejects_mixed_categories_and_unconfined_children(self):
        for last in (
            "system_u:system_r:swtpm_t:s0:c10,c20",
            "system_u:system_r:swtpm_t:s0:c30,c40",
            "system_u:system_r:unconfined_service_t:s0:c10,c20",
        ):
            with (
                self.subTest(last=last),
                tempfile.TemporaryDirectory() as tmp,
                patch("particleve.confinement.verify_qemu_sandbox"),
                patch("particleve.confinement.process_policy"),
            ):
                proc = Path(tmp)
                for pid, label in enumerate(
                    (
                        f"system_u:system_r:{CONTROLLER}:s0:c10,c20",
                        "system_u:system_r:svirt_t:s0:c10,c20",
                        last,
                    ),
                    1,
                ):
                    directory = proc / str(pid)
                    (directory / "attr").mkdir(parents=True)
                    (directory / "attr/current").write_text(label)
                    (directory / "stat").write_text(f"{pid} (vm) S " + "0 " * 18 + "1\n")
                processes = [{"pid": n, "starttime": 1} for n in (1, 2, 3)]
                if ":swtpm_t:s0:c10,c20" in last:
                    verify_processes(processes, proc=proc)
                else:
                    with self.assertRaises(Error):
                        verify_processes(processes, proc=proc)
