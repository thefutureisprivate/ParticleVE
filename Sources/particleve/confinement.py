"""Fail-closed native VM launch contract; persistent labels belong to provisioning."""

import os
import re
import resource
import shutil
import stat
from pathlib import Path

from .common import require, run
from .memoryprivacy import process_policy

MACHINES = Path("/var/lib/machines")
RUNTIME = Path("/run/particleve-vm")
GATE = Path("/run/particleve/vm-start-inhibited")
CONTROLLER = "particleve_vmspawn_t"
QEMU_HANDOFF = "/usr/libexec/particleve-qemu/qemu"
PTY_ALLOC = "system_u:object_r:particleve_vmspawn_pty_alloc_t:s0:c0.c1023"
PTY_TYPE = "particleve_vmspawn_devpts_t"
QEMU_SANDBOX = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
QEMU_MEMORY_PRIVACY = "mem-merge=off,dump-guest-core=off"
VM_ADDRESS_FAMILIES = {"AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6", "AF_PACKET", "AF_VSOCK"}
CONTROLLER_CAPABILITIES = {
    "cap_setfcap",
    "cap_setgid",
    "cap_setpcap",
    "cap_setuid",
    "cap_sys_admin",
    "cap_sys_resource",
}
QEMU_PRIVILEGES = (
    "/usr/bin/setpriv",
    "--no-new-privs",
    "--bounding-set=-all",
    "--inh-caps=-all",
    "--ambient-caps=-all",
    "--clear-groups",
    "--",
)


def qemu_arguments(arguments):
    """The verified handoff owns QEMU's syscall sandbox; external units cannot weaken it."""
    result = list(arguments)
    selected = []
    for index, argument in enumerate(result):
        if argument.startswith("-") and argument.lstrip("-").split("=", 1)[0] == "sandbox":
            require(argument == "-sandbox" and index + 1 < len(result), "unsupported QEMU sandbox override")
            selected.append(result[index + 1])
    require(not selected or selected == [QEMU_SANDBOX], "QEMU syscall sandbox must not be weakened")
    if not selected:
        result += ["-sandbox", QEMU_SANDBOX]
    # Native vmspawn supplies -readconfig. QEMU processes this final machine
    # group after that file, preserving its machine type and enforcing these
    # two properties. Verify the resulting VMAs too, including custom backends.
    if result[-2:] != ["-machine", QEMU_MEMORY_PRIVACY]:
        result += ["-machine", QEMU_MEMORY_PRIVACY]
    return result


def verify_qemu_sandbox(pid, *, proc=Path("/proc")):
    directory = proc / str(pid)
    values = dict(
        line.split(":", 1) for line in (directory / "status").read_text().splitlines() if ":" in line
    )
    require(
        values.get("Seccomp", "").strip() == "2"
        and int(values.get("Seccomp_filters", "0")) > 0
        and values.get("NoNewPrivs", "").strip() == "1",
        "QEMU syscall filtering is not active",
    )
    args = (directory / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    require(args.count("-sandbox") == 1 and qemu_arguments(args) == args, "QEMU's own sandbox is missing")
    require(
        all(
            int(values.get(field, "-1").strip(), 16) == 0
            for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
        and not values.get("Groups", "missing").strip(),
        "QEMU retained capabilities or supplementary groups",
    )
    process_policy(pid, proc=proc, qemu=True)


def check_unit_contract(unit):
    fields = (
        "ExecStart",
        "ExecStop",
        "KillMode",
        "KillSignal",
        "WatchdogSignal",
        "SendSIGKILL",
        "TimeoutStartUSec",
        "TimeoutStopUSec",
        "TimeoutAbortUSec",
        "NotifyAccess",
        "ExitType",
        "CapabilityBoundingSet",
        "SystemCallArchitectures",
        "RestrictAddressFamilies",
        "LimitCORE",
        "LimitCORESoft",
        "CoredumpFilter",
        "IOAccounting",
        "MemoryAccounting",
        "TasksAccounting",
        "MemoryHigh",
        "MemoryMax",
        "TasksMax",
        "OOMPolicy",
        "OOMScoreAdjust",
    )
    result = run(["systemctl", "show", unit, *("--property=" + field for field in fields)])
    require(not result.stderr, "native VM unit inspection produced diagnostics")
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    require(
        "path=/usr/libexec/particleve-vm-run " in values.get("ExecStart", ""),
        "external unit must launch the native runner through particleve-vm-run",
    )
    require("particleve-vm-stop" in values.get("ExecStop", ""), "VM synchronous stop helper is required")
    require(
        set(values.get("CapabilityBoundingSet", "").split()) == CONTROLLER_CAPABILITIES,
        "VM trusted-launcher capabilities changed",
    )
    require(values.get("SystemCallArchitectures") == "native", "VM host syscall ABI restriction changed")
    for field in ("IOAccounting", "MemoryAccounting", "TasksAccounting"):
        require(values.get(field) == "yes", "VM resource accounting changed: " + field)
    limits = {}
    for field in ("MemoryHigh", "MemoryMax", "TasksMax"):
        value = values.get(field, "")
        require(re.fullmatch(r"[1-9][0-9]{0,19}", value), "external VM unit needs a finite positive " + field)
        limits[field] = int(value)
    require(limits["MemoryHigh"] < limits["MemoryMax"], "VM MemoryHigh must be below MemoryMax")
    require(
        values.get("OOMPolicy") == "kill" and values.get("OOMScoreAdjust") == "0",
        "VM group OOM policy changed",
    )
    require(
        set(values.get("RestrictAddressFamilies", "").split()) == VM_ADDRESS_FAMILIES,
        "VM host socket-family restriction changed",
    )
    for field, expected in {
        "KillMode": "mixed",
        "KillSignal": "15",
        "WatchdogSignal": "15",
        "SendSIGKILL": "no",
        "TimeoutStartUSec": "infinity",
        "TimeoutStopUSec": "infinity",
        "TimeoutAbortUSec": "infinity",
        "NotifyAccess": "all",
        "ExitType": "cgroup",
        "LimitCORE": "0",
        "LimitCORESoft": "0",
        "CoredumpFilter": "0x0",
    }.items():
        require(values.get(field) == expected, f"VM lifecycle protection overridden: {field}")


def context(value, expected_type):
    parts = value.rstrip("\0\n").split(":", 4)
    require(
        len(parts) == 5 and parts[2] == expected_type and parts[3] == "s0", "unexpected VM SELinux context"
    )
    categories = []
    for item in parts[4].split(","):
        match = re.fullmatch(r"c([0-9]+)(?:\.c([0-9]+))?", item)
        require(match is not None, "invalid VM MCS category")
        first = int(match[1])
        last = int(match[2]) if match[2] else first
        require(0 <= first <= last < 1024 and last - first <= 1, "VM needs exactly two MCS categories")
        categories.extend(range(first, last + 1))
    require(
        len(categories) == 2 and len(set(categories)) == 2, "VM needs exactly two distinct MCS categories"
    )
    return tuple(sorted(categories))


def label(path):
    return os.getxattr(path, "security.selinux", follow_symlinks=False).decode()


def private_directory(path):
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
        f"VM directory must be a root-owned, nonsymlink directory with mode 0700: {path}",
    )
    return info


def check_tpm_arguments(name, command):
    """Native vmspawn must reuse provisioned state, never manufacture a transient identity."""
    options = [arg for arg in command if arg.split("=", 1)[0] in ("--tpm", "--tpm-state")]
    require(all("=" in arg for arg in options), "use explicit --tpm= and --tpm-state= arguments")
    modes = [arg.removeprefix("--tpm=") for arg in options if arg.startswith("--tpm=")]
    paths = [arg.removeprefix("--tpm-state=") for arg in options if arg.startswith("--tpm-state=")]
    require(modes in (["no"], ["yes"]), "declare --tpm=no or --tpm=yes exactly once")
    if modes == ["no"]:
        require(not paths, "disabled TPM must not select retained state")
        return
    require(len(paths) == 1, "enabled TPM requires one explicitly provisioned state directory")
    state = Path(paths[0])
    root = MACHINES / name
    require(
        state.parent == root and state.name not in (".", ".."), "TPM state must be inside its VM subvolume"
    )
    private_directory(state)
    categories = context(label(root), "virt_var_lib_t")
    require(context(label(state), "virt_var_lib_t") == categories, "TPM directory categories differ")
    permanent = state / "tpm2-00.permall"
    info = permanent.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == info.st_gid == 0
        and not stat.S_IMODE(info.st_mode) & 0o007
        and info.st_size > 0
        and info.st_nlink == 1,
        "provision a fresh private TPM with the image's profile before enabling it; "
        "retained state is never reset",
    )
    require(context(label(permanent), "virt_var_lib_t") == categories, "TPM state categories differ")


def start_guard(name):
    require(os.geteuid() == 0, "VM launch requires root")
    require(not GATE.exists(), "VM starts are temporarily inhibited for OS maintenance")
    require(
        Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "VM launch requires SELinux enforcing"
    )
    require(os.access("/dev/kvm", os.R_OK | os.W_OK), "KVM acceleration is required")
    require(shutil.which("qemu") == QEMU_HANDOFF, "VM launch requires the guarded QEMU handoff")
    require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name) is not None, "invalid VM instance name")
    unit = f"systemd-vmspawn@{name}.service"
    groups = [
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")
    ]
    require(len(groups) == 1 and Path(groups[0]).name == unit, "VM guard must run in its owning unit")
    check_unit_contract(unit)
    categories = context(Path("/proc/self/attr/current").read_text(), CONTROLLER)
    root = MACHINES / name
    require(private_directory(root).st_ino == 256, "VM root must be a Btrfs subvolume")
    require(context(label(root), "virt_var_lib_t") == categories, "VM subvolume and unit categories differ")
    for other in MACHINES.iterdir():
        if other == root or not other.is_dir():
            continue
        require(not other.is_symlink(), "symlink in VM storage inventory")
        require(
            context(label(other), "virt_var_lib_t") != categories,
            f"VM MCS category pair is already assigned: {other.name}",
        )
    runtime = RUNTIME / name
    private_directory(runtime)
    require(label(runtime).split(":")[2] == "qemu_var_run_t", "unexpected VM runtime directory type")
    # PID1 creates this ephemeral directory at s0. Never relabel retained VM data.
    first, second = categories
    os.setxattr(
        runtime,
        "security.selinux",
        f"system_u:object_r:qemu_var_run_t:s0:c{first},c{second}\0".encode(),
        follow_symlinks=False,
    )
    return categories


def qemu_handoff(arguments):
    """Label native console descriptors before the QEMU domain transition."""
    groups = [
        line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")
    ]
    require(len(groups) == 1, "QEMU handoff requires its owning unit")
    match = re.fullmatch(r"systemd-vmspawn@(.+)\.service", Path(groups[0]).name)
    require(match is not None, "QEMU handoff requires its owning unit")
    first, second = start_guard(match[1])
    arguments = qemu_arguments(arguments)
    target = f"system_u:object_r:{PTY_TYPE}:s0:c{first},c{second}"
    for fd in (0, 1, 2):
        if not os.isatty(fd):
            continue
        import selinux

        status, current = selinux.fgetfilecon(fd)
        require(status >= 0, "cannot inspect native console label")
        if current == PTY_ALLOC:
            require(selinux.fsetfilecon(fd, target) == 0, "cannot label native console")
            status, current = selinux.fgetfilecon(fd)
        require(
            status >= 0 and context(current, PTY_TYPE) == (first, second),
            "native console and VM categories differ",
        )
    # Preserve native vmspawn's arguments and inherited TAP/QMP/drive descriptors.
    # Keep namespace, TAP and descriptor setup in the trusted native controller.
    # Only its QEMU child loses every capability/bounding bit and supplementary
    # group. NoNewPrivileges prevents later exec from regaining root capabilities.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execv(QEMU_PRIVILEGES[0], [*QEMU_PRIVILEGES, "/usr/bin/qemu-kvm", *arguments])


def verify_processes(processes):
    categories = None
    types = set()
    for entry in processes:
        current = Path(f"/proc/{entry['pid']}/attr/current").read_text()
        kind = current.split(":")[2]
        require(
            kind in (CONTROLLER, "svirt_t", "swtpm_t"), "VM unit contains an unexpected or unconfined process"
        )
        pair = context(current, kind)
        if categories is None:
            categories = pair
        require(pair == categories, "VM processes have different MCS categories")
        types.add(kind)
        if kind == "svirt_t":
            verify_qemu_sandbox(entry["pid"])
        else:
            process_policy(entry["pid"])
    require(CONTROLLER in types and "svirt_t" in types, "VM controller or confined QEMU is missing")
