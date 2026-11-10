"""Compare passive allocator RPMs in an explicitly selected disposable recovery VM.

This is component evidence, not vmspawn, guest I/O, authentication, maintenance,
whole-host pressure, verified-/usr or signed-image acceptance. It never enables a
global preload, changes sysctls, or operates an existing guest or TPM identity.
"""

import argparse
import contextlib
import hashlib
import json
import os
import selectors
import socket
import struct
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(arguments, **options):
    return subprocess.run(
        arguments, capture_output=True, text=True, check=True, timeout=30, **options
    ).stdout.strip()


def snapshot(pid):
    root = Path("/proc") / str(pid)
    maps = (root / "maps").read_text().splitlines()
    status = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines())
    return {
        "pid": pid,
        "map_count": len(maps),
        "rss_kib": int(status["VmRSS"].split()[0]),
        "rss_peak_kib": int(status["VmHWM"].split()[0]),
        "virtual_kib": int(status["VmSize"].split()[0]),
        "allocator_mappings": [line for line in maps if "libhardened_malloc" in line],
        "selinux": (root / "attr/current").read_text().rstrip("\x00\n"),
        "capabilities": {
            key: status[key].strip() for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
        },
        "no_new_privileges": status["NoNewPrivs"].strip(),
        "seccomp": status["Seccomp"].strip(),
        "uids": [int(value) for value in status["Uid"].split()],
        "gids": [int(value) for value in status["Gid"].split()],
        "groups": [int(value) for value in status["Groups"].split()],
    }


def selected(snapshot, library):
    mappings = snapshot["allocator_mappings"]
    require(bool(mappings) == bool(library), "allocator mapping does not match selection")
    if library:
        require(all(line.endswith(library) for line in mappings), "unexpected allocator mapping")
    require(
        all(int(value, 16) == 0 for value in snapshot["capabilities"].values()),
        "test process retained capabilities",
    )
    require(snapshot["no_new_privileges"] == "1", "test process lost NoNewPrivileges")
    require(
        set(snapshot["uids"]) == {65534}
        and set(snapshot["gids"]) == {65534}
        and set(snapshot["groups"]) <= {65534},
        "test process retained privileged user/group authority",
    )


@contextlib.contextmanager
def child(arguments, environment, log):
    # Only processes created here are stopped during cleanup. No externally
    # managed guest, service, or identity is included in this process group.
    with log.open("wb") as errors:
        process = subprocess.Popen(
            [
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--bounding-set=-all",
                "--no-new-privs",
                *arguments,
            ],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            start_new_session=True,
        )
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(10), "allocation probe did not respond")
    data = process.stdout.readline(4097)
    require(0 < len(data) <= 4096, "invalid allocation response")
    return json.loads(data)


def allocation(probe, environment, library, log):
    with child([str(probe)], environment, log) as process:
        owner = line(process)
        require(owner["pid"] == process.pid, "unexpected probe PID")
        require(
            owner["malloc_owner"] == library if library else "libc.so.6" in owner["malloc_owner"],
            "malloc resolves to another library",
        )
        samples = [snapshot(process.pid)]
        selected(samples[0], library)
        process.stdin.write(b"\n")
        process.stdin.flush()
        deadline = time.monotonic() + 30
        missed_exit_samples = 0
        while process.poll() is None:
            require(time.monotonic() < deadline, "allocation probe exceeded deadline")
            try:
                samples.append(snapshot(process.pid))
            except FileNotFoundError, ProcessLookupError, KeyError:
                # Linux can release mm before this child becomes waitable.
                # Continue observing the same PID/handle until its terminal
                # status arrives; never turn a missing sample into success.
                missed_exit_samples += 1
            time.sleep(0.01)
        require(process.returncode == 0, f"allocation probe failed; inspect {log}")
        result = line(process)
        require(result["calloc_realloc_pairs"] == 65536, "incomplete allocation workload")
        return (
            owner
            | result
            | {
                "initial": samples[0],
                "sampled_peak_rss_kib": max(sample["rss_kib"] for sample in samples),
                "sampled_peak_map_count": max(sample["map_count"] for sample in samples),
                "samples": len(samples),
                "missed_exit_samples": missed_exit_samples,
            }
        )


def connect(path, process):
    deadline = time.monotonic() + 10
    while True:
        require(process.poll() is None, "component exited before socket readiness")
        try:
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(5)
            connection.connect(str(path))
            return connection
        except FileNotFoundError, ConnectionRefusedError:
            connection.close()
            require(time.monotonic() < deadline, "component socket exceeded readiness deadline")
            time.sleep(0.01)


def qmp(stream, execute, arguments=None):
    request = {"execute": execute}
    if arguments is not None:
        request["arguments"] = arguments
    stream.write(json.dumps(request).encode() + b"\n")
    stream.flush()
    deadline = time.monotonic() + 10
    while True:
        require(time.monotonic() < deadline, "QMP response exceeded deadline")
        message = json.loads(stream.readline(65537))
        if "event" in message:
            continue
        require("return" in message, message)
        return message["return"]


def qemu(directory, environment, library, log):
    source, target = directory / "source.raw", directory / "target.raw"
    source.write_bytes(bytes(range(256)) * (8 * 1024**2 // 256))
    with target.open("xb") as output:
        output.truncate(source.stat().st_size)
    os.chown(target, 65534, 65534)
    address = directory / "qmp"
    arguments = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=tcg",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-m",
        "128M",
        "-S",
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-qmp",
        f"unix:{address},server=on,wait=off",
        "-drive",
        f"if=none,id=source,file={source},format=raw,read-only=on",
        "-device",
        "virtio-blk-pci,drive=source",
        "-blockdev",
        f"driver=file,filename={target},node-name=target-file",
        "-blockdev",
        "driver=raw,file=target-file,node-name=target",
        "-netdev",
        "user,id=test,restrict=on",
        "-device",
        "virtio-net-pci,netdev=test",
    ]
    start = time.monotonic_ns()
    with child(arguments, environment, log) as process, connect(address, process) as connection:
        with connection.makefile("rwb") as stream:
            greeting = json.loads(stream.readline(65537))
            require("QMP" in greeting, "missing QMP greeting")
            qmp(stream, "qmp_capabilities")
            startup = time.monotonic_ns() - start
            observation = snapshot(process.pid)
            selected(observation, library)
            require(observation["seccomp"] == "2", "QEMU sandbox did not install seccomp")
            status = qmp(stream, "query-status")
            require(status["status"] == "prelaunch", status)
            pci = qmp(stream, "query-pci")
            devices = [device for bus in pci for device in bus["devices"]]
            virtio_classes = sorted(
                device["class_info"]["class"] for device in devices if device["id"]["vendor"] == 0x1AF4
            )
            require(virtio_classes == [0x100, 0x200], "missing virtio block/network initialization")
            start = time.monotonic_ns()
            qmp(
                stream,
                "blockdev-backup",
                {
                    "job-id": "allocator-copy",
                    "device": "source",
                    "target": "target",
                    "sync": "full",
                    "auto-finalize": True,
                    "auto-dismiss": False,
                },
            )
            deadline = time.monotonic() + 20
            while True:
                jobs = qmp(stream, "query-jobs")
                require(len(jobs) == 1 and jobs[0]["id"] == "allocator-copy", jobs)
                if jobs[0]["status"] == "concluded":
                    require("error" not in jobs[0], jobs)
                    break
                require(time.monotonic() < deadline, "private block copy exceeded deadline")
                time.sleep(0.01)
            copy_ns = time.monotonic_ns() - start
            qmp(stream, "job-dismiss", {"id": "allocator-copy"})
            qmp(stream, "quit")
        require(process.wait(timeout=10) == 0, "QEMU did not quit cleanly")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    require(hashlib.sha256(target.read_bytes()).hexdigest() == digest, "private block copy mismatch")
    return {
        "qmp_ready_ns": startup,
        "block_copy_ns": copy_ns,
        "block_copy_bytes": source.stat().st_size,
        "block_copy_sha256": digest,
        "observation": observation,
        "scope": "paused TCG QEMU initialization and QMP block copy; no guest boot or network I/O",
    }


def receive(connection, size):
    output = bytearray()
    while len(output) < size:
        data = connection.recv(size - len(output))
        require(data, "TPM socket closed early")
        output.extend(data)
    return bytes(output)


def pressure(probe, library, label):
    results = {}
    for kind in ("ok", "oom"):
        unit = f"pve-allocator-{label}-{kind}-{uuid.uuid4().hex[:8]}.service"
        properties = [
            "User=65534",
            "Group=65534",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "MemoryHigh=" + ("64M" if kind == "ok" else "128M"),
            "MemoryMax=128M",
            "MemorySwapMax=0",
            "TasksMax=16",
            "RuntimeMaxSec=20s",
            "TimeoutStopSec=3s",
            "OOMPolicy=kill",
            "RemainAfterExit=yes",
        ]
        arguments = ["systemd-run", "--quiet", "--no-block", "--service-type=exec", "--unit=" + unit]
        for property_ in properties:
            arguments.append("--property=" + property_)
        if library:
            arguments.append("--setenv=LD_PRELOAD=" + library)
        arguments.extend([str(probe), "--pressure-" + kind])
        samples, events = [], {}
        pressure_since = None
        relief = None
        command(arguments)
        try:
            deadline = time.monotonic() + 25
            while True:
                state = dict(
                    line.split("=", 1)
                    for line in command(
                        [
                            "systemctl",
                            "show",
                            unit,
                            "--property=ActiveState,SubState,MainPID,Result,"
                            "ExecMainStatus,ExecMainCode,MemoryPeak,ControlGroup,MemoryHigh,MemoryMax,MemorySwapMax",
                        ]
                    ).splitlines()
                )
                if state["MainPID"] != "0":
                    try:
                        pid = int(state["MainPID"])
                        if (Path("/proc") / str(pid) / "exe").resolve() == probe:
                            sample = snapshot(pid)
                            selected(sample, library)
                            samples.append(sample)
                    except FileNotFoundError, ProcessLookupError, KeyError:
                        # Re-observe this same unit; a missing /proc sample is
                        # not permission to launch another pressure process.
                        pass
                cgroup = Path("/sys/fs/cgroup") / state["ControlGroup"].lstrip("/")
                try:
                    if state["ControlGroup"]:
                        events = dict(
                            line.split() for line in (cgroup / "memory.events").read_text().splitlines()
                        )
                except FileNotFoundError:
                    pass
                if kind == "ok" and int(events.get("high", "0")) > 0 and relief is None:
                    if pressure_since is None:
                        pressure_since = time.monotonic()
                    if time.monotonic() - pressure_since >= 0.1:
                        require(
                            int(state["MemoryHigh"]) == 64 * 1024**2, "initial pressure threshold changed"
                        )
                        # Anonymous pages with swap disabled are not reclaimable.
                        # Release only this unit's throttle after observing it,
                        # retaining the same hard memory cap throughout.
                        command(["systemctl", "set-property", "--runtime", unit, "MemoryHigh=128M"])
                        relief = {
                            "observed_high_events": int(events["high"]),
                            "throttled_seconds": time.monotonic() - pressure_since,
                            "new_memory_high_bytes": 128 * 1024**2,
                        }
                if state["SubState"] in {"exited", "failed"} and state["MainPID"] == "0":
                    break
                require(time.monotonic() < deadline, f"pressure unit exceeded deadline: {unit}")
                time.sleep(0.01)
            journal = command(["journalctl", "--quiet", "--no-pager", "-o", "cat", "-u", unit])
            owners = [json.loads(line) for line in journal.splitlines() if line.startswith('{"pid":')]
            require(len(owners) == 1, "pressure process did not identify its malloc provider")
            require(
                owners[0]["malloc_owner"] == library if library else "libc.so.6" in owners[0]["malloc_owner"],
                "pressure process selected another allocator",
            )
            require(samples, "pressure process had no observed mappings")
            require(
                int(state["MemoryHigh"]) == 128 * 1024**2
                and int(state["MemoryMax"]) == 128 * 1024**2
                and state["MemorySwapMax"] == "0",
                "pressure bounds changed",
            )
            if kind == "ok":
                require(state["Result"] == "success" and state["ExecMainStatus"] == "0", state)
                require('{"touched_mib":80}' in journal, "bounded pressure workload did not complete")
                require(int(events.get("high", "0")) > 0, "MemoryHigh pressure was not observed")
                require(relief is not None, "pressure recovery was not exercised")
            else:
                require(state["Result"] == "oom-kill" and state["ExecMainStatus"] == "9", state)
            # PID 1 remains responsive outside the owned memory-limited unit.
            command(["systemctl", "show", "--property=Version"])
            results[kind] = {
                "unit": unit,
                "state": state,
                "memory_events": events,
                "sampled_peak_rss_kib": max(sample["rss_kib"] for sample in samples),
                "sampled_peak_map_count": max(sample["map_count"] for sample in samples),
                "first_observation": samples[0],
                "samples": len(samples),
                "journal": journal,
                "pressure_relief": relief,
            }
        finally:
            # This uniquely named unit contains only the process created above.
            command(["systemctl", "stop", unit])
            reset = subprocess.run(
                ["systemctl", "reset-failed", unit], capture_output=True, text=True, timeout=10
            )
            require(
                reset.returncode == 0
                or command(["systemctl", "show", "--value", "--property=LoadState", unit]) == "not-found",
                "pressure unit cleanup failed",
            )
    return results


def swtpm(directory, environment, library, log):
    state, control, server = directory / "state", directory / "control", directory / "server"
    state.mkdir()
    os.chown(state, 65534, 65534)
    start = time.monotonic_ns()
    with (
        child(
            [
                "swtpm",
                "socket",
                "--tpm2",
                "--tpmstate",
                f"dir={state}",
                "--ctrl",
                f"type=unixio,path={control}",
                "--server",
                f"type=unixio,path={server}",
                "--flags",
                "not-need-init,startup-clear",
            ],
            environment,
            log,
        ) as process,
        connect(server, process) as connection,
    ):
        ready_ns = time.monotonic_ns() - start
        observation = snapshot(process.pid)
        selected(observation, library)
        # TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, TPM_PT_FAMILY_INDICATOR, 1).
        connection.sendall(struct.pack(">HIIIII", 0x8001, 22, 0x17A, 6, 0x100, 1))
        header = receive(connection, 10)
        tag, size, result = struct.unpack(">HII", header)
        require(tag == 0x8001 and 10 <= size <= 65536 and result == 0, "TPM capability failed")
        response = receive(connection, size - 10)
        require(len(response) >= 17, "incomplete TPM capability")
        return {
            "ready_ns": ready_ns,
            "observation": observation,
            "tpm_capability_response": response.hex(),
            "scope": "fresh private TPM startup and capability command; no retained VM TPM identity",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-machine-uuid", required=True)
    parser.add_argument("--allocation-probe", type=Path, required=True)
    parser.add_argument("--payload-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new result file")
    args = parser.parse_args()
    require(os.geteuid() == 0, "run as root only in the selected disposable VM")
    require("QEMU" in Path("/sys/class/dmi/id/sys_vendor").read_text(), "not a QEMU fixture")
    require(
        Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == args.expect_machine_uuid,
        "wrong fixture identity",
    )
    require(
        not Path("/var/lib/particleve/installation.json").exists(),
        "installed host is not a component fixture",
    )
    require(not Path("/etc/ld.so.preload").exists(), "global preload policy is present")
    require(command(["getenforce"]) == "Enforcing", "SELinux must remain enforcing")
    here = Path(__file__).resolve().parent
    pin = json.loads((here / "source.json").read_text())
    require(
        json.loads(Path("/usr/share/hardened_malloc/source.json").read_text()) == pin, "source pin mismatch"
    )
    payload = json.loads(args.payload_record.read_text())
    require(payload["source"] == pin, "inspection source pin mismatch")
    require(
        set(payload["libraries"]) == {"libhardened_malloc.so", "libhardened_malloc-light.so"},
        "inspection must identify both allocator libraries",
    )
    for name, record in payload["libraries"].items():
        require(
            hashlib.sha256((Path("/usr/lib64") / name).read_bytes()).hexdigest() == record["sha256"],
            "library mismatch",
        )
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "GLIBC_TUNABLES"}
    }
    result = {
        "scope": __doc__,
        "kernel": os.uname().release,
        "selinux": command(["getenforce"]),
        "max_map_count_before": Path("/proc/sys/vm/max_map_count").read_text().strip(),
        "source": pin,
        "payload": payload,
        "packages": command(["rpm", "-q", "hardened_malloc", "glibc", "qemu-system-x86-core", "swtpm"]),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "allocation_probe_sha256": hashlib.sha256(args.allocation_probe.read_bytes()).hexdigest(),
        "allocation_source_sha256": hashlib.sha256((here / "allocation-probe.c").read_bytes()).hexdigest(),
        "variants": {},
    }
    with (
        args.output.open("x") as output,
        tempfile.TemporaryDirectory(prefix="pve-alloc-", dir="/run") as temporary,
    ):
        root = Path(temporary)
        root.chmod(0o755)
        try:
            variants = (
                ("glibc", None),
                ("default", "/usr/lib64/libhardened_malloc.so"),
                ("light", "/usr/lib64/libhardened_malloc-light.so"),
            )
            result["variants"] = {label: [] for label, _ in variants}
            result["execution_order"] = []
            for iteration in range(3):
                for label, library in variants[iteration:] + variants[:iteration]:
                    env = environment | ({"LD_PRELOAD": library} if library else {})
                    result["execution_order"].append(label)
                    directory = root / f"{label}-{iteration}"
                    directory.mkdir(mode=0o700)
                    os.chown(directory, 65534, 65534)
                    result["variants"][label].append(
                        {
                            "allocation": allocation(
                                args.allocation_probe.resolve(), env, library, directory / "allocation.log"
                            ),
                            "qemu": qemu(directory, env, library, directory / "qemu.log"),
                            "swtpm": swtpm(directory, env, library, directory / "swtpm.log"),
                        }
                    )
            result["pressure"] = {}
            for label, library in variants:
                result["pressure"][label] = pressure(args.allocation_probe.resolve(), library, label)
            require(not Path("/etc/ld.so.preload").exists(), "global preload changed")
            require(command(["getenforce"]) == "Enforcing", "SELinux changed")
            require(
                Path("/proc/sys/vm/max_map_count").read_text().strip() == result["max_map_count_before"],
                "map limit changed",
            )
            result["status"] = "pass"
        except Exception as error:
            result["status"] = "failed"
            result["error"] = str(error)
            result["component_logs"] = {
                str(path.relative_to(root)): path.read_text() for path in root.rglob("*.log")
            }
            raise
        finally:
            json.dump(result, output, indent=2)
            output.write("\n")
    print(json.dumps({"status": result["status"], "variants": list(result["variants"]), "repetitions": 3}))


if __name__ == "__main__":
    main()
