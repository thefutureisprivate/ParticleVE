"""Compare allocators in the native fwupd service of a selected disposable VM.

Only device discovery is requested. No metadata refresh, firmware installation,
trust enrollment or reboot is performed. Runtime overrides are removed and the
initially inactive service is stopped before returning.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import time
from pathlib import Path

from components import require, snapshot

PROPERTIES = (
    "CapabilityBoundingSet",
    "NoNewPrivileges",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "RestrictAddressFamilies",
    "RestrictNamespaces",
    "ProtectSystem",
    "ProtectHome",
    "ProtectKernelModules",
    "ProtectKernelTunables",
    "ProtectControlGroups",
    "ProtectClock",
    "PrivateTmp",
    "MemoryDenyWriteExecute",
    "RestrictSUIDSGID",
    "User",
    "Group",
)


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, check=True, timeout=30)
    require(not result.stderr.strip(), "native command diagnostics: " + result.stderr.strip())
    return result.stdout.strip()


def state(*properties):
    return dict(
        line.split("=", 1)
        for line in command(
            [
                "systemctl",
                "show",
                "fwupd.service",
                "--property=" + ",".join(properties),
            ]
        ).splitlines()
    )


def secure_execution(pid):
    entries = struct.iter_unpack("=QQ", (Path("/proc") / str(pid) / "auxv").read_bytes())
    secure = [value for tag, value in entries if tag == 23]  # Linux AT_SECURE.
    require(len(secure) == 1 and secure[0] in (0, 1), "invalid fwupd auxiliary vector")
    return secure[0]


def firmware_fingerprints():
    global_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    database_guid = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
    names = [f"{name}-{global_guid}" for name in ("BootNext", "BootOrder", "OsIndications", "PK", "KEK")]
    names.extend(f"{name}-{database_guid}" for name in ("db", "dbx"))
    root = Path("/sys/firmware/efi/efivars")
    require(root.is_dir(), "use the disposable UEFI fixture")
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() if (root / name).exists() else None
        for name in names
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-machine-uuid", required=True)
    parser.add_argument("--payload-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new public result file")
    args = parser.parse_args()
    require(os.geteuid() == 0 and os.uname().machine == "x86_64", "use the disposable x86-64 VM")
    require("QEMU" in Path("/sys/class/dmi/id/sys_vendor").read_text(), "not a QEMU fixture")
    require(
        Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() == args.expect_machine_uuid,
        "wrong fixture identity",
    )
    require(
        not Path("/var/lib/particleve/installation.json").exists(),
        "installed host is not a component fixture",
    )
    require(command(["getenforce"]) == "Enforcing", "SELinux must remain enforcing")
    require(not Path("/etc/ld.so.preload").exists(), "global preload policy is present")
    require(
        state("ActiveState", "SubState") == {"ActiveState": "inactive", "SubState": "dead"},
        "fwupd must initially be inactive",
    )
    here = Path(__file__).resolve().parent
    pin = json.loads((here / "source.json").read_text())
    payload = json.loads(args.payload_record.read_text())
    require(payload["source"] == pin, "source pin mismatch")
    require(
        json.loads(Path("/usr/share/hardened_malloc/source.json").read_text()) == pin,
        "installed pin mismatch",
    )
    require(
        set(payload["libraries"]) == {"libhardened_malloc.so", "libhardened_malloc-light.so"},
        "incomplete payload record",
    )
    for name, record in payload["libraries"].items():
        require(
            hashlib.sha256((Path("/usr/lib64") / name).read_bytes()).hexdigest() == record["sha256"],
            "library payload mismatch",
        )

    directory = Path("/run/systemd/system/fwupd.service.d")
    dropin = directory / "91-particleve-allocator-evaluation.conf"
    require(not dropin.exists(), "allocator override already exists")
    original_unit = command(["systemctl", "cat", "fwupd.service"])
    original_properties = state(*PROPERTIES)
    map_limit = Path("/proc/sys/vm/max_map_count").read_text()
    ca_bundle = Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    ca_digest = hashlib.sha256(ca_bundle.read_bytes()).hexdigest()
    firmware = firmware_fingerprints()
    result = {
        "scope": __doc__,
        "kernel": os.uname().release,
        "source": pin,
        "payload": payload,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "observer_sha256": hashlib.sha256((here / "components.py").read_bytes()).hexdigest(),
        "native_unit_sha256": hashlib.sha256(original_unit.encode()).hexdigest(),
        "native_properties": original_properties,
        "packages": command(
            ["rpm", "-q", "fwupd", "glibc", "hardened_malloc", "systemd", "selinux-policy-targeted"]
        ),
        "max_map_count": map_limit.strip(),
        "system_ca_bundle_sha256": ca_digest,
        "firmware_variable_fingerprints": firmware,
        "variants": {label: [] for label in ("glibc", "default", "light")},
        "execution_order": [],
    }
    created_directory = not directory.exists()
    baseline = None
    device_ids = None
    variants = (
        ("glibc", None),
        ("default", "/usr/lib64/libhardened_malloc.so"),
        ("light", "/usr/lib64/libhardened_malloc-light.so"),
    )
    with args.output.open("x") as output:
        start_requested = False
        try:
            directory.mkdir(parents=True, exist_ok=True)
            for iteration in range(3):
                for label, library in variants[iteration:] + variants[:iteration]:
                    entry = {"round": iteration, "selection": library}
                    result["variants"][label].append(entry)
                    result["execution_order"].append(label)
                    require(
                        state("ActiveState")["ActiveState"] == "inactive",
                        "fwupd was activated outside this attempt",
                    )
                    dropin.write_text(
                        "[Service]\n"
                        + (
                            "Environment=LD_PRELOAD=" + library + "\n"
                            if library
                            else "UnsetEnvironment=LD_PRELOAD\n"
                        )
                    )
                    command(["restorecon", str(dropin)])
                    command(["systemctl", "daemon-reload"])
                    start = time.monotonic_ns()
                    start_requested = True
                    command(["systemctl", "start", "fwupd.service"])
                    entry["native_start_ready_ns"] = time.monotonic_ns() - start
                    native = state(
                        "ActiveState", "SubState", "MainPID", "InvocationID", "Result", "Environment"
                    )
                    entry["state"] = native
                    require(native["ActiveState"] == "active" and native["SubState"] == "running", native)
                    require(state(*PROPERTIES) == original_properties, "fwupd confinement changed")
                    pid = int(native["MainPID"])
                    observation = snapshot(pid)
                    entry["observation"] = observation
                    entry["at_secure"] = secure_execution(pid)
                    require(
                        observation["selinux"].split(":")[2] == "fwupd_t",
                        "fwupd lost its native SELinux domain",
                    )
                    require(observation["seccomp"] == "2", "fwupd lost its seccomp filter")
                    mappings = observation["allocator_mappings"]
                    require(bool(mappings) == bool(library), "fwupd did not load the selected allocator")
                    if library:
                        require(
                            all(line.endswith(library) for line in mappings), "fwupd loaded another allocator"
                        )
                    if baseline is None:
                        baseline = observation
                    require(
                        all(
                            observation[key] == baseline[key]
                            for key in (
                                "selinux",
                                "capabilities",
                                "uids",
                                "gids",
                                "groups",
                                "no_new_privileges",
                                "seccomp",
                            )
                        ),
                        "fwupd process authority changed",
                    )

                    start = time.monotonic_ns()
                    inventory = json.loads(
                        command(
                            [
                                "fwupdmgr",
                                "--json",
                                "--no-unreported-check",
                                "--no-metadata-check",
                                "--no-remote-check",
                                "get-devices",
                            ]
                        )
                    )
                    entry["inventory_ns"] = time.monotonic_ns() - start
                    require(isinstance(inventory.get("Devices"), list), "invalid native device inventory")
                    identities = sorted(device["DeviceId"] for device in inventory["Devices"])
                    if device_ids is None:
                        device_ids = identities
                    require(identities == device_ids, "device inventory changed across allocator cases")
                    entry["device_ids"] = identities
                    entry["inventory_sha256"] = hashlib.sha256(
                        json.dumps(inventory, sort_keys=True).encode()
                    ).hexdigest()
                    interface = json.loads(
                        command(
                            [
                                "busctl",
                                "--json=short",
                                "call",
                                "org.freedesktop.fwupd",
                                "/",
                                "org.freedesktop.fwupd",
                                "GetDevices",
                            ]
                        )
                    )
                    require(
                        interface["type"] == "aa{sv}" and len(interface["data"]) == 1,
                        "unexpected D-Bus reply",
                    )
                    require(
                        sorted(device["DeviceId"]["data"] for device in interface["data"][0]) == identities,
                        "CLI and D-Bus inventory disagree",
                    )
                    entry["discovery"] = "pass"
                    command(["systemctl", "stop", "fwupd.service"])
                    start_requested = False
                    require(
                        state("ActiveState", "SubState") == {"ActiveState": "inactive", "SubState": "dead"},
                        "fwupd did not stop cleanly",
                    )
                    entry["journal"] = command(
                        [
                            "journalctl",
                            "--quiet",
                            "--no-pager",
                            "-o",
                            "short-precise",
                            "_SYSTEMD_INVOCATION_ID=" + native["InvocationID"],
                        ]
                    )
                    require(firmware_fingerprints() == firmware, "firmware selection/trust variables changed")
                    entry["firmware_variables_unchanged"] = True
            result["status"] = "pass"
        except Exception as error:
            result["status"] = "failed"
            result["error"] = str(error)
            raise
        finally:
            try:
                if start_requested:
                    command(["systemctl", "stop", "fwupd.service"])
                if dropin.exists():
                    dropin.unlink()
                if created_directory and directory.exists() and not list(directory.iterdir()):
                    directory.rmdir()
                command(["systemctl", "daemon-reload"])
                require(
                    command(["systemctl", "cat", "fwupd.service"]) == original_unit,
                    "native unit was not restored",
                )
                require(state(*PROPERTIES) == original_properties, "native properties were not restored")
                require(
                    state("ActiveState", "SubState") == {"ActiveState": "inactive", "SubState": "dead"},
                    "original service state was not restored",
                )
                require(command(["getenforce"]) == "Enforcing", "SELinux changed")
                require(not Path("/etc/ld.so.preload").exists(), "global preload changed")
                require(Path("/proc/sys/vm/max_map_count").read_text() == map_limit, "map limit changed")
                require(
                    hashlib.sha256(ca_bundle.read_bytes()).hexdigest() == ca_digest,
                    "system CA bundle changed",
                )
                require(firmware_fingerprints() == firmware, "firmware variables changed")
                result["restored"] = True
            except Exception as error:
                result["status"] = "failed"
                result["cleanup_error"] = str(error)
                raise
            finally:
                json.dump(result, output, indent=2)
                output.write("\n")
    print(
        json.dumps(
            {
                "status": result["status"],
                "cases": 9,
                "device_count": len(device_ids),
                "restored": result["restored"],
            }
        )
    )


if __name__ == "__main__":
    main()
