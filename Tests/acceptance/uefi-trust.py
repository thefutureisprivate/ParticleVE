"""Prepare and run an isolated OVMF trust-transition fixture, without an OS or TPM."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import uuid
from pathlib import Path

IMAGE_BYTES = 64 * 1024 * 1024
DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
CASES = (
    ("initial", "old", True),
    ("initial", "new", False),
    ("initial", "unrelated", False),
    ("overlap", "old", True),
    ("overlap", "new", True),
    ("overlap", "dual", True),
    ("new-only", "old", False),
    ("new-only", "new", True),
    ("new-only", "dual", True),
    ("cert-revoked", "old", False),
    ("cert-revoked", "new", True),
    ("cert-revoked", "dual", False),
    ("hash-revoked", "old", False),
    ("hash-revoked", "new", True),
    ("hash-revoked", "dual", False),
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(arguments, *, timeout=60, data=None):
    result = subprocess.run(arguments, input=data, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout)[-8192:]
        raise RuntimeError(f"{arguments[0]} failed ({result.returncode}): {detail}")
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def variables(path):
    data = json.loads(path.read_text())
    assert data["version"] == 2
    result = {(row["guid"], row["name"]): row for row in data["variables"]}
    assert len(result) == len(data["variables"])
    return result


def without_certificate(data, certificate):
    """Remove one generated X.509 entry, preserving every unrelated ESL byte."""
    source, result, removed, offset = bytes.fromhex(data), bytearray(), 0, 0
    certificate_type = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le
    while offset < len(source):
        assert len(source) - offset >= 28
        kind = source[offset : offset + 16]
        size, header, entry = struct.unpack_from("<III", source, offset + 16)
        assert kind == certificate_type and header == 0 and entry > 16
        assert 28 <= size <= len(source) - offset and (size - 28) % entry == 0
        kept = bytearray()
        for start in range(offset + 28, offset + size, entry):
            row = source[start : start + entry]
            if row[16:] == certificate:
                removed += 1
            else:
                kept.extend(row)
        if kept:
            result.extend(kind + struct.pack("<III", 28 + len(kept), 0, entry) + kept)
        offset += size
    assert removed == 1 and result
    return result.hex()


def prepare(args):
    for tool in (
        "openssl",
        "gcc",
        "ld",
        "objcopy",
        "sbsign",
        "sbverify",
        "virt-fw-vars",
        "pesign",
        "mkfs.fat",
        "mmd",
        "mcopy",
        "sfdisk",
    ):
        assert shutil.which(tool), f"missing preparation tool: {tool}"
    work = args.work_directory.resolve()
    assert "," not in str(work), "QEMU option paths cannot contain commas"
    for path in (args.firmware_code, args.firmware_vars):
        assert path.is_file() and 0 < path.stat().st_size <= 8 * 1024 * 1024
    assert args.firmware_code.stat().st_size + args.firmware_vars.stat().st_size == 4 * 1024 * 1024, (
        "select a matching current 4 MiB raw OVMF code/variable pair"
    )
    work.mkdir(mode=0o700)
    source = Path(__file__).with_name("efi-trust.c")
    original = {str(path.resolve()): digest(path) for path in (args.firmware_code, args.firmware_vars)}
    shutil.copyfile(args.firmware_code, work / "code.fd")
    shutil.copyfile(args.firmware_vars, work / "blank.fd")
    keys, images = work / "keys", work / "images"
    keys.mkdir(mode=0o700)
    images.mkdir(mode=0o700)
    owners = {name: str(uuid.uuid4()) for name in ("recovery", "old", "new", "unrelated")}
    for name in owners:
        command(
            [
                "openssl",
                "req",
                "-new",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-subj",
                f"/CN=ParticleVE disposable firmware {name}/",
                "-keyout",
                str(keys / f"{name}.key"),
                "-out",
                str(keys / f"{name}.crt"),
            ]
        )
    # These objects use only the EFI ABI and in/out instructions in this fixture.
    (work / "reloc.S").write_text('.section .reloc, "a"\n.balign 4\n.long 0\n.long 12\n.word 0\n.word 0\n')
    command(["gcc", "-c", "-o", str(work / "reloc.o"), str(work / "reloc.S")])
    for name, defines in (
        ("parent", ["-DPVE_TRUST_PARENT"]),
        ("old", []),
        ("new", ["-DPVE_TRUST_CHILD_NEW"]),
    ):
        command(
            [
                "gcc",
                "-DGNU_EFI_USE_MS_ABI",
                *defines,
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fpie",
                "-ffreestanding",
                "-fno-builtin",
                "-fshort-wchar",
                "-mno-red-zone",
                "-fno-stack-protector",
                "-fno-asynchronous-unwind-tables",
                "-I/usr/include/efi",
                "-I/usr/include/efi/x86_64",
                "-c",
                str(source),
                "-o",
                str(work / f"{name}.o"),
            ]
        )
        command(
            [
                "ld",
                "--fatal-warnings",
                "-shared",
                "-Bsymbolic",
                "-z",
                "noexecstack",
                "-z",
                "separate-code",
                "-T",
                "/usr/lib/elf_x86_64_efi.lds",
                "--entry",
                "efi_main",
                str(work / f"{name}.o"),
                str(work / "reloc.o"),
                "-o",
                str(work / f"{name}.so"),
            ]
        )
        command(
            [
                "objcopy",
                "--strip-all",
                "-j",
                ".text",
                "-j",
                ".data",
                "-j",
                ".rodata",
                "-j",
                ".dynamic",
                "-j",
                ".dynsym",
                "-j",
                ".reloc",
                "--file-alignment=512",
                "--section-alignment=4096",
                "--output-target=efi-app-x86_64",
                str(work / f"{name}.so"),
                str(work / f"{name}-unsigned.efi"),
            ]
        )
    for image, authority, input_name in (
        ("parent", "recovery", "parent-unsigned"),
        ("old", "old", "old-unsigned"),
        ("new", "new", "new-unsigned"),
        ("unrelated", "unrelated", "old-unsigned"),
        ("dual", "new", "old"),
    ):
        command(
            [
                "sbsign",
                "--key",
                str(keys / f"{authority}.key"),
                "--cert",
                str(keys / f"{authority}.crt"),
                "--output",
                str(work / f"{image}.efi"),
                str(work / f"{input_name}.efi"),
            ]
        )
        command(["sbverify", "--cert", str(keys / f"{authority}.crt"), str(work / f"{image}.efi")])

    def firmware(name, previous, options):
        response = command(
            [
                "virt-fw-vars",
                "--input",
                str(work / f"{previous}.fd"),
                *options,
                "--output",
                str(work / f"{name}.fd"),
                "--output-json",
                str(work / f"{name}.json"),
            ]
        )
        assert not any(word in (response.stdout + response.stderr).lower() for word in ("warning", "error"))

    firmware(
        "initial",
        "blank",
        [
            "--set-pk",
            owners["recovery"],
            str(keys / "recovery.crt"),
            "--add-kek",
            owners["recovery"],
            str(keys / "recovery.crt"),
            "--add-db",
            owners["recovery"],
            str(keys / "recovery.crt"),
            "--add-db",
            owners["old"],
            str(keys / "old.crt"),
            "--sb",
        ],
    )
    firmware("overlap", "initial", ["--add-db", owners["new"], str(keys / "new.crt")])
    overlap = variables(work / "overlap.json")
    db = dict(overlap[DB_GUID, "db"])
    der = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(keys / "old.crt"),
            "-outform",
            "DER",
        ],
        capture_output=True,
        check=True,
        timeout=15,
    ).stdout
    db["data"] = without_certificate(db["data"], der)
    write_json(work / "new-db.json", {"version": 2, "variables": [db]})
    firmware("new-only", "overlap", ["--set-json", str(work / "new-db.json")])
    firmware("cert-revoked", "overlap", ["--add-dbx-cert", owners["old"], str(keys / "old.crt")])

    def authenticode(image):
        response = command(["pesign", "--hash", "--padding", "--digest-type=sha256", "--in", str(image)])
        hashes = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", response.stdout)
        assert len(hashes) == 1 and not response.stderr.strip()
        return hashes[0].lower()

    old_hash = authenticode(work / "old.efi")
    assert authenticode(work / "dual.efi") == old_hash
    assert authenticode(work / "new.efi") != old_hash and digest(work / "old.efi") != old_hash
    firmware("hash-revoked", "overlap", ["--add-dbx-hash", owners["old"], old_hash])
    for name, allowed in (("new-only", {"db"}), ("cert-revoked", {"dbx"}), ("hash-revoked", {"dbx"})):
        after = variables(work / f"{name}.json")
        changed = {key[1] for key in overlap.keys() | after.keys() if overlap.get(key) != after.get(key)}
        assert changed == allowed, (name, changed)
    for name in ("old", "new", "unrelated", "dual"):
        image = images / f"{name}.raw"
        with image.open("xb") as output:
            output.truncate(IMAGE_BYTES)
        # Use a GPT ESP on both transports, keeping the FAT payload clear of
        # the backup GPT. Partition only this newly created regular file.
        esp_type = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        command(
            ["sfdisk", "--quiet", "--no-reread", "--no-tell-kernel", str(image)],
            data=f"label: gpt\nstart=2048,size=122880,type={esp_type}\n",
        )
        table = json.loads(command(["sfdisk", "--json", str(image)]).stdout)["partitiontable"]
        assert table["label"] == "gpt" and table["sectorsize"] == 512
        assert len(table["partitions"]) == 1
        partition = table["partitions"][0]
        assert partition["start"] == 2048 and partition["size"] == 122880
        assert partition["type"].lower() == esp_type
        fat = work / f"{name}.fat"
        with fat.open("xb") as output:
            output.truncate(60 * 1024 * 1024)
        command(["mkfs.fat", "-F", "32", "-h", "2048", str(fat)])
        command(["mmd", "-i", str(fat), "::/EFI", "::/EFI/BOOT", "::/EFI/ParticleVE"])
        command(["mcopy", "-i", str(fat), str(work / "parent.efi"), "::/EFI/BOOT/BOOTX64.EFI"])
        command(["mcopy", "-i", str(fat), str(work / f"{name}.efi"), "::/EFI/ParticleVE/candidate.efi"])
        with image.open("r+b") as output, fat.open("rb") as source_image:
            output.seek(1024 * 1024)
            shutil.copyfileobj(source_image, output, length=1024 * 1024)
        fat.unlink()
    assert all(digest(Path(path)) == value for path, value in original.items())
    for key in keys.glob("*.key"):
        key.unlink()
    paths = [
        work / "code.fd",
        *(work / f"{state}.fd" for state in {row[0] for row in CASES}),
        *images.glob("*.raw"),
    ]
    write_json(
        work / "identity.json",
        {
            "schema": 1,
            "fixture": "particleve-uefi-trust",
            "uuid": str(uuid.uuid4()),
            "input_sha256": original,
            "probe_source_sha256": digest(source),
            "old_authenticode_sha256": old_hash,
            "harness_sha256": digest(Path(__file__)),
            "sha256": {str(path.relative_to(work)): digest(path) for path in paths},
            "private_keys_removed": not list(keys.glob("*.key")),
            "physical_devices": False,
        },
    )
    print(json.dumps({"prepared": str(work), "private_keys_removed": True}))


def run(args):
    work = args.work_directory.resolve(strict=True)
    assert "," not in str(work), "QEMU option paths cannot contain commas"
    identity = json.loads((work / "identity.json").read_text())
    assert identity["schema"] == 1 and identity["fixture"] == "particleve-uefi-trust"
    assert identity["private_keys_removed"] and not identity["physical_devices"]
    rows = [line.split() for line in Path("/proc/self/uid_map").read_text().splitlines()]
    assert os.geteuid() == 0 and rows[0][0] == "0" and rows[0][1] != "0", "use a rootless user namespace"
    with open("/dev/kvm", "rb+", buffering=0) as device:
        assert fcntl.ioctl(device, 0xAE00, 0) == 12
    for path, expected in identity["sha256"].items():
        assert (work / path).resolve().is_relative_to(work) and digest(work / path) == expected
    results = []
    cases = [(state, image, accepted, "disk") for state, image, accepted in CASES]
    cases.extend(("hash-revoked", image, image == "new", "usb") for image in ("old", "new", "dual"))
    for state, image, accepted, transport in cases:
        case = work / f"case-{state}-{image}-{transport}"
        case.mkdir(mode=0o700)
        shutil.copyfile(work / f"{state}.fd", case / "vars.fd")
        argv = [
            "/usr/bin/prlimit",
            "--fsize=8388608",
            "--",
            "/usr/bin/qemu-system-x86_64",
            "-name",
            "particleve-uefi-trust-" + identity["uuid"],
            "-uuid",
            identity["uuid"],
            "-machine",
            "q35,smm=on",
            "-accel",
            "kvm",
            "-cpu",
            "host",
            "-m",
            "512",
            "-smp",
            "1",
            "-nodefaults",
            "-no-user-config",
            "-nic",
            "none",
            "-global",
            "driver=cfi.pflash01,property=secure,value=on",
            "-drive",
            "if=pflash,format=raw,unit=0,readonly=on,file=" + str(work / "code.fd"),
            "-drive",
            "if=pflash,format=raw,unit=1,file=" + str(case / "vars.fd"),
            "-drive",
            "if=none,id=probe,format=raw,readonly=on,file=" + str(work / "images" / f"{image}.raw"),
            "-display",
            "none",
            "-serial",
            "file:" + str(case / "serial.log"),
            "-monitor",
            "none",
            "-no-reboot",
            "-sandbox",
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
        if transport == "usb":
            controller = "qemu-xhci" if args.usb_controller == "xhci" else "usb-ehci"
            argv.extend(
                [
                    "-device",
                    controller + ",id=usb",
                    "-device",
                    "usb-storage,bus=usb.0,drive=probe,bootindex=1,removable=on",
                ]
            )
        else:
            argv.extend(["-device", "virtio-blk-pci,drive=probe,bootindex=1"])
        write_json(case / "command.json", argv)
        with (case / "qemu.log").open("wb") as log, subprocess.Popen(argv, stdout=log, stderr=log) as process:
            try:
                returncode = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise
        # A firmware UART has no UTF-8 contract. Preserve its bytes while
        # matching the probe's exact ASCII markers.
        text = (case / "serial.log").read_bytes().decode("latin-1")
        observed = re.findall(r"ParticleVE trust fixture: load_status=(0x[0-9a-f]{16})", text)
        record = {
            "state": state,
            "image": image,
            "transport": transport,
            "expected_accept": accepted,
            "load_status": observed,
            "qemu_exit": returncode,
            "usb_controller": args.usb_controller if transport == "usb" else None,
        }
        write_json(case / "result.json", record)
        assert returncode == 0 and text.count("secureboot=1 setup=0") == 1, record
        # UEFI 2.11 LoadImage distinguishes a prohibited load (ACCESS_DENIED)
        # from a loaded image prohibited from starting (SECURITY_VIOLATION).
        # Missing, malformed, unsupported or unreadable images are not refusals.
        statuses = {"0x0000000000000000"} if accepted else {"0x800000000000000f", "0x800000000000001a"}
        assert len(observed) == 1 and observed[0] in statuses, record
        assert text.count("child_entered=") == int(accepted), record
        assert text.count("recovery_reached=1") == 1, record
        if accepted:
            assert text.count("start_status=0x0000000000000000") == 1, record
        results.append(record)
        print(json.dumps(record), flush=True)
    for path, expected in identity["sha256"].items():
        assert digest(work / path) == expected
    write_json(
        work / "result.json",
        {
            "result": "pass",
            "cases": results,
            "inputs_unchanged": True,
            "run_harness_sha256": digest(Path(__file__)),
            "usb_controller": args.usb_controller,
            "scope": "OVMF db/dbx and EFI recovery; no OS, TPM, storage or physical firmware acceptance",
        },
    )


def inspect(args):
    """Read back effective public trust databases after every completed boot."""
    work = args.work_directory.resolve(strict=True)
    result = json.loads((work / "result.json").read_text())
    assert result["result"] == "pass" and len(result["cases"]) == len(CASES) + 3
    global_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
    for row in result["cases"]:
        state, image, transport = row["state"], row["image"], row["transport"]
        case = work / f"case-{state}-{image}-{transport}"
        output = case / "variables.json"
        command(["virt-fw-vars", "--input", str(case / "vars.fd"), "--output-json", str(output)])
        expected = variables(work / f"{state}.json")
        actual = variables(output)
        for key in ((global_guid, "PK"), (global_guid, "KEK"), (DB_GUID, "db"), (DB_GUID, "dbx")):
            before, after = expected.get(key), actual.get(key)
            assert (before or {}).get("data", "") == (after or {}).get("data", ""), (case, key)
            if before:
                assert before["attr"] == after["attr"], (case, key)
        row["effective_pk_kek_db_dbx_readback"] = "unchanged from reviewed case input"
    result["effective_trust_readback"] = "pass"
    result["authenticated_variable_update_transport"] = "not exercised; private offline fixture provisioning"
    write_json(work / "result.json", result)
    print(json.dumps({"effective_trust_readback": "pass", "cases": len(result["cases"])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    setup = subs.add_parser(
        "prepare",
        help="requires GCC/gnu-efi, OpenSSL, sbsigntools, pesign, virt-firmware and FAT/GPT tools",
    )
    setup.add_argument("--firmware-code", type=Path, required=True)
    setup.add_argument("--firmware-vars", type=Path, required=True, help="blank OVMF variable template")
    execution = subs.add_parser("run", help="run public fixtures in a rootless user namespace")
    execution.add_argument("--usb-controller", choices=("xhci", "ehci"), default="xhci")
    for sub in (setup, execution, subs.add_parser("inspect", help="read back variables with virt-fw-vars")):
        sub.add_argument("--work-directory", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    {"prepare": prepare, "run": run, "inspect": inspect}[args.action](args)


if __name__ == "__main__":
    main()
