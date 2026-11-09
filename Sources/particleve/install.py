"""Explicit, reviewed installation and disk replacement from an owner recovery environment."""

import base64
import json
import os
import shutil
import stat
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from . import inventory, network
from .common import (
    Error,
    array_uuid,
    atomic_write,
    digest,
    hash_file,
    lock,
    read_json,
    require,
    run,
    write_json,
)
from .layout import MIB, calculate, os_label, sfdisk_script
from .linux import Linux
from .release import verify_directory

TPM_PUBLIC_KEY = "/usr/lib/particleve/trust/pcr-public-key.pem"


def plan(config, release):
    report = inventory.collect(config)
    require(
        report["ok"],
        "preflight failed: "
        + "; ".join(c["name"] + ": " + c["detail"] for c in report["checks"] if not c["ok"]),
    )
    return calculate(config, report["devices"], release)


def validate_plan(config, release, proposed, confirmation):
    original = {k: v for k, v in proposed.items() if k != "confirmation"}
    require(
        confirmation == proposed["confirmation"] == digest(original), "plan confirmation hash does not match"
    )
    require(proposed["config_sha256"] == digest(config), "configuration differs from reviewed plan")
    require(proposed["release_sha256"] == digest(release), "release differs from reviewed plan")
    require(
        [d["path"] for d in proposed["devices"]] == [d["path"] for d in config["disks"]],
        "disk selection changed",
    )
    require(
        proposed.get("storage_admission") == "uefi-witness-v1",
        "review a fresh installation plan with storage admission",
    )
    require(
        str(uuid.UUID(proposed["installation_uuid"])) == proposed["installation_uuid"],
        "invalid installation UUID",
    )
    current = plan(config, release)
    unique = set()
    for expected, actual in zip(proposed["devices"], current["devices"], strict=True):
        require(
            expected["observed"] == actual["observed"],
            "disk identity, geometry or capacity changed after planning",
        )
        for field in ("path", "role", "serial"):
            require(expected[field] == actual[field], f"disk {field} changed")
        for partition, calculated in zip(expected["partitions"], actual["partitions"], strict=True):
            for field in ("number", "role", "offset", "size", "type", "label"):
                require(
                    partition[field] == calculated[field], f"partition {field} differs from calculated layout"
                )
            require(str(uuid.UUID(partition["uuid"])) == partition["uuid"], "invalid partition UUID")
            if partition["role"].startswith("a_"):
                require(partition["uuid"] == calculated["uuid"], "verified OS partition UUID changed")
            else:
                require(partition["uuid"] not in unique, "ESP/writable partition UUID must be unique")
                unique.add(partition["uuid"])
        require(str(uuid.UUID(expected["disk_uuid"])) == expected["disk_uuid"], "invalid disk UUID")
        require(expected["disk_uuid"] not in unique, "disk UUID must be unique")
        unique.add(expected["disk_uuid"])
        nodes = inventory.walk(inventory.block_tree(expected["path"]))
        require(
            not any((n.get("partlabel") or "").startswith("ParticleVE") for n in nodes),
            "fresh install refuses existing/partial ParticleVE storage; use owner recovery or replacement",
        )


def partition(device):
    run(
        ["sfdisk", "--lock=yes", "--wipe=always", "--wipe-partitions=always", device["path"]],
        input=sfdisk_script(device),
    )
    run(["udevadm", "settle"])


def member(device, role):
    number = next(p["number"] for p in device["partitions"] if p["role"] == role)
    return inventory.partition_path(device["path"], number)


def write_os(device, release, directory):
    for kind in ("verity_sig", "verity", "usr"):
        item = release["artifacts"][kind]
        target = member(device, f"a_{kind}")
        run(
            [
                "dd",
                f"if={Path(directory) / item['file']}",
                f"of={target}",
                "bs=4M",
                "conv=fsync,notrunc",
                "status=none",
            ],
            timeout=3600,
        )
        require(hash_file(target, item["size"]) == item["sha256"], f"installed {kind} failed readback")


def luks_uuid(name):
    return run(["cryptsetup", "luksUUID", f"/dev/md/{name}"]).stdout.strip()


def validate_keyfile(path):
    path = Path(path)
    st = path.stat()
    require(
        stat.S_ISREG(st.st_mode)
        and not path.is_symlink()
        and st.st_uid == 0
        and stat.S_IMODE(st.st_mode) == 0o600,
        "recovery key must be a root-owned regular file with mode 0600",
    )
    require(
        path.resolve(strict=True).is_relative_to("/run"),
        "keep the independent recovery key in /run, outside installed storage",
    )
    require(16 <= st.st_size <= 4096, "recovery key must be 16..4096 bytes")
    require(
        all(32 <= byte <= 126 for byte in path.read_bytes()),
        "recovery passphrase must be printable ASCII without a trailing newline for console unlock",
    )


def enroll_source(source, keyfile):
    inventory.measured_boot(normal=True)
    run(
        [
            "systemd-cryptenroll",
            f"--unlock-key-file={keyfile}",
            "--tpm2-device=auto",
            "--tpm2-pcrs=7",
            "--tpm2-pcrlock=",
            f"--tpm2-public-key={TPM_PUBLIC_KEY}",
            "--tpm2-public-key-pcrs=11",
            source,
        ],
        timeout=300,
    )
    verify_tpm_policy(source)


def verify_tpm_policy(source):
    public_key = base64.b64encode(Path(TPM_PUBLIC_KEY).read_bytes()).decode()
    tokens = json.loads(run(["cryptsetup", "luksDump", "--dump-json-metadata", source]).stdout)["tokens"]
    require(
        any(
            token.get("type") == "systemd-tpm2"
            and token.get("tpm2-pcrs") == [7]
            and token.get("tpm2-pcr-bank") == "sha256"
            and token.get("tpm2_pubkey_pcrs") == [11]
            and token.get("tpm2_pubkey") == public_key
            and token.get("keyslots")
            and not token.get("tpm2_pcrlock", False)
            and not token.get("tpm2-pin", False)
            for token in tokens.values()
        ),
        "TPM enrollment does not match PCR7 plus signed-PCR11 without pcrlock or PIN",
    )


def format_encrypted(source, name, keyfile, *, enroll):
    run(
        [
            "cryptsetup",
            "luksFormat",
            "--type=luks2",
            "--batch-mode",
            "--label",
            name,
            "--key-file",
            keyfile,
            source,
        ],
        timeout=300,
    )
    run(["cryptsetup", "open", "--key-file", keyfile, source, name], timeout=300)
    if enroll:
        enroll_source(source, keyfile)
    return run(["cryptsetup", "luksUUID", source]).stdout.strip()


def block_uuid(path, field="UUID"):
    return run(["blkid", "-s", field, "-o", "value", path]).stdout.strip()


def enrollment_uuids(manifest):
    return sorted([d["state_luks_uuid"] for d in manifest["devices"]] + [manifest["swap"]["luks_uuid"]])


def crypttab(manifest):
    return (
        "".join(
            f"particleve-state-{d['role']} UUID={d['state_luks_uuid']} - "
            "noauto,tpm2-device=auto,x-initrd.attach,nofail,x-systemd.device-timeout=30s\n"
            for d in manifest["devices"]
        )
        + f"particleve-swap UUID={manifest['swap']['luks_uuid']} - tpm2-device=auto\n"
    )


def replace_btrfs(devid, mapper):
    # The caller/service must own the copy until it finishes. Backgrounding lets
    # service teardown cancel the scrub ioctl before the replacement completes.
    run(["btrfs", "replace", "start", "-B", str(devid), mapper, "/"], timeout=None)


def enroll_tpm(backend, keyfile, state):
    """Bind PCR7 from the normal verified boot, never from the recovery installer."""
    validate_keyfile(keyfile)
    require(not state["pending"], "finish or cancel the pending OS transaction before TPM enrollment")
    require(
        not (backend.directory / "commissioned.json").exists() or state["maintenance"],
        "enter persistent maintenance before changing a commissioned host's TPM policy",
    )
    require(inventory.secure_boot(), "TPM enrollment requires the normal Secure Boot chain")
    backend.check_storage(healthy=True)
    backend.check_firmware_clear()
    release = backend.release(backend.current_version())
    for role in ("a", "b"):
        require(
            backend.verify_disk(role, release, boot=True), "verify both current boot paths before enrollment"
        )
    for device in backend.manifest["devices"]:
        enroll_source(member(device, "state"), keyfile)
    enroll_source("/dev/md/particleve-swap", keyfile)
    # Native cryptenroll reuses an existing matching policy. Interrupted attempts
    # can be repeated; no recovery slot or existing TPM slot is wiped here.
    write_json(
        backend.directory / "tpm-enrollment.json",
        {
            "schema": 1,
            "policy": backend.config["tpm_policy"],
            "luks_uuids": enrollment_uuids(backend.manifest),
            "image_version": backend.current_version(),
            "boot_id": backend.boot_id(),
            "recorded_at": datetime.now(UTC).isoformat(),
        },
    )
    return {
        "action": "tpm-enrolled",
        "policy": backend.config["tpm_policy"],
        "next": "test unattended unlock from both boot disks before commissioning",
    }


def create_writable(proposed, keyfile):
    from .storage import members

    for device in proposed["devices"]:
        name = f"particleve-state-{device['role']}"
        device["state_luks_uuid"] = format_encrypted(member(device, "state"), name, keyfile, enroll=False)
    state_paths = [f"/dev/mapper/particleve-state-{d['role']}" for d in proposed["devices"]]
    run(
        ["mkfs.btrfs", "--data=raid1", "--metadata=raid1", "--label=ParticleVE-root", *state_paths],
        timeout=600,
    )
    observed = members(run(["btrfs", "filesystem", "show", "--raw", state_paths[0]]).stdout)
    require(len(observed) == 2, "new Btrfs mirror does not report two devices")
    for device in proposed["devices"]:
        mapper = f"/dev/mapper/particleve-state-{device['role']}"
        matching = [d for d in observed if Path(d["path"]).resolve() == Path(mapper).resolve()]
        require(len(matching) == 1, "cannot identify new Btrfs device")
        device["btrfs_devid"] = matching[0]["devid"]
        device["btrfs_device_uuid"] = block_uuid(mapper, "UUID_SUB")
    swap_md = "/dev/md/particleve-swap"
    run(
        [
            "mdadm",
            "--create",
            swap_md,
            "--metadata=1.2",
            "--level=1",
            "--raid-devices=2",
            "--bitmap=internal",
            "--homehost=any",
            "--name=particleve-swap",
            *[member(d, "swap") for d in proposed["devices"]],
        ],
        timeout=300,
    )
    swap_luks = format_encrypted(swap_md, "particleve-swap", keyfile, enroll=False)
    run(["mkswap", "-L", "ParticleVE-swap", "/dev/mapper/particleve-swap"])
    return {
        "btrfs": {
            "uuid": block_uuid(state_paths[0]),
            "data": "raid1",
            "metadata": "raid1",
            "factory_reset": False,
            "var_subvolume": "var",
        },
        "swap": {
            "md_uuid": array_uuid("particleve-swap"),
            "luks_uuid": swap_luks,
            "uuid": block_uuid("/dev/mapper/particleve-swap"),
        },
    }


def install(config, release_directory, proposed, confirmation, keyfile, *, keyring, certificate):
    require(os.geteuid() == 0, "installation requires root in the owner recovery environment")
    from .admission import VARIABLE

    require(
        not VARIABLE.exists(), "existing firmware storage witness requires owner recovery before reinstall"
    )
    validate_keyfile(keyfile)
    release = verify_directory(release_directory, keyring, certificate)
    validate_plan(config, release, proposed, confirmation)
    require(
        not any(Path(f"/dev/mapper/particleve-state-{role}").exists() for role in ("a", "b")),
        "state storage is already active",
    )
    with lock("/run/particleve-installer"):
        write_json("/run/particleve-installer/plan.json", proposed)
        for device in proposed["devices"]:
            require(
                inventory.observe_disk(device, unused=True) == device["observed"], "disk changed before write"
            )
            partition(device)
            run(["mkfs.vfat", "-F", "32", "-n", "PARTICLEVE", member(device, "esp")])
            write_os(device, release, release_directory)
        recorded_storage = create_writable(proposed, keyfile)
        with tempfile.TemporaryDirectory(prefix="particleve-root-", dir="/run") as rootdir:
            root = Path(rootdir)
            run(["mount", "-t", "btrfs", "-o", "compress=zstd:1", "/dev/mapper/particleve-state-a", root])
            try:
                run(["btrfs", "subvolume", "create", root / "var"])
                with tempfile.TemporaryDirectory(prefix="particleve-usr-", dir="/run") as usr:
                    raw = Path(release_directory) / release["artifacts"]["usr"]["file"]
                    verity = Path(release_directory) / release["artifacts"]["verity"]["file"]
                    run(["veritysetup", "verify", raw, verity, release["usr_root_hash"]], timeout=3600)
                    run(["mount", "-t", "erofs", "-o", "ro,loop", raw, usr])
                    try:
                        factory = Path(usr) / "share/factory/etc"
                        (root / "etc").mkdir()
                        for name in ("usr", "root", "run", "proc", "sys", "dev", "efi", "tmp", "home"):
                            (root / name).mkdir(exist_ok=True)
                        for name in ("bin", "sbin", "lib", "lib64"):
                            (root / name).symlink_to("usr/" + name)
                        (root / "root").chmod(0o700)
                        (root / "tmp").chmod(0o1777)
                        (root / "var/lib").mkdir(parents=True, exist_ok=True)
                        run(["btrfs", "subvolume", "create", root / "var/lib/machines"])
                        (root / "var/lib/machines").chmod(0o700)
                        # Let upstream sysusers/tmpfiles materialize writable state
                        # and links to /usr's current defaults. Copying factory /etc
                        # would freeze PAM, SSH and trust defaults across OS updates.
                        run(["mount", "--bind", usr, root / "usr"])
                        try:
                            run(["systemd-sysusers", f"--root={root}"])
                            run(["systemd-tmpfiles", f"--root={root}", "--create"], timeout=300)
                            run(
                                [
                                    "systemd-firstboot",
                                    f"--root={root}",
                                    "--setup-machine-id",
                                    "--root-password-hashed=!",
                                    "--root-shell=/bin/bash",
                                    "--force",
                                ]
                            )
                            run(["systemctl", f"--root={root}", "preset-all"])
                            run(["systemctl", f"--root={root}", "set-default", "multi-user.target"])
                        finally:
                            run(["umount", root / "usr"])
                        network.write(config, root)
                        fsid = recorded_storage["btrfs"]["uuid"]
                        fstab = (
                            f"UUID={fsid} / btrfs defaults,compress=zstd:1 0 0\n"
                            f"UUID={fsid} /var btrfs defaults,subvol=var,compress=zstd:1 0 0\n"
                            "/dev/mapper/particleve-swap none swap "
                            "defaults,x-systemd.device-timeout=45s 0 0\n"
                        )
                        atomic_write(root / "etc/fstab", fstab.encode(), 0o644)
                        atomic_write(
                            root / "etc/crypttab", crypttab({**proposed, **recorded_storage}).encode()
                        )
                        atomic_write(
                            root / "etc/mdadm.conf",
                            (
                                "HOMEHOST <ignore>\nAUTO -all\nARRAY /dev/md/particleve-swap UUID="
                                + recorded_storage["swap"]["md_uuid"]
                                + "\n"
                            ).encode(),
                            0o644,
                        )
                        atomic_write(
                            root / "root/.ssh/authorized_keys",
                            ("\n".join(config["admin_ssh_keys"]) + "\n").encode(),
                        )
                        directory = root / "var/lib/particleve"
                        record = {k: v for k, v in proposed.items() if k != "confirmation"}
                        record.update(recorded_storage)
                        record["storage_wait_seconds"] = config["storage"]["degraded_wait_seconds"]
                        write_json(directory / "installation.json", record)
                        write_json(root / "etc/particleve/host.json", config)
                        shutil.copytree(release_directory, directory / "releases" / release["version"])
                        contexts = factory / "selinux/targeted/contexts/files/file_contexts"
                        require(contexts.exists(), "SELinux file contexts missing from image")
                        policies = list((factory / "selinux/targeted/policy").glob("policy.[0-9]*"))
                        require(
                            len(policies) == 1 and policies[0].is_file() and not policies[0].is_symlink(),
                            "image must supply one regular compiled SELinux policy",
                        )
                        run(["setfiles", "-c", policies[0], "-r", root, contexts, root], timeout=600)
                    finally:
                        run(["umount", usr])
                backend = Linux(config, root / "var/lib/particleve")
                from .bootloaders import Loaders

                Loaders(backend).seed(release)
                for device in proposed["devices"]:
                    backend.expose_boot(device["role"], release)
                    with backend.esp(device["role"]) as esp:
                        backend.default(esp, release["version"])
                    run(
                        [
                            "efibootmgr",
                            "--create",
                            "--disk",
                            device["path"],
                            "--part",
                            "1",
                            "--label",
                            f"ParticleVE {device['role']}",
                            "--loader",
                            "\\EFI\\systemd\\systemd-bootx64.efi",
                        ]
                    )
            finally:
                run(["umount", root])
    from .admission import initialize

    initialize(record)
    return {
        "action": "installed",
        "version": release["version"],
        "automatic_updates": False,
        "tpm_enrollment": "required from the first verified normal boot",
        "next": "validate independent/degraded boots and owner recovery, then commission",
    }


def replace(
    config, backend, role, replacement, *, confirmation=None, keyfile=None, rebuild_quarantined=False
):
    from .config import validate

    require(role in ("a", "b"), "replacement role must be a or b")
    state = read_json(backend.directory / "state.json")
    require(
        state["maintenance"] and not state["pending"],
        "maintenance and no pending OS transaction are required",
    )
    require(
        not (backend.directory / "replacement.json").exists(), "reconcile the interrupted replacement first"
    )
    old, peer = backend.disk(role), backend.disk("b" if role == "a" else "a")
    mapper = f"particleve-state-{role}"
    try:
        (Path("/dev/mapper") / mapper).lstat()
    except FileNotFoundError:
        pass
    else:
        raise Error("old state mapper is still present; reboot degraded before planning replacement")
    from .admission import verify_manifest

    witness = verify_manifest(backend.manifest)
    require(
        role not in witness["allowed"] and len(witness["allowed"]) == 1,
        "boot from the authoritative survivor with the target quarantined before replacement",
    )
    if rebuild_quarantined:
        require(
            replacement["path"] == old["path"] and replacement["serial"] == old["serial"],
            "rebuild must select the exact quarantined disk",
        )
    else:
        require(not Path(old["path"]).exists(), "disconnect the failed disk before replacement")
    observed = inventory.observe_disk(replacement, unused=True)
    require(observed["identity"] != inventory.observe_disk(peer)["identity"], "replacement aliases survivor")
    require(
        observed["logical_sector"] == old["observed"]["logical_sector"], "replacement sector geometry differs"
    )
    require(
        observed["size"] >= old["partitions"][-1]["offset"] + old["partitions"][-1]["size"] + MIB,
        "replacement is too small",
    )
    release = backend.release(backend.current_version())
    new_config = {**config, "disks": [replacement if d["role"] == role else d for d in config["disks"]]}
    validate(new_config)
    basis = {
        "role": role,
        "replacement": replacement,
        "erase_quarantined_member": rebuild_quarantined,
        "observed": observed,
        "release_sha256": digest(release),
        "installation_sha256": digest(backend.manifest),
    }
    seed = digest(basis)
    device = json.loads(json.dumps(old))
    device.update(replacement)
    device.update(observed=observed, disk_uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, seed + ":disk")))
    for part in device["partitions"]:
        part["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, seed + ":" + part["role"]))
        if part["role"].startswith("a_"):
            kind = part["role"][2:]
            part["uuid"] = release["artifacts"][kind]["partition_uuid"]
            part["label"] = os_label(release["version"])
            require(part["size"] >= release["artifacts"][kind]["size"], "current OS does not fit")
        elif part["role"].startswith("b_"):
            part["label"] = "_empty"
    proposed = {**basis, "device": device}
    if confirmation is None:
        return {**proposed, "confirmation": digest(proposed)}
    require(confirmation == digest(proposed), "replacement plan changed")
    require(os.geteuid() == 0 and keyfile, "root and an independent recovery key file are required")
    validate_keyfile(keyfile)
    write_json(backend.directory / "replacement.json", proposed)
    (backend.directory / "commissioned.json").unlink(missing_ok=True)
    backend.freeze_vms()
    backend.stop_vms()
    backend.assert_no_vms()
    partition(device)
    run(["mkfs.vfat", "-F", "32", member(device, "esp")])
    write_os(device, release, backend.cache / release["version"])
    device["state_luks_uuid"] = format_encrypted(member(device, "state"), mapper, keyfile, enroll=True)
    device["btrfs_device_uuid"] = None
    record = json.loads(json.dumps(backend.manifest))
    record["devices"] = [device if d["role"] == role else d for d in record["devices"]]
    record["config_sha256"] = digest(new_config)
    write_json(backend.directory / "installation.json", record)
    write_json("/etc/particleve/host.json", new_config)
    atomic_write(Path("/etc/crypttab"), crypttab(record).encode())
    backend.manifest, backend.config = record, new_config
    replace_btrfs(old["btrfs_devid"], f"/dev/mapper/{mapper}")
    run(["mdadm", "--manage", "/dev/md/particleve-swap", "--add", member(device, "swap")])
    backend.expose_boot(role, release)
    from .bootloaders import Loaders

    Loaders(backend).restore(role)
    with backend.esp(role) as esp:
        backend.default(esp, release["version"])
    run(
        [
            "efibootmgr",
            "--create",
            "--disk",
            device["path"],
            "--part",
            "1",
            "--label",
            f"ParticleVE {role}",
            "--loader",
            "\\EFI\\systemd\\systemd-bootx64.efi",
        ]
    )
    return {
        "action": "replacement-started",
        "next": "wait for Btrfs replace and swap sync; restore RAID1 profiles, then finalize",
    }


def finalize_replacement(backend):
    from .storage import status

    record = read_json(backend.directory / "replacement.json")
    report = status(backend.manifest, backend.config, healthy=False)
    require(
        len(report["devices"]) == 2 and not report["swap_degraded"] and report["swap_sync_action"] == "idle",
        "replacement or swap resynchronization is incomplete",
    )
    require(
        all(p["profile"] == "raid1" for p in report["allocation"]),
        "restore all allocated data/metadata profiles to RAID1 before finalization",
    )
    progress = run(["btrfs", "replace", "status", "-1", "/"]).stdout.lower()
    require("finished" in progress, "Btrfs replacement has not completed")
    device = backend.disk(record["role"])
    device["btrfs_device_uuid"] = block_uuid(f"/dev/mapper/particleve-state-{record['role']}", "UUID_SUB")
    write_json(backend.directory / "installation.json", backend.manifest)
    from .admission import readmit

    require(
        run(["btrfs", "device", "stats", "--check", "/"], check=False).returncode == 0,
        "replacement has device errors",
    )
    readmit(backend.manifest, record["role"])
    (backend.directory / "replacement.json").unlink()
    restoration = backend.restore_vms()
    return {
        "action": "replacement-finalized",
        "vm_restoration": restoration,
        "next": "validate both boot paths and recommission",
    }
