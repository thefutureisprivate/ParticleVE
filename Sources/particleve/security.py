"""Image-build kernel, TPM and executable-privilege policy."""

import errno
import json
import os
import re
import stat
import struct
from pathlib import Path

from .common import hash_file, read_json, require, run

# The compiled runtime and build inspection consume the same authored policy.
RUNTIME_POLICY = read_json(Path(__file__).with_name("runtime-policy.json"))
require(
    type(RUNTIME_POLICY) is dict
    and set(RUNTIME_POLICY) == {"schema", "kernel_required", "tpm_profile", "selinux_booleans", "sysctls"}
    and type(RUNTIME_POLICY["schema"]) is int
    and RUNTIME_POLICY["schema"] == 1,
    "unknown runtime baseline policy schema",
)
KERNEL_REQUIRED = tuple(RUNTIME_POLICY["kernel_required"])
require(
    KERNEL_REQUIRED
    and len(KERNEL_REQUIRED) == len(set(KERNEL_REQUIRED))
    and all(type(name) is str and re.fullmatch(r"[A-Z0-9_]+", name) for name in KERNEL_REQUIRED),
    "invalid required kernel policy",
)
TPM_PROFILE = RUNTIME_POLICY["tpm_profile"]
require(
    type(TPM_PROFILE) is dict
    and set(TPM_PROFILE) == {"Name", "Attributes"}
    and all(type(value) is str and value for value in TPM_PROFILE.values()),
    "invalid TPM creation policy",
)
SELINUX_BOOLEANS = RUNTIME_POLICY["selinux_booleans"]
require(
    type(SELINUX_BOOLEANS) is dict
    and SELINUX_BOOLEANS
    and all(
        type(name) is str and re.fullmatch(r"[a-z0-9_]+", name) and type(value) is bool
        for name, value in SELINUX_BOOLEANS.items()
    ),
    "invalid SELinux boolean policy",
)
require(
    type(RUNTIME_POLICY["sysctls"]) is dict
    and RUNTIME_POLICY["sysctls"]
    and all(
        type(name) is str
        and re.fullmatch(r"[a-z0-9_.]+", name)
        and type(value) is str
        and re.fullmatch(r"[0-9]+", value)
        for name, value in RUNTIME_POLICY["sysctls"].items()
    ),
    "invalid kernel runtime policy",
)
POLICY = Path("usr/lib/particleve/security-policy.json")


def write_tpm_profile(root):
    """Publish creation policy for explicit native provisioning, without opening any TPM state."""
    path = Path(root) / "usr/lib/particleve/tpm-profile.json"
    path.write_text(json.dumps(TPM_PROFILE) + "\n")


def kernel_baseline(root):
    from .kernelruntime import kernel_support

    trees = [p for p in (Path(root) / "usr/lib/modules").iterdir() if p.is_dir()]
    require(len(trees) == 1, "security baseline requires exactly one kernel")
    config = trees[0] / "config"
    values = dict(re.findall(r"^CONFIG_(\w+)=(.+)$", config.read_text(), re.M))
    missing = [name for name in KERNEL_REQUIRED if values.get(name) != "y"]
    require(not missing, "kernel security support missing: " + ", ".join(missing))
    require(values.get("RFKILL") in ("y", "m"), "kernel RFKill support is missing")
    console_uarts = {}
    for name in ("SERIAL_8250_NR_UARTS", "SERIAL_8250_RUNTIME_UARTS"):
        value = values.get(name, "")
        require(
            value.isdecimal() and int(value) >= 4, "kernel lacks the four signed serial consoles: " + name
        )
        console_uarts[name] = int(value)
    return {
        "schema": 1,
        "kernel": trees[0].name,
        "config_sha256": hash_file(config),
        "required": {name: values[name] for name in KERNEL_REQUIRED},
        "module_sig_force": values.get("MODULE_SIG_FORCE") == "y",
        "rfkill": {"core": values["RFKILL"], "deprecated_input": values.get("RFKILL_INPUT") == "y"},
        "module_signing_key": values.get("MODULE_SIG_KEY"),
        "iommu_default_strict": values.get("IOMMU_DEFAULT_DMA_STRICT") == "y",
        "runtime_support": kernel_support(values),
        "console_uarts": console_uarts,
    }


def capabilities(data):
    """Decode Linux vfs_cap_data; namespace-rooted capabilities are explicit."""
    require(len(data) in (20, 24), "unsupported file capability record")
    magic, low_p, low_i, high_p, high_i = struct.unpack("<IIIII", data[:20])
    revision = magic >> 24
    require(
        revision in (2, 3) and len(data) == (24 if revision == 3 else 20) and magic & 0xFFFFFE == 0,
        "unsupported file capability flags",
    )
    return {
        "effective": bool(magic & 1),
        "permitted": low_p | high_p << 32,
        "inheritable": low_i | high_i << 32,
        "rootid": struct.unpack("<I", data[20:])[0] if revision == 3 else 0,
    }


def privilege_inventory(root, *, image=None):
    root = Path(root)
    result = {}

    def failed(exc):
        raise exc

    for directory, dirs, files in os.walk(root / "usr", followlinks=False, onerror=failed):
        dirs.sort()
        for name in sorted(files):
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            try:
                caps = capabilities(os.getxattr(path, "security.capability", follow_symlinks=False))
            except OSError as exc:
                if exc.errno != errno.ENODATA:
                    raise
                caps = None
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o6000 or caps:
                owner = info.st_uid, info.st_gid
                if image is not None:
                    # fsck.erofs applies chown after xattrs, clearing capabilities.
                    # Extraction therefore omits chown; read the original owner
                    # from EROFS metadata rather than trusting the extractor UID.
                    name = "/" + path.relative_to(root / "usr").as_posix()
                    metadata = run(["dump.erofs", "--path=" + name, image]).stdout
                    matches = re.findall(r"^Uid:\s*(\d+)\s+Gid:\s*(\d+)\s+Access:", metadata, re.M)
                    require(len(matches) == 1, "ambiguous original privileged-file ownership")
                    owner = tuple(int(value) for value in matches[0])
                result["/" + path.relative_to(root).as_posix()] = {
                    "mode": format(mode, "04o"),
                    "uid": owner[0],
                    "gid": owner[1],
                    "capabilities": caps,
                }
    return result


def check_privileges(root, *, image=None):
    policy = read_json(Path(root) / POLICY)
    require(policy.get("schema") == 1, "unknown image privilege policy")
    allowed = policy["privileged_files"]
    for path, record in allowed.items():
        require(path.startswith("/usr/") and record.get("purpose"), "privilege needs a reviewed purpose")
        require(
            record["uid"] == 0 and not int(record["mode"], 8) & 0o022, "unsafe privileged-file owner/mode"
        )
    actual = privilege_inventory(root, image=image)
    expected = {path: {k: v for k, v in record.items() if k != "purpose"} for path, record in allowed.items()}
    require(actual == expected, "image privileged-file inventory differs from the reviewed policy")
    return actual


def apply_image_privileges(root):
    """Revoke only individually reviewed privileges, rejecting dependency drift first."""
    root = Path(root)
    policy = read_json(root / POLICY)
    require(policy.get("schema") == 1, "unknown image privilege policy")
    allowed, revoked = policy["privileged_files"], policy["revoked_privileges"]
    require(not (set(allowed) & set(revoked)), "conflicting image privilege decisions")
    expected = {
        path: {k: v for k, v in item.items() if k != "purpose"} for path, item in (allowed | revoked).items()
    }
    actual = privilege_inventory(root)
    require(
        all(name in expected and item == expected[name] for name, item in actual.items())
        and all(actual.get(name) == expected[name] for name in allowed),
        "package privilege inventory expanded or a required helper changed",
    )
    for name, item in revoked.items():
        require(
            name.startswith("/usr/") and item.get("purpose"), "privilege revocation needs a reviewed purpose"
        )
        if name not in actual:
            continue  # A vendor already removing an unused privilege is acceptable.
        path = root / name.lstrip("/")
        if item["capabilities"]:
            os.removexattr(path, "security.capability", follow_symlinks=False)
        path.chmod(int(item["mode"], 8) & ~0o6000, follow_symlinks=False)
    return check_privileges(root)
