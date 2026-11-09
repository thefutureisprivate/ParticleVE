"""Trial EFI loaders without replacing either independently reachable recovery path."""

import re
import uuid
from pathlib import Path

from .common import atomic_write, hash_file, read_json, require, run, write_json

FIXED = ("EFI/systemd/systemd-bootx64.efi", "EFI/BOOT/BOOTX64.EFI")
BLI = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
VARIABLES = Path("/sys/firmware/efi/efivars")


def loader_path(sha256):
    require(re.fullmatch("[0-9a-f]{64}", sha256), "invalid EFI loader hash")
    return f"EFI/ParticleVE/loaders/{sha256}.efi"


def executed_path():
    return (
        (VARIABLES / f"LoaderImageIdentifier-{BLI}")
        .read_bytes()[4:]
        .decode("utf-16-le")
        .rstrip("\0")
        .replace("\\", "/")
        .lstrip("/")
    )


def owned_entry(path, sha, esp_uuid):
    """Check EFI_LOAD_OPTION identity before reusing/deleting a firmware entry."""
    data = path.read_bytes()
    require(len(data) >= 12, "truncated EFI boot option")
    # efivar attributes (4), load-option attributes (4), path-list length (2),
    # followed by a NUL-terminated UTF-16 description and the device path.
    end = next((i for i in range(10, len(data) - 1, 2) if data[i : i + 2] == b"\0\0"), None)
    require(end is not None, "unterminated EFI boot option description")
    label = data[10:end].decode("utf-16-le")
    expected = ("\\" + loader_path(sha).replace("/", "\\") + "\0").encode("utf-16-le")
    return (
        label == f"ParticleVE trial {sha}"
        and expected in data[end + 2 :]
        and uuid.UUID(esp_uuid).bytes_le in data[end + 2 :]
    )


class Loaders:
    def __init__(self, backend):
        self.backend = backend
        self.directory = backend.directory / "bootloaders"
        self.path = self.directory / "state.json"

    def load(self):
        state = read_json(self.path)
        require(
            type(state) is dict and state.get("schema") == 1,
            "unknown bootloader state; owner recovery required",
        )
        for sha in [state["seed"], *state["rejected"], *([state["good"]] if state["good"] else [])]:
            loader_path(sha)
        if state["trial"]:
            trial = state["trial"]
            loader_path(trial["sha256"])
            require(
                re.fullmatch("[0-9a-fA-F]{4}", trial["entry"]) and trial["role"] in ("a", "b"),
                "invalid EFI trial identity",
            )
        return state

    def seed(self, release):
        """Fresh installation only; first normal healthy boot must validate this seed."""
        require(not self.path.exists(), "bootloader state already exists")
        item = release["artifacts"]["bootloader"]
        data = (self.backend.cache / release["version"] / item["file"]).read_bytes()
        atomic_write(self.directory / f"{item['sha256']}.efi", data)
        write_json(
            self.path, {"schema": 1, "good": None, "seed": item["sha256"], "trial": None, "rejected": []}
        )
        for role in ("a", "b"):
            self.restore(role)

    def restore(self, role):
        state = self.load()
        sha = state["good"] or state["seed"]
        source = self.directory / f"{sha}.efi"
        require(hash_file(source) == sha, "retained EFI loader changed")
        with self.backend.esp(role) as esp:
            for name in FIXED:
                if (esp / name).is_file() and hash_file(esp / name) == sha:
                    continue
                atomic_write(esp / name, source.read_bytes())
                require(hash_file(esp / name) == sha, "EFI loader write verification failed")

    def prove(self, esp):
        state = self.load()
        require(state["good"], "no healthy boot has validated the installation loader")
        # Both paths on every disk must remain usable even when the candidate hangs.
        for name in FIXED:
            require(
                (esp / name).is_file() and hash_file(esp / name) == state["good"],
                "known-working EFI loader is unavailable",
            )

    def queue(self, release):
        state = self.load()
        sha = release["artifacts"]["bootloader"]["sha256"]
        if sha == state["good"] or sha in state["rejected"]:
            return
        require(not state["trial"], "an EFI loader trial requires reconciliation")
        require(not list(VARIABLES.glob("BootNext-*")), "another UEFI one-time boot is staged")
        role = self.backend.current_esp_role()
        disk = self.backend.disk(role)
        esp_uuid = next(p["uuid"] for p in disk["partitions"] if p["role"] == "esp")
        label = f"ParticleVE trial {sha}"
        # --create-only explicitly preserves BootOrder. A crash here leaves an
        # unselected entry, never a replacement of a working boot path.
        existing = [p for p in VARIABLES.glob(f"Boot????-{GLOBAL}") if owned_entry(p, sha, esp_uuid)]
        require(len(existing) <= 1, "duplicate EFI trial entries require owner reconciliation")
        if existing:
            entry = existing[0].name[4:8]
        else:
            result = run(
                [
                    "efibootmgr",
                    "--create-only",
                    "--disk",
                    self.backend.disk(role)["path"],
                    "--part",
                    "1",
                    "--label",
                    label,
                    "--loader",
                    "\\" + loader_path(sha).replace("/", "\\"),
                ]
            )
            matches = re.findall(
                r"^Boot([0-9A-Fa-f]{4})\*?\s+" + re.escape(label) + r"(?:\t|$)", result.stdout, re.M
            )
            require(len(matches) == 1, "cannot identify the created EFI trial entry")
            entry = matches[0]
        state["trial"] = {
            "sha256": sha,
            "entry": entry,
            "role": role,
            "esp_uuid": esp_uuid,
            "boot_id": self.backend.boot_id(),
        }
        write_json(self.path, state)  # durable before changing BootNext
        run(["efibootmgr", "--bootnext", entry])

    def cancel(self):
        state = self.load()
        trial = state["trial"]
        if not trial:
            return
        option = VARIABLES / f"Boot{trial['entry']}-{GLOBAL}"
        require(
            not option.exists() or owned_entry(option, trial["sha256"], trial["esp_uuid"]),
            "foreign EFI option replaced the loader trial",
        )
        next_path = VARIABLES / f"BootNext-{GLOBAL}"
        if next_path.exists():
            entry = int.from_bytes(next_path.read_bytes()[4:], "little")
            require(entry == int(trial["entry"], 16), "foreign BootNext replaced the EFI loader trial")
            run(["efibootmgr", "--delete-bootnext"])
        if option.exists():
            run(["efibootmgr", "--bootnum", trial["entry"], "--delete-bootnum"])
        state["trial"] = None
        write_json(self.path, state)

    def bless(self):
        state = self.load()
        trial = state["trial"]
        role = self.backend.current_esp_role()
        actual = executed_path()
        if trial and trial["sha256"] == state["good"]:
            # A previous healthy boot persisted proof, then lost power during
            # sequential promotion. Resume from the retained verified blob.
            for target in ("a", "b"):
                if target == role or Path(self.backend.disk(target)["path"]).exists():
                    self.restore(target)
            self.cancel()
            return {"loader": "validated", "sha256": state["good"]}
        if trial:
            require(trial["boot_id"] != self.backend.boot_id(), "EFI loader trial has not rebooted")
            current = int.from_bytes((VARIABLES / f"BootCurrent-{GLOBAL}").read_bytes()[4:], "little")
            proven = (
                current == int(trial["entry"], 16)
                and role == trial["role"]
                and actual.lower() == loader_path(trial["sha256"]).lower()
            )
            if not proven:
                # A good old loader may boot the new OS after the trial returns
                # an EFI error. OS health is not proof that the new loader ran.
                if trial["sha256"] not in state["rejected"]:
                    state["rejected"].append(trial["sha256"])
                write_json(self.path, state)
                self.cancel()
                return {"loader": "quarantined", "sha256": trial["sha256"]}
            sha = trial["sha256"]
        else:
            sha = state["good"] or state["seed"]
            require(
                actual.lower() in {p.lower() for p in FIXED} | {loader_path(sha).lower()},
                "running loader path is not recorded",
            )
        with self.backend.esp(role) as esp:
            require(hash_file(esp / actual) == sha, "executed EFI loader does not match its recorded hash")
            atomic_write(self.directory / f"{sha}.efi", (esp / actual).read_bytes())
        # Record proof before promotion. Interrupted writes always leave another
        # independently reachable path containing a loader that actually booted.
        state["good"] = sha
        write_json(self.path, state)
        for target in ("a", "b"):
            # Degraded boots must not attempt promotion on an absent ESP.
            if target == role or Path(self.backend.disk(target)["path"]).exists():
                self.restore(target)
        self.cancel()
        return {"loader": "validated", "sha256": sha}
