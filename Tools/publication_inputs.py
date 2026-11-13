"""Compare producer inputs using the same policies as checked source selection."""

import re
import tempfile
from pathlib import Path

from particleve.common import require
from Tools.build_source import system_changes
from Tools.obs_refresh import component_changed
from Tools.sourcegit import git, source_url


def compare(root, selected, development, sources):
    """The selected build ref must contain every relevant development change."""
    changes = system_changes(root, selected, development, git_command=git)
    matches = {}
    for name, source in sources.items():
        if source is None:
            matches[name] = False
        elif name in {"particleve", "image"}:
            matches[name] = source == selected
        else:
            matches[name] = not component_changed(root, name, source, selected, git_command=git)
    return {"matches": matches, "system_changes": len(changes)}


def collect(url, selected, development, sources):
    source_url(url)
    revisions = {selected, development, *(v for v in sources.values() if v is not None)}
    require(all(re.fullmatch(r"[0-9a-f]{40}", v) for v in revisions), "invalid publication revision")
    require(set(sources) == {"particleve", "image", "mkosi", "fwupd-efi", "kernel"}, "missing source inputs")
    # Matching immutable identities need no repository transfer. Host/image
    # commits always match exactly; only dependency inputs can remain unchanged.
    if development == selected and all(
        value is None or value == selected or name in {"particleve", "image"}
        for name, value in sources.items()
    ):
        return {"matches": {name: value == selected for name, value in sources.items()}, "system_changes": 0}
    with tempfile.TemporaryDirectory(prefix="particleve-publication-inputs-") as temporary:
        root = Path(temporary)
        git(root, "init", "--bare", "--quiet")
        git(root, "remote", "add", "origin", url)
        # Keep history for ancestry checks while avoiding unrelated blob payloads.
        git(root, "config", "remote.origin.promisor", "true")
        git(root, "config", "remote.origin.partialclonefilter", "blob:none")
        git(
            root,
            "fetch",
            "--no-tags",
            "--no-progress",
            "--filter=blob:none",
            "origin",
            *sorted(revisions),
            remote=url,
            timeout=90,
        )
        return compare(root, selected, development, sources)
