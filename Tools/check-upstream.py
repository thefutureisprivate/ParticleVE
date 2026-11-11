#!/usr/bin/python3
"""Check the locked source identities, release tags, and downstream patches."""

import argparse
import io
import json
import re
import tarfile
import tempfile
from pathlib import Path

from particleve.common import require, run
from particleve.package_sources import COMPONENTS, source_identity
from Tools.kernel_source import generate, write_generated
from Tools.sourcegit import fetch, git

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sources", type=Path, default=Path("build/sources"))
args = parser.parse_args()
root = Path.cwd()
checked = []
for component, name in COMPONENTS.items():
    identity = source_identity(root, component)
    pin = identity["upstream"]
    source = args.sources / name
    commit = git(source, "rev-parse", "HEAD").stdout.strip()
    require(commit == pin["revision"], f"{component}: checkout differs from its source pin")
    if re.fullmatch(r"\d+(?:\.\d+){0,2}", pin["version"]):
        tag = ("v" if component == "mkosi" else "") + pin["version"]
        fetch(source, pin["url"], f"refs/tags/{tag}")
        tagged = git(source, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
        require(tagged == commit, f"{component}: release tag does not match its immutable source pin")
    archive = git(source, "archive", "HEAD", text=False, timeout=60).stdout
    with tempfile.TemporaryDirectory(prefix="particleve-upstream-") as temporary:
        tree = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(tree, filter="data")
        for path in identity["inputs"]:
            if path.endswith(".patch"):
                git(tree, "apply", "--check", root / path)
                git(tree, "apply", root / path)
        if component == "mkosi":
            run(["bash", "-n", tree / "mkosi/resources/mkosi-obs/mkosi.build"])
    checked.append(component)
lock = json.loads((root / "sources.lock.json").read_text())
write_generated(
    root / ".obs/kernel",
    generate(root, lock, args.sources / "fedora_kernel", args.sources / "secureblue_kernel"),
    check=True,
)
checked.append("kernel sources")
print(json.dumps({"verified": checked}))
