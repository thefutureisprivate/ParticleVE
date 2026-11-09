#!/usr/bin/python3 -I
"""Pass the full ParticleVE build identity to unmodified upstream mkosi."""

import os
import sys

sys.path.insert(0, "/usr/lib/particleve-build")
from particleve.versioning import mkosi_args

try:
    arguments = mkosi_args(sys.argv[1:])
except (OSError, ValueError) as exc:
    raise SystemExit(f"mkosi: {exc}") from None
os.execv(sys.executable, [sys.executable, "-I", "-m", "mkosi", *arguments])
