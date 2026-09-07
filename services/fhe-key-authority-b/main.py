#!/usr/bin/env python3
"""Security/Privacy Authority — threshold FHE key authority B (spec §41, §60.25).

A standalone process holding party B's secret share. Delegates to the shared
authority CLI. See ``docs/THRESHOLD_FHE.md``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the repo importable when run as a standalone script/process.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cvztte.cac.threshold.authority import AuthorityRole  # noqa: E402
from cvztte.cac.threshold.service import run_authority_cli  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(run_authority_cli("B", AuthorityRole.SECURITY_PRIVACY, sys.argv[1:]))
