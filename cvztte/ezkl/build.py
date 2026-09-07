"""Build the EZKL artifact set for the committed Judge model (spec §30).

Run as a module to (re)generate proving/verifying artifacts + manifest::

    python -m cvztte.ezkl.build [out_dir]

The proving key and SRS are large (100+ MB); they are NOT committed to the repo
(see .gitignore) — in a real deployment they come from a trusted build/ceremony
and are pinned by the manifest hashes. This script rebuilds them locally.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cvztte.ezkl.prover import build
from cvztte.judge.features import N_FEATURES
from cvztte.judge.train import ARTIFACT_DIR as JUDGE_ARTIFACT_DIR
from cvztte.judge.train import ONNX_FILE as JUDGE_ONNX_FILE

DEFAULT_OUT = Path(__file__).parent / "artifacts"


def calibration_set() -> list[list[float]]:
    """A small representative feature set spanning low/high risk (for calibration)."""
    zero = [0.0] * N_FEATURES
    one = [1.0] * N_FEATURES
    mid = [0.5] * N_FEATURES
    ramp = [i / max(N_FEATURES - 1, 1) for i in range(N_FEATURES)]
    return [zero, one, mid, ramp]


def main(out_dir: str | Path = DEFAULT_OUT) -> None:
    onnx_path = JUDGE_ARTIFACT_DIR / JUDGE_ONNX_FILE
    manifest = build(
        onnx_path=onnx_path,
        calibration_features=calibration_set(),
        out_dir=out_dir,
    )
    print(f"EZKL artifacts built in {out_dir}")
    print(f"logrows={manifest.logrows} input_scale={manifest.input_scale} "
          f"output_scale={manifest.output_scale}")
    print(f"manifest_hash={manifest.manifest_hash()}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT)
