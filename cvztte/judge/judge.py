"""Safety-Judge inference with margin guard (spec §29, §60.8).

Loads a pinned ONNX model (verifying the artifact manifest at construction —
drift is rejected fail-closed, §60.8) and evaluates a :class:`JudgeInput` into a
verdict. Inference runs the deterministic feature extractor, the ONNX model, a
softmax, and a **margin guard**: when the top two class probabilities are within
``margin`` the verdict collapses to the *more restrictive* of the two, so a
quantization-boundary flip can only ever move toward caution, never toward SAFE
(§60.8, "ambiguous -> REVIEW/DENY").

Any inference error raises :class:`CVZTTEError` (``JUDGE_FAILED``) — the caller
treats an unavailable Judge as DENY/ESCALATE, never as implicit SAFE (§4.20).
"""

from __future__ import annotations

import math
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.judge.features import JudgeInput, extract, feature_extractor_hash
from cvztte.judge.manifest import JudgeManifest
from cvztte.judge.model import VERDICT_BY_INDEX, JudgeVerdict

_ARTIFACT_DIR = Path(__file__).parent / "artifacts"
_DEFAULT_MANIFEST = _ARTIFACT_DIR / "judge_manifest.json"


class JudgeResult(BaseModel):
    """Verdict + the exact features/probabilities it was derived from (§30 binding)."""

    model_config = ConfigDict(extra="forbid")

    verdict: JudgeVerdict
    probabilities: list[float]
    margin: float
    features: list[float]
    feature_extractor_hash: str
    model_hash: str

    @property
    def is_safe(self) -> bool:
        return self.verdict is JudgeVerdict.SAFE


def _softmax(logits: list[float]) -> list[float]:
    m = max(logits)
    exps = [math.exp(x - m) for x in logits]
    s = sum(exps)
    return [e / s for e in exps]


class SafetyJudge:
    """ONNX-backed Safety Judge (spec §29)."""

    def __init__(self, manifest_path: str | Path = _DEFAULT_MANIFEST) -> None:
        manifest_path = Path(manifest_path)
        try:
            self._manifest = JudgeManifest.load(manifest_path)
        except FileNotFoundError as exc:
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "judge manifest missing") from exc
        artifact_dir = manifest_path.parent
        # Startup: recompute hashes, reject drift (fail-closed, §60.8).
        self._manifest.verify_against_runtime(artifact_dir)
        self._onnx_path = artifact_dir / self._manifest.onnx_file
        self._model_hash = self._manifest.model_hash
        self._margin = self._manifest.margin
        try:
            import onnxruntime as ort  # local import: heavy optional dep

            so = ort.SessionOptions()
            so.intra_op_num_threads = 1
            so.inter_op_num_threads = 1
            self._session = ort.InferenceSession(
                str(self._onnx_path), sess_options=so, providers=["CPUExecutionProvider"]
            )
            self._input_name = self._session.get_inputs()[0].name
        except Exception as exc:  # onnxruntime import/load failure -> fail closed
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "judge model load failed") from exc

    @property
    def manifest(self) -> JudgeManifest:
        return self._manifest

    def logits(self, features: list[float]) -> list[float]:
        """Raw ONNX logits for a feature vector (used for EZKL parity, Phase 12)."""
        try:
            import numpy as np

            arr = np.asarray([features], dtype=np.float32)
            out = self._session.run(None, {self._input_name: arr})
            return [float(x) for x in out[0][0]]
        except CVZTTEError:
            raise
        except Exception as exc:  # any inference failure -> fail closed
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "judge inference failed") from exc

    def evaluate(self, inp: JudgeInput) -> JudgeResult:
        """Full pipeline: extract -> infer -> softmax -> margin guard -> verdict."""
        features = extract(inp)
        logits = self.logits(features)
        probs = _softmax(logits)

        order = sorted(range(len(probs)), key=lambda i: probs[i], reverse=True)
        top, second = order[0], order[1]
        margin = probs[top] - probs[second]

        if margin < self._margin:
            # Ambiguous: resolve to the more restrictive (lower index) of the top two.
            verdict = VERDICT_BY_INDEX[min(top, second)]
        else:
            verdict = VERDICT_BY_INDEX[top]

        return JudgeResult(
            verdict=verdict,
            probabilities=[round(p, 6) for p in probs],
            margin=round(margin, 6),
            features=features,
            feature_extractor_hash=feature_extractor_hash(),
            model_hash=self._model_hash,
        )

    def binding_commitment(self, result: JudgeResult) -> str:
        """Commitment over the exact Judge statement (feeds Decision Token / EZKL, §30)."""
        return commit(
            Domain.MODEL,
            {
                "verdict": result.verdict.value,
                "features": result.features,
                "feature_extractor_hash": result.feature_extractor_hash,
                "model_hash": result.model_hash,
            },
        )
