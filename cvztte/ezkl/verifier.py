"""EZKL proof verification + feature/predicate binding (spec §30, §60.8).

The verifier enforces the real binding §30 requires. It is not enough to check
that *a* proof verifies; the proof must be shown to be about the *exact* action
the gateway authorized:

1. **Cryptographic validity** — ``ezkl.verify`` against the pinned VK/SRS.
2. **Public-input binding** — the proof's public input field elements MUST equal
   the field elements the gateway independently derives from the exact
   action/policy/behavior/containment snapshot (feature equality). A proof about
   different features is rejected (``EZKL_PUBLIC_INPUT_MISMATCH``).
3. **SAFE predicate** — the public output field elements are decoded and the
   argmax verdict is computed from the proven logits.
4. **Quantization guard** — the proven (quantized) verdict MUST match the trusted
   float ONNX verdict; a quantization-boundary flip is rejected
   (``EZKL_QUANTIZATION_GUARD``) rather than silently accepted (§60.8).

Every failure raises :class:`CVZTTEError` (fail-closed, §4.20).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.ezkl.model import EZKLManifest
from cvztte.ezkl.prover import EZKLProof, _ezkl
from cvztte.judge.features import N_FEATURES
from cvztte.judge.model import VERDICT_BY_INDEX, JudgeVerdict


class EZKLVerification(BaseModel):
    """Result of verifying + binding a Judge proof."""

    model_config = ConfigDict(extra="forbid")

    verified: bool
    verdict: JudgeVerdict
    logits: list[float]
    is_safe: bool


class EZKLVerifier:
    """Verify-only: loads settings/SRS/VK (no proving key needed)."""

    def __init__(self, manifest_path: str | Path) -> None:
        manifest_path = Path(manifest_path)
        self._dir = manifest_path.parent
        self._manifest = EZKLManifest.load(manifest_path)
        self._manifest.verify_against_runtime(self._dir, require_pk=False)
        self._ezkl = _ezkl()

    @property
    def manifest(self) -> EZKLManifest:
        return self._manifest

    def expected_input_felts(self, features: list[float]) -> list[str]:
        """Field elements the gateway expects for these features (binding key)."""
        scale = self._manifest.input_scale
        return [self._ezkl.float_to_felt(float(f), scale) for f in features]

    def decode_logits(self, output_felts: list[str]) -> list[float]:
        scale = self._manifest.output_scale
        return [self._ezkl.felt_to_float(x, scale) for x in output_felts]

    def verify(
        self,
        *,
        proof: EZKLProof,
        expected_features: list[float],
        expected_float_verdict: JudgeVerdict | None = None,
    ) -> EZKLVerification:
        if len(expected_features) != N_FEATURES:
            raise CVZTTEError(ErrorCode.EZKL_PUBLIC_INPUT_MISMATCH, "wrong feature length")
        ez = self._ezkl
        d = self._dir

        # 1. Cryptographic validity against the pinned VK/SRS/settings.
        with tempfile.TemporaryDirectory() as tmp:
            proof_path = Path(tmp) / "proof.json"
            proof_path.write_text(proof.proof_json)
            try:
                ok = ez.verify(str(proof_path), str(d / self._manifest.settings_file),
                               str(d / self._manifest.vk_file), str(d / self._manifest.srs_file))
            except CVZTTEError:
                raise
            except Exception as exc:
                raise CVZTTEError(ErrorCode.EZKL_PROOF_INVALID, "proof verification error") from exc
        if not ok:
            raise CVZTTEError(ErrorCode.EZKL_PROOF_INVALID, "proof failed verification")

        # 2. Public-input binding: proven inputs must equal gateway-derived features.
        expected = self.expected_input_felts(expected_features)
        if list(proof.input_felts) != expected:
            raise CVZTTEError(
                ErrorCode.EZKL_PUBLIC_INPUT_MISMATCH,
                "proof public inputs do not bind to gateway features",
            )

        # 3. SAFE predicate from the proven outputs.
        logits = self.decode_logits(proof.output_felts)
        verdict_idx = max(range(len(logits)), key=lambda i: logits[i])
        verdict = VERDICT_BY_INDEX[verdict_idx]

        # 4. Quantization guard: proven verdict must match the trusted float verdict.
        if expected_float_verdict is not None and verdict is not expected_float_verdict:
            raise CVZTTEError(
                ErrorCode.EZKL_QUANTIZATION_GUARD,
                "quantized verdict disagrees with float judge (boundary flip)",
            )

        return EZKLVerification(
            verified=True,
            verdict=verdict,
            logits=[round(x, 6) for x in logits],
            is_safe=verdict is JudgeVerdict.SAFE,
        )
