"""EZKL ZKML tests (spec §30, §60.8): real proof, binding, quantization guard.

Builds a real EZKL artifact set once per session (settings/calibrate/compile/
SRS/setup) from the committed Judge ONNX, then exercises genuine proof
generation and verification — including the §30 binding checks (public-input
equality to gateway-derived features, SAFE predicate, quantization guard) and
fail-closed artifact-drift rejection. No mocks: these run the ezkl prover.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("ezkl")

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.ezkl import EZKLProver, EZKLVerifier, build
from cvztte.ezkl.build import calibration_set
from cvztte.ezkl.model import EZKLManifest
from cvztte.ezkl.prover import MANIFEST_FILE
from cvztte.judge import JudgeInput, SafetyJudge, extract
from cvztte.judge.model import JudgeVerdict
from cvztte.judge.train import ARTIFACT_DIR as JUDGE_DIR
from cvztte.judge.train import ONNX_FILE as JUDGE_ONNX
from cvztte.policy.model import PolicyDecision

pytestmark = pytest.mark.slow


@pytest.fixture(scope="session")
def artifact_dir(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("ezkl_artifacts")
    build(
        onnx_path=JUDGE_DIR / JUDGE_ONNX,
        calibration_features=calibration_set(),
        out_dir=out,
    )
    return out


@pytest.fixture(scope="session")
def prover(artifact_dir: Path) -> EZKLProver:
    return EZKLProver(artifact_dir / MANIFEST_FILE)


@pytest.fixture(scope="session")
def verifier(artifact_dir: Path) -> EZKLVerifier:
    return EZKLVerifier(artifact_dir / MANIFEST_FILE)


@pytest.fixture(scope="session")
def safe_case():
    inp = JudgeInput(
        action=AgentAction(action_type=ActionType.FILE_READ, target="notes.txt",
                           operation="read", data_classification=DataClassification.INTERNAL),
        policy=PolicyDecision(allow=True, reason_code="ok", risk_level=0),
    )
    return inp, extract(inp), SafetyJudge().evaluate(inp).verdict


@pytest.fixture(scope="session")
def safe_proof(prover: EZKLProver, safe_case):
    _, features, _ = safe_case
    return prover.prove(features)


def test_prove_and_verify_binds_features(verifier, safe_proof, safe_case) -> None:
    _, features, float_verdict = safe_case
    result = verifier.verify(
        proof=safe_proof, expected_features=features, expected_float_verdict=float_verdict,
    )
    assert result.verified is True
    assert result.verdict is JudgeVerdict.SAFE
    assert result.is_safe is True
    assert len(result.logits) == 3


def test_ezkl_onnx_verdict_parity(verifier, safe_proof, safe_case) -> None:
    # The proven (quantized) argmax must agree with the float ONNX argmax.
    _, _, float_verdict = safe_case
    logits = verifier.decode_logits(safe_proof.output_felts)
    quant_idx = max(range(len(logits)), key=lambda i: logits[i])
    from cvztte.judge.model import VERDICT_BY_INDEX
    assert VERDICT_BY_INDEX[quant_idx] is float_verdict


def test_binding_rejects_mismatched_features(verifier, safe_proof, safe_case) -> None:
    _, features, _ = safe_case
    tampered = list(features)
    tampered[0] = 1.0 if tampered[0] == 0.0 else 0.0
    with pytest.raises(CVZTTEError) as exc:
        verifier.verify(proof=safe_proof, expected_features=tampered)
    assert exc.value.code == ErrorCode.EZKL_PUBLIC_INPUT_MISMATCH


def test_quantization_guard_rejects_verdict_disagreement(verifier, safe_proof, safe_case) -> None:
    _, features, _ = safe_case
    # Claim the float judge said UNSAFE while the proof proves SAFE -> guard trips.
    with pytest.raises(CVZTTEError) as exc:
        verifier.verify(
            proof=safe_proof, expected_features=features,
            expected_float_verdict=JudgeVerdict.UNSAFE,
        )
    assert exc.value.code == ErrorCode.EZKL_QUANTIZATION_GUARD


def test_tampered_proof_rejected(verifier, safe_proof, safe_case) -> None:
    _, features, _ = safe_case
    doc = json.loads(safe_proof.proof_json)
    # Corrupt the proof transcript bytes so cryptographic verification fails.
    p = doc["proof"]
    if isinstance(p, list) and p:
        p[0] = (int(p[0]) ^ 0xFF) & 0xFF if isinstance(p[0], int) else p[0]
    elif isinstance(p, str) and p:
        doc["proof"] = ("f" if p[0] != "f" else "0") + p[1:]
    bad = safe_proof.model_copy(update={"proof_json": json.dumps(doc)})
    with pytest.raises(CVZTTEError) as exc:
        verifier.verify(proof=bad, expected_features=features)
    assert exc.value.code == ErrorCode.EZKL_PROOF_INVALID


def test_manifest_hash_drift_rejected(artifact_dir: Path) -> None:
    manifest = EZKLManifest.load(artifact_dir / MANIFEST_FILE)
    drifted = manifest.model_copy(update={"vk_hash": "sha256:" + "00" * 32})
    with pytest.raises(CVZTTEError) as exc:
        drifted.verify_against_runtime(artifact_dir, require_pk=False)
    assert exc.value.code == ErrorCode.EZKL_ARTIFACT_UNAPPROVED


def test_feature_extractor_drift_rejected(artifact_dir: Path) -> None:
    manifest = EZKLManifest.load(artifact_dir / MANIFEST_FILE)
    drifted = manifest.model_copy(update={"feature_names": ["x"]})
    with pytest.raises(CVZTTEError) as exc:
        drifted.verify_against_runtime(artifact_dir, require_pk=False)
    assert exc.value.code == ErrorCode.EZKL_ARTIFACT_UNAPPROVED


def test_missing_manifest_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(CVZTTEError) as exc:
        EZKLVerifier(tmp_path / "nope.json")
    assert exc.value.code == ErrorCode.EZKL_ARTIFACT_UNAPPROVED
