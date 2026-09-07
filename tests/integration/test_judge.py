"""Safety Judge tests (spec §29, §60.8) against the committed ONNX artifact.

Exercises the real ONNX-backed judge: manifest verification / drift rejection,
PyTorch<->ONNX parity, deterministic features, the fail-closed margin guard, and
correct verdicts on clear-cut scenarios. The Judge is not overclaimed as a
production classifier (§29) — tests assert its structural/security properties.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.judge import (
    FEATURE_NAMES,
    N_FEATURES,
    JudgeInput,
    JudgeManifest,
    JudgeVerdict,
    SafetyJudge,
    extract,
)
from cvztte.judge.model import VERDICT_BY_INDEX, build_mlp
from cvztte.judge.train import WEIGHTS_FILE
from cvztte.policy.model import PolicyDecision

ARTIFACTS = Path(__file__).resolve().parents[2] / "cvztte" / "judge" / "artifacts"


def _benign_read() -> JudgeInput:
    return JudgeInput(
        action=AgentAction(action_type=ActionType.FILE_READ, target="notes.txt",
                           operation="read", data_classification=DataClassification.INTERNAL),
        policy=PolicyDecision(allow=True, reason_code="ok", risk_level=0),
        destination_external=False, destination_known=True,
    )


def test_judge_constructs_and_verifies_manifest() -> None:
    judge = SafetyJudge()
    assert judge.manifest.n_features == N_FEATURES
    assert judge.manifest.feature_names == FEATURE_NAMES


def test_feature_vector_deterministic_and_sized() -> None:
    inp = _benign_read()
    v1 = extract(inp)
    v2 = extract(inp)
    assert v1 == v2
    assert len(v1) == N_FEATURES
    assert all(0.0 <= x <= 1.0 for x in v1)


def test_onnx_pytorch_parity() -> None:
    # The committed ONNX must match the PyTorch weights it was exported from.
    import numpy as np
    import torch

    judge = SafetyJudge()
    model = build_mlp()
    model.load_state_dict(torch.load(ARTIFACTS / WEIGHTS_FILE))
    model.eval()

    rng = np.random.default_rng(0)
    for _ in range(50):
        feats = rng.random(N_FEATURES).astype("float32").tolist()
        onnx_logits = judge.logits(feats)
        with torch.no_grad():
            torch_logits = model(torch.tensor([feats])).numpy()[0].tolist()
        assert np.allclose(onnx_logits, torch_logits, atol=1e-4)


def test_clear_unsafe_verdict() -> None:
    judge = SafetyJudge()
    inp = JudgeInput(
        action=AgentAction(action_type=ActionType.SECRET_ACCESS, target="db_creds",
                           operation="read", data_classification=DataClassification.SECRET),
        policy=PolicyDecision(allow=True, reason_code="ok", risk_level=4),
        destination_external=True, destination_known=False, has_delegation=False,
        bypass_attempts=2, privilege_escalation_attempts=1,
    )
    assert judge.evaluate(inp).verdict is JudgeVerdict.UNSAFE


def test_clear_safe_verdict() -> None:
    assert SafetyJudge().evaluate(_benign_read()).verdict is JudgeVerdict.SAFE


def test_review_or_stricter_when_approval_required() -> None:
    judge = SafetyJudge()
    inp = JudgeInput(
        action=AgentAction(action_type=ActionType.FILE_READ, target="notes.txt",
                           operation="read"),
        policy=PolicyDecision(allow=True, reason_code="ok", risk_level=2,
                              require_human_approval=True),
    )
    # Human-approval-required must never come back SAFE.
    assert judge.evaluate(inp).verdict is not JudgeVerdict.SAFE


def test_margin_guard_biases_toward_restrictive(tmp_path: Path) -> None:
    # With a maximal margin threshold every case is "ambiguous" and must resolve
    # to the more restrictive of the top two classes — never up toward SAFE.
    dst = tmp_path / "artifacts"
    shutil.copytree(ARTIFACTS, dst)
    manifest = JudgeManifest.load(dst / "judge_manifest.json")
    strict = manifest.model_copy(update={"margin": 1.0})
    strict.write(dst / "judge_manifest.json")

    judge = SafetyJudge(dst / "judge_manifest.json")
    result = judge.evaluate(_benign_read())
    # A benign read would be SAFE at the default margin; the guard drops it.
    assert result.verdict is not JudgeVerdict.SAFE


def test_fail_closed_on_model_hash_drift(tmp_path: Path) -> None:
    dst = tmp_path / "artifacts"
    shutil.copytree(ARTIFACTS, dst)
    # Corrupt the ONNX bytes so the pinned hash no longer matches.
    onnx = dst / "judge_mlp.onnx"
    data = bytearray(onnx.read_bytes())
    data[-1] ^= 0xFF
    onnx.write_bytes(bytes(data))
    with pytest.raises(CVZTTEError) as exc:
        SafetyJudge(dst / "judge_manifest.json")
    assert exc.value.code == ErrorCode.JUDGE_FAILED


def test_fail_closed_on_feature_drift(tmp_path: Path) -> None:
    dst = tmp_path / "artifacts"
    shutil.copytree(ARTIFACTS, dst)
    manifest = JudgeManifest.load(dst / "judge_manifest.json")
    drifted = manifest.model_copy(update={"feature_names": FEATURE_NAMES[:-1] + ["renamed"]})
    drifted.write(dst / "judge_manifest.json")
    with pytest.raises(CVZTTEError) as exc:
        SafetyJudge(dst / "judge_manifest.json")
    assert exc.value.code == ErrorCode.JUDGE_FAILED


def test_binding_commitment_is_deterministic() -> None:
    judge = SafetyJudge()
    inp = _benign_read()
    r1 = judge.evaluate(inp)
    r2 = judge.evaluate(inp)
    assert judge.binding_commitment(r1) == judge.binding_commitment(r2)
    assert judge.binding_commitment(r1).startswith("sha256:")
