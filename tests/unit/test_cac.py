"""CAC registries, envelopes & permission gate (spec §35-§47) — no native broker."""

from __future__ import annotations

import pytest

from cvztte.action.model import DataClassification
from cvztte.cac import (
    CACPermission,
    CiphertextEnvelope,
    ContextStatus,
    FHEContext,
    FHEContextRegistry,
    FHEProgramRegistry,
    ProgramId,
    REFERENCE_ROLE_GRANTS,
    SecurityProfile,
    assert_no_substitution,
    ceiling_for,
    effective_cac_permissions,
    require_compute,
    require_decrypt,
)
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode


def _ctx(**kw) -> FHEContext:
    base = dict(
        context_id="ckks-v1", openfhe_version="1.5.1",
        security_profile=SecurityProfile.SECURE_LAB, multiplicative_depth=2,
        scaling_mod_size=50, batch_size=8, key_epoch=3,
    )
    base.update(kw)
    return FHEContext(**base)


def _envelope(ctx: FHEContext, **kw) -> CiphertextEnvelope:
    allowed = kw.pop("allowed", ["SUM_V1"])
    base = dict(
        dataset_id="ds1", ciphertext_id="ct_1", context_id=ctx.context_id,
        context_hash=ctx.context_hash(), key_epoch=ctx.key_epoch,
        classification=DataClassification.CONFIDENTIAL, owner="data_owner",
        ciphertext_hash="sha256:" + "aa" * 32, created_at="2026-09-07T00:00:00Z",
        allowed_programs=allowed,
        allowed_program_set_hash=commit(Domain.FHE_PROGRAM, sorted(allowed)),
    )
    base.update(kw)
    return CiphertextEnvelope(schema="vector<double>[batch]", **base)


# --- context registry (§37) ---

def test_agent_cannot_substitute_context() -> None:
    reg = FHEContextRegistry()
    ctx = _ctx()
    reg.register(ctx)
    # Substituted (different) hash is rejected fail-closed.
    with pytest.raises(CVZTTEError) as exc:
        reg.require_active("ckks-v1", expected_hash="sha256:" + "00" * 32)
    assert exc.value.code == ErrorCode.FHE_CONTEXT_MISMATCH


def test_unknown_context_rejected() -> None:
    with pytest.raises(CVZTTEError) as exc:
        FHEContextRegistry().get("nope")
    assert exc.value.code == ErrorCode.FHE_CONTEXT_UNKNOWN


def test_retired_context_rejected() -> None:
    reg = FHEContextRegistry()
    ctx = _ctx(status=ContextStatus.RETIRED)
    reg.register(ctx)
    with pytest.raises(CVZTTEError) as exc:
        reg.require_active("ckks-v1", expected_hash=ctx.context_hash())
    assert exc.value.code == ErrorCode.FHE_CONTEXT_UNAPPROVED


# --- program registry (§39) ---

def test_unlisted_program_rejected() -> None:
    reg = FHEProgramRegistry(programs=[])
    with pytest.raises(CVZTTEError) as exc:
        reg.get(ProgramId.SUM_V1)
    assert exc.value.code == ErrorCode.FHE_PROGRAM_UNKNOWN


def test_program_depth_exceeding_context_rejected() -> None:
    reg = FHEProgramRegistry()
    # AVERAGE_V1 has depth 1; a depth-0 context cannot run it.
    with pytest.raises(CVZTTEError) as exc:
        reg.require(ProgramId.AVERAGE_V1, context_depth=0)
    assert exc.value.code == ErrorCode.FHE_PROGRAM_DENIED


def test_default_programs_present() -> None:
    reg = FHEProgramRegistry()
    for pid in (ProgramId.SUM_V1, ProgramId.AVERAGE_V1, ProgramId.WEIGHTED_SCORE_V1):
        assert reg.get(pid).program_id is pid


# --- envelopes (§38) ---

def test_envelope_substitution_key_epoch_rejected() -> None:
    ctx = _ctx()
    env = _envelope(ctx)
    with pytest.raises(CVZTTEError) as exc:
        assert_no_substitution(
            env, expected_context_id="ckks-v1",
            expected_context_hash=ctx.context_hash(), expected_key_epoch=99,
        )
    assert exc.value.code == ErrorCode.FHE_KEY_EPOCH_MISMATCH


def test_envelope_substitution_context_rejected() -> None:
    ctx = _ctx()
    env = _envelope(ctx)
    with pytest.raises(CVZTTEError) as exc:
        assert_no_substitution(
            env, expected_context_id="other",
            expected_context_hash=ctx.context_hash(), expected_key_epoch=3,
        )
    assert exc.value.code == ErrorCode.FHE_CONTEXT_MISMATCH


def test_envelope_no_substitution_ok() -> None:
    ctx = _ctx()
    env = _envelope(ctx)
    assert_no_substitution(
        env, expected_context_id="ckks-v1",
        expected_context_hash=ctx.context_hash(), expected_key_epoch=3,
    )
    assert env.allows_program("SUM_V1")
    assert not env.allows_program("WEIGHTED_SCORE_V1")


# --- permission model + containment ceilings (§35, §42, §47) ---

def test_compute_authority_does_not_imply_decrypt() -> None:
    granted = REFERENCE_ROLE_GRANTS["analytics_agent"]
    # Compute is fine at NORMAL...
    require_compute(granted, ContainmentState.NORMAL)
    # ...but decrypt is not implied.
    with pytest.raises(CVZTTEError) as exc:
        require_decrypt(granted, ContainmentState.NORMAL)
    assert exc.value.code == ErrorCode.FHE_DECRYPT_DENIED


def test_restricted_forbids_decrypt_even_for_owner() -> None:
    granted = REFERENCE_ROLE_GRANTS["data_owner"]
    require_compute(granted, ContainmentState.RESTRICTED)  # compute still allowed
    with pytest.raises(CVZTTEError) as exc:
        require_decrypt(granted, ContainmentState.RESTRICTED)
    assert exc.value.code == ErrorCode.FHE_DECRYPT_DENIED


def test_quarantined_forbids_all_cac() -> None:
    granted = REFERENCE_ROLE_GRANTS["data_owner"]
    assert effective_cac_permissions(granted, ContainmentState.QUARANTINED) == frozenset()
    with pytest.raises(CVZTTEError):
        require_compute(granted, ContainmentState.QUARANTINED)


def test_ceiling_matches_spec() -> None:
    assert CACPermission.DECRYPT_RESULT in ceiling_for(ContainmentState.NORMAL)
    assert CACPermission.DECRYPT_RESULT not in ceiling_for(ContainmentState.SUSPICIOUS)
    assert ceiling_for(ContainmentState.SUSPICIOUS) == frozenset(
        {CACPermission.COMPUTE_ON_CIPHERTEXT}
    )
    assert ceiling_for(ContainmentState.TERMINATED) == frozenset()
