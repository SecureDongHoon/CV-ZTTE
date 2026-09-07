"""Audit chain + ML-DSA checkpoint tests (spec §32, §34)."""

from __future__ import annotations

from cvztte.audit import AuditStage, HashChainedAuditLog
from cvztte.identity import OpenSSLMLDSAProvider


def test_chain_links_and_verifies() -> None:
    log = HashChainedAuditLog()
    e0 = log.append(AuditStage.PROPOSED, {"action_hash": "sha256:aa"})
    e1 = log.append(AuditStage.AUTHORIZED, {"decision_id": "dec_1"})
    e2 = log.append(AuditStage.EXECUTED, {"result_hash": "sha256:bb"})
    assert e1.prev_hash == e0.event_hash()
    assert e2.prev_hash == e1.event_hash()
    assert [e.seq for e in log.events()] == [0, 1, 2]
    assert log.verify() is True


def test_tamper_is_detected() -> None:
    log = HashChainedAuditLog()
    log.append(AuditStage.PROPOSED, {"x": 1})
    log.append(AuditStage.EXECUTED, {"x": 2})
    # Retroactively edit a committed event's payload.
    log.events()  # snapshot copy, unaffected
    log._events[0].payload["x"] = 999  # noqa: SLF001 - simulate tampering
    assert log.verify() is False


def test_lifecycle_stages_recorded() -> None:
    log = HashChainedAuditLog()
    for stage in (
        AuditStage.PROPOSED,
        AuditStage.AUTHORIZED,
        AuditStage.TOKEN_ISSUED,
        AuditStage.ACTUAL_ACTION_OBSERVED,
        AuditStage.EXECUTED,
        AuditStage.RECEIPT,
    ):
        log.append(stage, {})
    assert [e.stage for e in log.events()][-1] is AuditStage.RECEIPT
    assert log.verify() is True


def test_mldsa_checkpoint_roundtrip(mldsa_provider: OpenSSLMLDSAProvider) -> None:
    log = HashChainedAuditLog()
    log.append(AuditStage.PROPOSED, {"x": 1})
    log.append(AuditStage.EXECUTED, {"x": 2})

    handle, public = mldsa_provider.generate_key()
    checkpoint = log.checkpoint(mldsa_provider, handle, public)

    assert checkpoint.covers_through_seq == 1
    assert checkpoint.head_hash == log.head_hash
    assert HashChainedAuditLog.verify_checkpoint(mldsa_provider, public, checkpoint) is True

    # A checkpoint over a different head must not verify against this one.
    log.append(AuditStage.RECEIPT, {"x": 3})
    stale = checkpoint.model_copy(update={"head_hash": log.head_hash})
    assert HashChainedAuditLog.verify_checkpoint(mldsa_provider, public, stale) is False
