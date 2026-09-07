"""Decision Token v3 tests (spec §31, §60.11) wired through the real broker.

These exercise the *production* `DecisionTokenValidator` (not the Phase 7 stub)
end to end: the authority mints a MAC-authenticated, epoch/audience/TTL-bound,
single-use token; the agent presents it; a real `FileBroker` mediates and
executes only on an exact match; every failure fails closed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cvztte.adapters.base import AdapterBinding
from cvztte.audit import AuditReceiptSink, AuditStage, HashChainedAuditLog
from cvztte.decision import (
    DecisionTokenAuthority,
    DecisionTokenValidator,
    EpochSet,
    EpochSource,
    PresentedTokenStore,
    SignedDecisionToken,
    TokenChecks,
    TokenDecision,
)
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.file_broker import FileBroker, FileRequest

KEY = b"k" * 32
BINDING = AdapterBinding(agent_id="agt_alice", runtime_id="rt_1", session_id="ses_1")
POLICY_HASH = "sha256:" + "de" * 32


def _wiring(epochs: EpochSet | None = None):
    epochs = epochs or EpochSet()
    authority = DecisionTokenAuthority(KEY)
    store = PresentedTokenStore()
    source = EpochSource(epochs)
    validator = DecisionTokenValidator(mac_key=KEY, epoch_source=source, store=store)
    return authority, store, source, validator


def _issue_for(authority, broker, request, binding=BINDING, **kw):
    action = broker.observe(request, binding)
    return authority.issue(
        action=action, binding=binding, audience=broker.audience,
        policy_hash=POLICY_HASH, epochs=kw.pop("epochs", EpochSet()),
        checks=TokenChecks(mldsa=True, opa=True, gnark=True, behavior=True,
                           judge="SAFE", ezkl=True),
        **kw,
    )


def test_happy_path_executes_and_audits(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring()
    log = HashChainedAuditLog()
    fb = FileBroker(str(tmp_path), validator, AuditReceiptSink(log))
    req = FileRequest("a.txt", "write", b"hello")

    store.present(_issue_for(authority, fb, req))
    out = fb.mediate(req, BINDING)

    assert (tmp_path / "a.txt").read_bytes() == b"hello"
    assert out.receipt.outcome == "EXECUTED"
    # Receipt landed in a verifiable hash chain.
    assert len(log) == 1
    assert log.events()[0].stage is AuditStage.RECEIPT
    assert log.verify() is True


def test_single_use_replay_rejected(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req = FileRequest("a.txt", "write", b"x")
    store.present(_issue_for(authority, fb, req))

    fb.mediate(req, BINDING)  # first use consumes the single-use token
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req, BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_REPLAY


def test_expired_token_rejected(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req = FileRequest("a.txt", "write", b"x")
    past = datetime.now(timezone.utc) - timedelta(seconds=60)
    store.present(_issue_for(authority, fb, req, ttl_seconds=1, now=past))
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req, BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_EXPIRED


def test_stale_epoch_rejected(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring(EpochSet(policy_epoch=1))
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req = FileRequest("a.txt", "write", b"x")
    store.present(_issue_for(authority, fb, req, epochs=EpochSet(policy_epoch=1)))
    # A policy change advances the epoch, invalidating the in-flight token.
    source.set(EpochSet(policy_epoch=2))
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req, BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_EPOCH_STALE


def test_mac_tamper_rejected(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req = FileRequest("a.txt", "write", b"x")
    signed = _issue_for(authority, fb, req)
    tampered = SignedDecisionToken(token=signed.token, mac="hmac-sha256:" + "00" * 32)
    store.present(tampered)
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req, BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_INVALID


def test_cross_action_token_cannot_execute_other_action(tmp_path: Path) -> None:
    # §4.11: a token minted for action A must not authorize action B.
    authority, store, source, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req_a = FileRequest("a.txt", "write", b"x")
    store.present(_issue_for(authority, fb, req_a))
    req_b = FileRequest("b.txt", "write", b"x")  # different action, no token
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req_b, BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_INVALID
    assert not (tmp_path / "b.txt").exists()


def test_binding_mismatch_rejected(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req = FileRequest("a.txt", "write", b"x")
    store.present(_issue_for(authority, fb, req))  # bound to agt_alice
    other = AdapterBinding(agent_id="agt_bob", runtime_id="rt_1", session_id="ses_1")
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req, other)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_INVALID


def test_deny_token_does_not_execute(tmp_path: Path) -> None:
    authority, store, source, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    req = FileRequest("a.txt", "write", b"x")
    store.present(_issue_for(authority, fb, req, decision=TokenDecision.DENY))
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(req, BINDING)
    assert exc.value.code == ErrorCode.ENFORCEMENT_DENIED
    assert not (tmp_path / "a.txt").exists()


def test_no_token_presented_is_denied(tmp_path: Path) -> None:
    # Bypass attempt: reach a broker with no matching token.
    _, store, _, validator = _wiring()
    fb = FileBroker(str(tmp_path), validator, _sink_log())
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(FileRequest("a.txt", "write", b"x"), BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_INVALID


def test_audience_mismatch_rejected() -> None:
    # White-box: a token filed under a different audience than its own field.
    from cvztte.action.model import ActionType, AgentAction

    authority, store, source, validator = _wiring()
    action = AgentAction(action_type=ActionType.FILE_WRITE, target="a.txt", operation="write")
    signed = authority.issue(
        action=action, binding=BINDING, audience="file-broker-01",
        policy_hash=POLICY_HASH, epochs=EpochSet(),
    )
    # Simulate presentation misfiled under a different audience key.
    store._by_key[("egress-proxy-01", action.action_hash())] = signed  # noqa: SLF001
    with pytest.raises(CVZTTEError) as exc:
        validator.authorize(
            action=action, action_hash=action.action_hash(),
            binding=BINDING, audience="egress-proxy-01",
        )
    assert exc.value.code == ErrorCode.DECISION_TOKEN_AUDIENCE_MISMATCH


def _sink_log() -> AuditReceiptSink:
    return AuditReceiptSink(HashChainedAuditLog())
