"""Phase 3 SignedActionRequest assembly + verification (spec §10, §60.3)."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from cvztte.action.model import ActionType, AgentAction
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity import KeyRegistry, KeyState
from cvztte.request import RequestBuilder, verify_request
from cvztte.request.builder import _now


def _action() -> AgentAction:
    return AgentAction(action_type=ActionType.FILE_READ, target="/data/report.csv")


@pytest.fixture()
def ready(registry: KeyRegistry):
    registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    builder = RequestBuilder(registry)
    return registry, builder


def _build(builder: RequestBuilder, **overrides):
    kwargs = dict(
        agent_id="agt_alice",
        runtime_id="runtime_1",
        session_id="ses_1",
        delegation_id="dlg_1",
        policy_hash="sha256:" + "0" * 64,
        action=_action(),
    )
    kwargs.update(overrides)
    return builder.build_and_sign(**kwargs)


def test_valid_request_verifies(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    req = verify_request(registry, env)
    assert req.agent_id == "agt_alice"
    assert req.action_hash == req.action.action_hash()
    # nonce is >=128-bit hex, sequence starts at 0.
    assert len(req.nonce) >= 32
    assert req.sequence == 0


def test_sequence_is_monotonic_per_session(ready) -> None:
    _, builder = ready
    e0 = _build(builder)
    e1 = _build(builder)
    assert e0.request.sequence == 0
    assert e1.request.sequence == 1
    assert e0.request.nonce != e1.request.nonce  # fresh CSPRNG nonce each time


def test_action_mutation_detected(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    tampered = env.model_copy(
        update={
            "request": env.request.model_copy(
                update={"action": _action().model_copy(update={"target": "/etc/shadow"})}
            )
        }
    )
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, tampered)
    assert exc.value.code == ErrorCode.ACTION_HASH_MISMATCH


def test_field_mutation_breaks_signature(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    # Change a signature-covered field but keep action/action_hash consistent.
    tampered = env.model_copy(
        update={"request": env.request.model_copy(update={"sequence": 999})}
    )
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, tampered)
    assert exc.value.code == ErrorCode.MLDSA_INVALID


def test_signature_byte_mutation_rejected(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    raw = bytearray(base64.b64decode(env.signature_b64))
    raw[5] ^= 0x01
    tampered = env.model_copy(
        update={"signature_b64": base64.b64encode(bytes(raw)).decode()}
    )
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, tampered)
    assert exc.value.code == ErrorCode.MLDSA_INVALID


def test_expired_request_rejected(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    future = _now() + timedelta(hours=1)
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, env, now=future)
    assert exc.value.code == ErrorCode.REQUEST_EXPIRED


def test_revoked_key_request_rejected(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    registry.revoke(env.request.key_id, reason="compromise")
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, env)
    assert exc.value.code == ErrorCode.KEY_REVOKED


def test_key_bound_to_other_agent_rejected(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    # Forge an agent_id that does not own the signing key.
    forged = env.model_copy(
        update={"request": env.request.model_copy(update={"agent_id": "agt_mallory"})}
    )
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, forged)
    assert exc.value.code in (ErrorCode.MLDSA_INVALID, ErrorCode.ACTION_HASH_MISMATCH)


def test_policy_hash_pinning(ready) -> None:
    registry, builder = ready
    env = _build(builder)
    with pytest.raises(CVZTTEError) as exc:
        verify_request(registry, env, expected_policy_hash="sha256:" + "f" * 64)
    assert exc.value.code == ErrorCode.POLICY_HASH_MISMATCH
