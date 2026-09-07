"""Adversarial family: identity / integrity / replay / policy (§51, §60.31 #1-21).

Every case is driven through the Phase 17 ``ControlPlane.evaluate`` pipeline (the
same path a real agent uses) and asserts the two mandatory invariants: the attack
raises a ``CVZTTEError`` (never an implicit ALLOW) and no token is minted / no
side-effect occurs.
"""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.control_plane import InMemoryReplayGuard
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.request.builder import _now

from lab import AGENT, POLICY_HASH, RUNTIME, AdversarialLab


def _evaluate(lab: AdversarialLab, envelope):
    """Run one attack through the pipeline; return the raised error."""
    with pytest.raises(CVZTTEError) as exc:
        lab.agent.evaluate(envelope, grant=lab.grant(), audience=lab.broker.audience)
    lab.assert_no_side_effects()
    return exc.value


def _mutate_sig(envelope, index=5):
    raw = bytearray(base64.b64decode(envelope.signature_b64))
    raw[index] ^= 0x01
    return envelope.model_copy(
        update={"signature_b64": base64.b64encode(bytes(raw)).decode()}
    )


# #2 wrong public key / #1 forged agent -------------------------------------


def test_case01_forged_unknown_agent(registry, tmp_path, allow_decision):
    lab = AdversarialLab(registry, tmp_path, decision=allow_decision)
    with pytest.raises(CVZTTEError) as exc:
        lab.plane.create_session(agent_id="agt_forged", runtime_id=RUNTIME)
    assert exc.value.code in (ErrorCode.AGENT_UNKNOWN, ErrorCode.AGENT_DISABLED)


def test_case03_signature_byte_mutation(lab):
    sess = lab.open_session()
    env = _mutate_sig(lab.sign(sess.session_id, action=lab.file_action()))
    assert _evaluate(lab, env).code is ErrorCode.MLDSA_INVALID


def test_case04_revoked_key(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    lab.registry.revoke(env.request.key_id, reason="compromise")
    assert _evaluate(lab, env).code is ErrorCode.KEY_REVOKED


def test_case05_key_id_substitution_unknown(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    tampered = env.model_copy(
        update={"request": env.request.model_copy(update={"key_id": "key_does_not_exist"})}
    )
    # key_id is signature-covered; substituting it breaks the signature or is unknown.
    assert _evaluate(lab, tampered).code in (ErrorCode.MLDSA_INVALID, ErrorCode.KEY_UNKNOWN)


def test_case07_action_argument_mutation(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    mutated_action = env.request.action.model_copy(update={"arguments": {"evil": "1"}})
    tampered = env.model_copy(
        update={"request": env.request.model_copy(update={"action": mutated_action})}
    )
    assert _evaluate(lab, tampered).code is ErrorCode.ACTION_HASH_MISMATCH


def test_case08_target_mutation(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    mutated_action = env.request.action.model_copy(update={"target": "fs:/etc/shadow"})
    tampered = env.model_copy(
        update={"request": env.request.model_copy(update={"action": mutated_action})}
    )
    assert _evaluate(lab, tampered).code is ErrorCode.ACTION_HASH_MISMATCH


def test_case09_action_type_mutation(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    mutated_action = env.request.action.model_copy(update={"action_type": ActionType.FILE_DELETE})
    tampered = env.model_copy(
        update={"request": env.request.model_copy(update={"action": mutated_action})}
    )
    assert _evaluate(lab, tampered).code is ErrorCode.ACTION_HASH_MISMATCH


def test_case10_session_mutation_breaks_signature(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    # session_id is signature-covered: changing it post-sign breaks the signature.
    tampered = env.model_copy(
        update={"request": env.request.model_copy(update={"session_id": "ses_hijacked"})}
    )
    assert _evaluate(lab, tampered).code is ErrorCode.MLDSA_INVALID


def test_case11_policy_hash_mutation(registry, tmp_path, allow_decision):
    # A plane that pins the policy hash rejects an envelope signed under another.
    lab = AdversarialLab(registry, tmp_path, decision=allow_decision, policy_hash=POLICY_HASH)
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action(),
                   policy_hash="sha256:" + "f" * 64)
    assert _evaluate(lab, env).code is ErrorCode.POLICY_HASH_MISMATCH


def test_case15_expired_request(lab):
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action(), ttl_seconds=1)
    with pytest.raises(CVZTTEError) as exc:
        lab.agent.evaluate(
            env, grant=lab.grant(), audience=lab.broker.audience,
            now=_now() + timedelta(hours=1),
        )
    assert exc.value.code is ErrorCode.REQUEST_EXPIRED
    lab.assert_no_side_effects()


# Replay family #12-14, #16 (through the plane with a real replay guard) -----


def _replay_lab(registry, tmp_path, allow_decision):
    lab = AdversarialLab(registry, tmp_path, decision=allow_decision)
    lab.plane._replay = InMemoryReplayGuard()  # wire the freshness guard
    return lab


def test_case12_13_exact_replay_and_nonce_reuse(registry, tmp_path, allow_decision):
    lab = _replay_lab(registry, tmp_path, allow_decision)
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    first = lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
    assert first.token is not None
    # Exact replay of the same signed envelope (same nonce) fails closed.
    assert _evaluate(lab, env).code is ErrorCode.NONCE_REPLAY


def test_case14_sequence_rollback(registry, tmp_path, allow_decision):
    lab = _replay_lab(registry, tmp_path, allow_decision)
    sess = lab.open_session()
    # Two independent envelopes: the builder auto-increments sequence, so we
    # forge a rollback by reusing the first sequence with a fresh nonce.
    e1 = lab.sign(sess.session_id, action=lab.file_action())
    lab.agent.evaluate(e1, grant=lab.grant(), audience=lab.broker.audience)
    e2 = lab.sign(sess.session_id, action=lab.file_action())
    rolled = e2.model_copy(
        update={"request": e2.request.model_copy(update={"sequence": e1.request.sequence})}
    )
    # The mutated sequence breaks the signature before the guard, but either way
    # it fails closed (never an ALLOW).
    assert _evaluate(lab, rolled).code in (
        ErrorCode.MLDSA_INVALID, ErrorCode.SEQUENCE_INVALID
    )


def test_case16_concurrent_duplicate_one_wins(registry, tmp_path, allow_decision):
    lab = _replay_lab(registry, tmp_path, allow_decision)
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
    # The duplicate (same nonce) is rejected — only one of the pair can win.
    assert _evaluate(lab, env).code is ErrorCode.NONCE_REPLAY
