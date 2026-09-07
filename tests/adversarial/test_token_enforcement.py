"""Adversarial family: enforcement mediation / Decision Token binding
(§51 Enforcement, §60.31 #42-45, #68, #72-80, #96).

Each attack is driven through the real ``FileBroker``, which independently
re-observes the operation and re-validates the presented token. Every DENY
asserts fail-closed (a ``CVZTTEError``), a ``"DENIED"``/``"FAILED"`` receipt, and
zero protected side-effects (the target file never appears).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.request.builder import _now
from enforcement.file_broker import FileRequest


# #45 / #80 token for action A used on action B ------------------------------


def test_case45_token_A_cannot_execute_action_B(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    action_a = lab.observe(FileRequest("a.txt", "write", b"A"), binding)
    lab.present(lab.issue_token(action=action_a, binding=binding))

    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(FileRequest("b.txt", "write", b"B"), binding)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_INVALID
    assert not (lab.workspace / "b.txt").exists()
    lab.assert_no_side_effects()


# #72 token replay (single-use) ---------------------------------------------


def test_case72_token_single_use_replay(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    req = FileRequest("once.txt", "write", b"data")
    action = lab.observe(req, binding)
    lab.present(lab.issue_token(action=action, binding=binding))

    out = lab.broker.mediate(req, binding)
    assert out.receipt.outcome == "EXECUTED"
    lab.ledger.snapshot()  # the legit write is authorized; measure from here

    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, binding)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_REPLAY
    lab.assert_no_side_effects()  # no *second* write


# #73 token used by another agent -------------------------------------------


def test_case73_token_bound_to_other_agent(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    req = FileRequest("x.txt", "write", b"x")
    action = lab.observe(req, binding)
    lab.present(lab.issue_token(action=action, binding=binding))

    attacker = lab.binding(sess.session_id, agent_id="agt_bob")
    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, attacker)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_INVALID
    assert not (lab.workspace / "x.txt").exists()
    lab.assert_no_side_effects()


# #74 token used by another runtime -----------------------------------------


def test_case74_token_bound_to_other_runtime(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    req = FileRequest("y.txt", "write", b"y")
    action = lab.observe(req, binding)
    lab.present(lab.issue_token(action=action, binding=binding))

    attacker = lab.binding(sess.session_id, runtime_id="runtime_evil")
    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, attacker)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_INVALID
    assert not (lab.workspace / "y.txt").exists()
    lab.assert_no_side_effects()


# #75 wrong enforcement audience --------------------------------------------


def test_case75_wrong_audience_misfiled_token(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    req = FileRequest("z.txt", "write", b"z")
    action = lab.observe(req, binding)
    # A token minted for a different audience, misfiled under the file broker's key.
    signed = lab.issue_token(action=action, binding=binding, audience="egress-proxy-01")
    lab.store._by_key[(lab.broker.audience, action.action_hash())] = signed

    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, binding)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_AUDIENCE_MISMATCH
    assert not (lab.workspace / "z.txt").exists()
    lab.assert_no_side_effects()


# #44 / #76 expired token ---------------------------------------------------


def test_case76_expired_token(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    req = FileRequest("exp.txt", "write", b"e")
    action = lab.observe(req, binding)
    past = _now() - timedelta(hours=1)
    lab.present(lab.issue_token(action=action, binding=binding, ttl_seconds=1, now=past))

    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, binding)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_EXPIRED
    assert not (lab.workspace / "exp.txt").exists()
    lab.assert_no_side_effects()


# #78 runtime kill switch invalidates in-flight token (stale epoch) ----------


def test_case78_79_kill_switch_makes_token_stale(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    req = FileRequest("stale.txt", "write", b"s")
    action = lab.observe(req, binding)
    lab.present(lab.issue_token(action=action, binding=binding))

    # A containment escalation bumps the shared capability_epoch; the token minted
    # under the old epoch is now stale (§79 policy/capability epoch invalidation).
    subject = f"{binding.agent_id}|{binding.runtime_id}|{binding.session_id}"
    lab.admin.quarantine("admin_root", subject=subject, agent_id=binding.agent_id,
                         runtime_id=binding.runtime_id)

    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, binding)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_EPOCH_STALE
    assert not (lab.workspace / "stale.txt").exists()
    lab.assert_no_side_effects()


# #49 / #102 no token presented (SDK/enforcement bypass) --------------------


def test_case49_direct_broker_no_token(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(FileRequest("bypass.txt", "write", b"b"), binding)
    assert exc.value.code is ErrorCode.DECISION_TOKEN_INVALID
    assert not (lab.workspace / "bypass.txt").exists()
    lab.assert_no_side_effects()


# #144 DENY-effect token never executes -------------------------------------


def test_deny_effect_token_blocks(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    from cvztte.decision.model import TokenDecision

    req = FileRequest("deny.txt", "write", b"d")
    action = lab.observe(req, binding)
    lab.present(lab.issue_token(action=action, binding=binding, decision=TokenDecision.DENY))
    with pytest.raises(CVZTTEError) as exc:
        lab.broker.mediate(req, binding)
    assert exc.value.code is ErrorCode.ENFORCEMENT_DENIED
    assert not (lab.workspace / "deny.txt").exists()
    lab.assert_no_side_effects()


# #68 File Broker path traversal / escape -----------------------------------


def test_case68_path_traversal_escape(lab):
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    with pytest.raises(CVZTTEError) as exc:
        # Traversal is caught fail-closed regardless of any token.
        lab.broker.mediate(FileRequest("../escape.txt", "write", b"nope"), binding)
    assert exc.value.code in (ErrorCode.FILE_PATH_ESCAPE, ErrorCode.FINAL_ACTION_BINDING_FAILED,
                              ErrorCode.DECISION_TOKEN_INVALID)
    assert not (lab.workspace.parent / "escape.txt").exists()
    lab.assert_no_side_effects()
