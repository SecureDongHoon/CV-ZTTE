"""Adversarial family: containment (§51 Containment, §60.31 #96, #103-119).

Escalation is evidence-driven and escalate-only; a contained subject can never
regain authority, an agent can never self-reset, and an escalation invalidates
outstanding tokens through the shared EpochSource. Driven through the integrated
ControlPlane + ContainmentEngine.
"""

from __future__ import annotations

import pytest

from cvztte.containment.engine import RecoveryMethod
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode

from lab import AGENT, RUNTIME, AdversarialLab


def _subject(sess) -> str:
    return f"{AGENT}|{RUNTIME}|{sess.session_id}"


# #103 repeated policy denials cause escalation -----------------------------


def test_case103_repeated_denials_escalate(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    t = lab.containment.evaluate(subject=subject, agent_id=AGENT, features={"denials_60s": 3})
    assert t is not None
    assert lab.containment.state(subject) is ContainmentState.SUSPICIOUS


# #106 direct bypass raises containment / #107 secret probing ---------------


def test_case106_107_bypass_and_probe_escalate(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.containment.evaluate(subject=subject, agent_id=AGENT,
                             features={"bypass_attempts_5m": 3})
    assert lab.containment.state(subject) is ContainmentState.QUARANTINED


def test_case107_secret_exfiltration_flag_quarantines(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.containment.evaluate(subject=subject, agent_id=AGENT,
                             features={"secret_exfiltration_attempt": True})
    assert lab.containment.state(subject) is ContainmentState.QUARANTINED


# #96 / #114 quarantine blocks new consequential tokens ---------------------


def test_case96_114_quarantine_blocks_new_tokens(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)

    env = lab.sign(sess.session_id, action=lab.file_action())
    with pytest.raises(CVZTTEError) as exc:
        lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
    assert exc.value.code is ErrorCode.CONTAINMENT_QUARANTINED
    lab.assert_no_side_effects()


# #118 terminated runtime cannot obtain a token -----------------------------


def test_case118_terminated_cannot_obtain_token(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                         target=ContainmentState.TERMINATED)
    env = lab.sign(sess.session_id, action=lab.file_action())
    with pytest.raises(CVZTTEError) as exc:
        lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
    assert exc.value.code is ErrorCode.CONTAINMENT_TERMINATED
    lab.assert_no_side_effects()


# #110 capability set shrinks (escalate-only, no recovery by syntax) --------


def test_case110_containment_only_shrinks_authority(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    assert lab.containment.blocks_new_consequential_tokens(subject) is False
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)
    assert lab.containment.blocks_new_consequential_tokens(subject) is True
    # Re-evaluating with clean features must NOT de-escalate (escalate-only).
    lab.containment.evaluate(subject=subject, agent_id=AGENT, features={"denials_60s": 0})
    assert lab.containment.state(subject) is ContainmentState.QUARANTINED


# #115 agent cannot self-reset ----------------------------------------------


def test_case115_agent_plane_has_no_reset():
    from cvztte.control_plane import AgentPlane

    assert not hasattr(AgentPlane, "reset_containment")
    assert not hasattr(AgentPlane, "quarantine")


# #116 unauthorized de-escalation -------------------------------------------


def test_case116_unauthorized_deescalation_denied(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)
    # A non-admin principal cannot reset containment.
    with pytest.raises(CVZTTEError) as exc:
        lab.admin.reset_containment(AGENT, subject=subject, agent_id=AGENT,
                                    runtime_id=RUNTIME, method=RecoveryMethod.ADMIN_APPROVAL)
    assert exc.value.code is ErrorCode.ENFORCEMENT_DENIED
    assert lab.containment.state(subject) is ContainmentState.QUARANTINED


# #117 admin recovery is method-gated and audited ---------------------------


def test_case117_admin_recovery_restores_normal(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)
    lab.admin.reset_containment("admin_root", subject=subject, agent_id=AGENT,
                                runtime_id=RUNTIME, method=RecoveryMethod.ADMIN_APPROVAL)
    assert lab.containment.state(subject) is ContainmentState.NORMAL


# #119 repeated attack while quarantined reaches termination ----------------


def test_case119_escalate_to_termination(lab):
    sess = lab.open_session()
    subject = _subject(sess)
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)
    # Continued abuse: admin escalates quarantine to termination (per policy).
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                         target=ContainmentState.TERMINATED)
    assert lab.containment.state(subject) is ContainmentState.TERMINATED
