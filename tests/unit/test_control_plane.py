"""Unit tests for the Control Plane orchestrator (spec §17, §54, §60.29).

These exercise the fail-closed pipeline with real ML-DSA identity, a real
DecisionTokenAuthority, and a real ContainmentEngine sharing one EpochSource.
OPA has no fake in the codebase, so we inject a directly-constructed
``PolicyDecision`` behind a tiny authorize() shim — the established pattern
(see tests/integration/test_judge.py).
"""

from __future__ import annotations

import pytest

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.containment.engine import ContainmentEngine, RecoveryMethod
from cvztte.control_plane import (
    AdminAuthorizer,
    AdminPlane,
    AgentPlane,
    ControlPlane,
    DecisionStatus,
    InMemoryReplayGuard,
    containment_subject,
)
from cvztte.decision.authority import DecisionTokenAuthority
from cvztte.decision.model import ContainmentState
from cvztte.decision.validator import (
    DecisionTokenValidator,
    EpochSource,
    PresentedTokenStore,
)
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity import KeyState
from cvztte.policy.model import PolicyDecision, RiskTier
from cvztte.policy.opa_input import Grant
from cvztte.request import RequestBuilder
from cvztte.session.model import SessionStore

KEY = b"k" * 32
POLICY_HASH = "sha256:" + "0" * 64
ADMIN = "admin_root"


class _FakeOPA:
    """Injects a pre-built PolicyDecision; mimics OPAClient.authorize semantics."""

    def __init__(self, decision: PolicyDecision, *, hard_deny: bool = False) -> None:
        self._decision = decision
        self._hard_deny = hard_deny

    def authorize(self, input_doc: dict) -> PolicyDecision:
        if self._hard_deny:
            raise CVZTTEError(ErrorCode.OPA_DENY, "policy hard deny")
        return self._decision


def _grant() -> Grant:
    return Grant(
        capabilities={"fs:read"},
        resource_scopes={"fs:/data"},
        clearance=DataClassification.CONFIDENTIAL,
    )


def _action() -> AgentAction:
    return AgentAction(
        action_type=ActionType.FILE_READ, target="fs:/data/report.csv", operation="read"
    )


class _Wiring:
    """A fully wired Control Plane + the shared EpochSource and a peer validator."""

    def __init__(self, registry, decision, *, hard_deny=False, replay=None,
                 require_tier=RiskTier.L4, suspicious_cooldown=300.0):
        registry.generate_key("agt_alice", state=KeyState.ACTIVE)
        self.registry = registry
        self.builder = RequestBuilder(registry)
        self.source = EpochSource()
        self.authority = DecisionTokenAuthority(KEY)
        self.store = PresentedTokenStore()
        self.sessions = SessionStore()
        self.containment = ContainmentEngine(
            epoch_source=self.source, suspicious_cooldown_seconds=suspicious_cooldown
        )
        self.opa = _FakeOPA(decision, hard_deny=hard_deny)
        self.validator = DecisionTokenValidator(
            mac_key=KEY, epoch_source=self.source, store=self.store
        )
        self.plane = ControlPlane(
            key_registry=registry, session_store=self.sessions, opa_client=self.opa,
            authority=self.authority, presented_store=self.store,
            containment=self.containment, replay_guard=replay,
            require_approval_from_tier=require_tier,
        )
        self.agent = AgentPlane(self.plane)
        self.admin = AdminPlane(
            self.plane, authorizer=AdminAuthorizer({ADMIN}),
            key_registry=registry, containment=self.containment,
        )

    def open_session(self):
        return self.plane.create_session(agent_id="agt_alice", runtime_id="runtime_1")

    def envelope(self, session_id, *, action=None):
        return self.builder.build_and_sign(
            agent_id="agt_alice", runtime_id="runtime_1", session_id=session_id,
            delegation_id="dlg_1", policy_hash=POLICY_HASH, action=action or _action(),
        )


@pytest.fixture()
def allow_decision():
    return PolicyDecision(allow=True, reason_code="ALLOW_OK", risk_level=1)


# -- happy path -------------------------------------------------------------


def test_evaluate_allow_mints_single_use_token(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    sess = w.open_session()
    result = w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")

    assert result.status is DecisionStatus.ALLOW
    assert result.token is not None
    # The token was presented at the audience keyed by the action hash.
    assert w.store.get("file-broker-01", result.action_hash) is not None
    # Public view never leaks the MAC / token internals.
    assert result.public_view()["token_issued"] is True
    assert "token" not in result.public_view()


def test_create_session_rejects_unknown_agent(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    with pytest.raises(CVZTTEError) as exc:
        w.plane.create_session(agent_id="agt_ghost", runtime_id="runtime_1")
    assert exc.value.code in (ErrorCode.AGENT_UNKNOWN, ErrorCode.AGENT_DISABLED)


# -- hard deny --------------------------------------------------------------


def test_evaluate_hard_deny_mints_nothing(registry, allow_decision):
    w = _Wiring(registry, allow_decision, hard_deny=True)
    sess = w.open_session()
    with pytest.raises(CVZTTEError) as exc:
        w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")
    assert exc.value.code is ErrorCode.OPA_DENY


# -- approval workflow ------------------------------------------------------


def test_high_risk_parks_pending_and_approve_mints(registry):
    decision = PolicyDecision(allow=True, reason_code="HIGH", risk_level=4)
    w = _Wiring(registry, decision, require_tier=RiskTier.L4)
    sess = w.open_session()
    result = w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")

    assert result.status is DecisionStatus.PENDING_APPROVAL
    assert result.token is None
    assert result.approval_id is not None
    # No token was presented while parked (fail-closed).
    assert w.store.get("file-broker-01", result.action_hash) is None

    approved = w.admin.approve(ADMIN, result.decision_id)
    assert approved.status is DecisionStatus.ALLOW
    assert approved.token is not None
    assert w.store.get("file-broker-01", result.action_hash) is not None


def test_require_human_approval_flag_parks_even_at_low_risk(registry):
    decision = PolicyDecision(
        allow=True, reason_code="NEEDS_HUMAN", risk_level=1, require_human_approval=True
    )
    w = _Wiring(registry, decision)
    sess = w.open_session()
    result = w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")
    assert result.status is DecisionStatus.PENDING_APPROVAL


def test_denied_approval_never_mints(registry):
    decision = PolicyDecision(allow=True, reason_code="HIGH", risk_level=4)
    w = _Wiring(registry, decision)
    sess = w.open_session()
    result = w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")

    w.admin.deny_approval(ADMIN, result.decision_id, reason="not this one")
    # A denied decision can never be granted afterwards.
    with pytest.raises(CVZTTEError) as exc:
        w.admin.approve(ADMIN, result.decision_id)
    assert exc.value.code is ErrorCode.APPROVAL_REQUIRED
    # And it stays PENDING_APPROVAL in the decision record (no token).
    assert w.plane.get_decision(result.decision_id).status is DecisionStatus.PENDING_APPROVAL


# -- containment gate -------------------------------------------------------


def test_containment_blocks_new_tokens(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    sess = w.open_session()
    subject = f"agt_alice|runtime_1|{sess.session_id}"
    w.admin.quarantine(ADMIN, subject=subject, agent_id="agt_alice", runtime_id="runtime_1")

    with pytest.raises(CVZTTEError) as exc:
        w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")
    assert exc.value.code is ErrorCode.CONTAINMENT_QUARANTINED


def test_quarantine_invalidates_outstanding_token_via_shared_epoch(registry, allow_decision):
    """Escalation bumps the shared capability_epoch, so the peer validator rejects
    a token minted a moment earlier (containment can only remove authority)."""
    w = _Wiring(registry, allow_decision)
    sess = w.open_session()
    result = w.agent.evaluate(w.envelope(sess.session_id), grant=_grant(), audience="file-broker-01")
    assert result.status is DecisionStatus.ALLOW

    before = w.source.current().capability_epoch
    subject = f"agt_alice|runtime_1|{sess.session_id}"
    w.admin.quarantine(ADMIN, subject=subject, agent_id="agt_alice", runtime_id="runtime_1")
    assert w.source.current().capability_epoch > before


# -- plane separation -------------------------------------------------------


def test_admin_plane_rejects_non_admin_principal(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    with pytest.raises(CVZTTEError) as exc:
        w.admin.quarantine("agt_alice", subject="s", agent_id="agt_alice", runtime_id="runtime_1")
    assert exc.value.code is ErrorCode.ENFORCEMENT_DENIED


def test_agent_plane_has_no_admin_methods():
    for attr in ("quarantine", "approve", "reset_containment", "register_agent",
                 "rotate_key", "revoke_key", "deny_approval"):
        assert not hasattr(AgentPlane, attr), f"AgentPlane must not expose {attr}"


def test_reset_containment_requires_admin_and_method(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    sess = w.open_session()
    subject = f"agt_alice|runtime_1|{sess.session_id}"
    w.admin.quarantine(ADMIN, subject=subject, agent_id="agt_alice", runtime_id="runtime_1")
    w.admin.reset_containment(
        ADMIN, subject=subject, agent_id="agt_alice", runtime_id="runtime_1",
        method=RecoveryMethod.ADMIN_APPROVAL,
    )
    assert w.plane.containment_status(subject)["state"] == ContainmentState.NORMAL.value


# -- replay / freshness -----------------------------------------------------


def test_replay_guard_rejects_reused_envelope(registry, allow_decision):
    w = _Wiring(registry, allow_decision, replay=InMemoryReplayGuard())
    sess = w.open_session()
    env = w.envelope(sess.session_id)
    first = w.agent.evaluate(env, grant=_grant(), audience="file-broker-01")
    assert first.status is DecisionStatus.ALLOW
    # Replaying the exact same signed envelope (same nonce) must fail closed.
    with pytest.raises(CVZTTEError) as exc:
        w.agent.evaluate(env, grant=_grant(), audience="file-broker-01")
    assert exc.value.code is ErrorCode.NONCE_REPLAY


# -- health & helpers -------------------------------------------------------


def test_health_endpoints(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    assert w.agent.health_live()["status"] == "live"
    ready = w.agent.health_ready()
    assert ready["status"] == "ready"
    assert all(ready["checks"].values())


def test_containment_subject_format():
    from cvztte.adapters.base import AdapterBinding

    b = AdapterBinding(agent_id="a", runtime_id="r", session_id="s")
    assert containment_subject(b) == "a|r|s"


def test_get_unknown_decision_fails_closed(registry, allow_decision):
    w = _Wiring(registry, allow_decision)
    with pytest.raises(CVZTTEError) as exc:
        w.plane.get_decision("dec_nope")
    assert exc.value.code is ErrorCode.DECISION_TOKEN_INVALID
