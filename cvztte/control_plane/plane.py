"""CV-ZTTE Control Plane orchestrator (spec §17, §54 Phase 17, §60.29).

This is the integration seam that ties the phase-by-phase library into one
authorization pipeline and drives the §60.29 API. It composes, in order and
fail-closed at every step:

1. **identity / integrity / freshness** — :func:`verify_request` (ML-DSA, action
   binding, expiry) + an atomic replay/sequence commit;
2. **session** — the session must be active and bound to the agent/runtime;
3. **containment** — a RESTRICTED+ subject cannot mint new consequential tokens
   (§26); containment can only remove authority;
4. **policy / risk** — OPA authorizes and supplies the risk tier (hard DENY is
   final, §13); risk *is* ``PolicyDecision.risk_level``;
5. **approval** — if policy requires human approval, the decision is parked
   ``PENDING_APPROVAL`` and NO executable token is minted until granted (§28);
6. **mint + present** — the sole :class:`DecisionTokenAuthority` mints a
   short-lived, single-use, execution-bound token under the current epoch
   snapshot and presents it at the enforcement audience;
7. **execute** (``evaluate_execute`` only) — the enforcement broker independently
   re-observes the action, re-validates the token, and executes only on exact
   match (§16, §4.11).

Nothing here can turn a security error into an ALLOW. Errors propagate as
:class:`CVZTTEError`; the API layer maps them to the §60.30 taxonomy.
"""

from __future__ import annotations

import enum
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

from cvztte.action.model import AgentAction
from cvztte.adapters.base import AdapterBinding
from cvztte.containment.engine import ContainmentEngine, RecoveryMethod
from cvztte.control_plane.approval import ApprovalStore
from cvztte.control_plane.replay import ReplayGuardProtocol
from cvztte.decision.authority import DecisionTokenAuthority
from cvztte.decision.model import (
    ContainmentState,
    EpochSet,
    SignedDecisionToken,
    TokenChecks,
    TokenDecision,
)
from cvztte.decision.validator import PresentedTokenStore
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity.registry import KeyRegistry
from cvztte.policy.model import PolicyDecision, RiskTier
from cvztte.policy.opa_client import OPAClient
from cvztte.policy.opa_input import Grant, build_authz_input
from cvztte.request.model import SignedEnvelope
from cvztte.request.verify import verify_request
from cvztte.session.model import Session, SessionStore
from enforcement.common import EnforcementBroker, MediationOutcome

#: States that block minting new consequential tokens, mapped to their code.
_CONTAINMENT_BLOCK_CODES = {
    ContainmentState.RESTRICTED: ErrorCode.CONTAINMENT_RESTRICTED,
    ContainmentState.QUARANTINED: ErrorCode.CONTAINMENT_QUARANTINED,
    ContainmentState.TERMINATED: ErrorCode.CONTAINMENT_TERMINATED,
}


def containment_subject(binding: AdapterBinding) -> str:
    """Stable per-(agent, runtime, session) containment subject key."""
    return f"{binding.agent_id}|{binding.runtime_id}|{binding.session_id}"


class DecisionStatus(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    PENDING_APPROVAL = "PENDING_APPROVAL"


class EvaluationResult(BaseModel):
    """Public result of an evaluate / approve step (never leaks internals)."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    status: DecisionStatus
    decision_id: str
    agent_id: str
    action_hash: str
    audience: str
    risk_level: int
    containment_state: ContainmentState
    reason_code: str
    approval_id: str | None = None
    #: The presented token, only on ALLOW. The MAC stays internal to the token.
    token: SignedDecisionToken | None = None

    def public_view(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "action_hash": self.action_hash,
            "audience": self.audience,
            "risk_level": self.risk_level,
            "containment_state": self.containment_state.value,
            "reason_code": self.reason_code,
            "approval_id": self.approval_id,
            "token_issued": self.token is not None,
        }


@dataclass
class _PendingMint:
    """The context parked for a PENDING_APPROVAL decision so approve() can mint."""

    action: AgentAction
    binding: AdapterBinding
    audience: str
    policy_hash: str
    risk_level: int
    containment_state: ContainmentState
    checks: TokenChecks


@dataclass
class _DecisionEntry:
    result: EvaluationResult
    pending: _PendingMint | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ExecuteOutcome(BaseModel):
    """Result of evaluate_execute: the decision plus the mediation outcome."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    evaluation: EvaluationResult
    outcome: MediationOutcome | None = None


class ControlPlane:
    """The orchestrator behind the CV-ZTTE control-plane API (§60.29)."""

    def __init__(
        self,
        *,
        key_registry: KeyRegistry,
        session_store: SessionStore,
        opa_client: OPAClient,
        authority: DecisionTokenAuthority,
        presented_store: PresentedTokenStore,
        containment: ContainmentEngine,
        approvals: ApprovalStore | None = None,
        replay_guard: ReplayGuardProtocol | None = None,
        policy_hash: str = "",
        require_approval_from_tier: RiskTier = RiskTier.L4,
    ) -> None:
        self._keys = key_registry
        self._sessions = session_store
        self._opa = opa_client
        self._authority = authority
        self._store = presented_store
        self._containment = containment
        self._approvals = approvals or ApprovalStore()
        self._replay = replay_guard
        self._policy_hash = policy_hash
        self._require_approval_from_tier = require_approval_from_tier
        self._lock = threading.Lock()
        self._decisions: dict[str, _DecisionEntry] = {}

    # -- sessions -----------------------------------------------------------

    def create_session(
        self, *, agent_id: str, runtime_id: str, ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> Session:
        """POST /v3/sessions — the agent must already be a registered, enabled agent."""
        # Fail-closed: refuse to open a session for an unknown/disabled agent.
        self._keys._require_agent(agent_id)  # noqa: SLF001 - registry gate (raises AGENT_*)
        kwargs: dict[str, Any] = {"agent_id": agent_id, "runtime_id": runtime_id, "now": now}
        if ttl_seconds is not None:
            kwargs["ttl_seconds"] = ttl_seconds
        return self._sessions.create(**kwargs)

    # -- evaluation ---------------------------------------------------------

    def evaluate(
        self,
        envelope: SignedEnvelope,
        *,
        grant: Grant,
        audience: str,
        destination_domain: str | None = None,
        row_count: int | None = None,
        byte_count: int | None = None,
        now: datetime | None = None,
    ) -> EvaluationResult:
        """POST /v3/actions/evaluate — authorize (mint) without executing."""
        now = now or datetime.now(timezone.utc)

        # 1. identity / integrity / freshness (raises on any defect).
        request = verify_request(
            self._keys, envelope, now=now,
            expected_policy_hash=self._policy_hash or None,
        )
        action = request.action
        binding = AdapterBinding(
            agent_id=request.agent_id,
            runtime_id=request.runtime_id,
            session_id=request.session_id,
            delegation_id=request.delegation_id or None,
        )

        # 2. atomic replay/sequence commit (§11). Skipped only if no guard wired.
        if self._replay is not None:
            self._replay.check_and_commit(
                session_id=request.session_id, nonce=request.nonce, sequence=request.sequence
            )

        # 3. session must be active and bound to this agent/runtime.
        self._sessions.validate(
            request.session_id, agent_id=request.agent_id,
            runtime_id=request.runtime_id, now=now,
        )

        # 4. containment gate — a contained subject cannot gain new authority (§26).
        subject = containment_subject(binding)
        state = self._containment.state(subject)
        if self._containment.blocks_new_consequential_tokens(subject):
            raise CVZTTEError(
                _CONTAINMENT_BLOCK_CODES.get(state, ErrorCode.CONTAINMENT_RESTRICTED),
                "subject is contained; new consequential tokens are blocked",
                detail={"containment_state": state.value},
            )

        # 5. policy / risk — OPA authorizes; hard DENY is final (§13).
        opa_input = build_authz_input(
            action, grant, destination_domain=destination_domain,
            row_count=row_count, byte_count=byte_count,
        )
        decision: PolicyDecision = self._opa.authorize(opa_input)

        decision_id = "dec_" + uuid.uuid4().hex
        checks = TokenChecks(mldsa=True, opa=True)

        # 6. approval requirement — park PENDING_APPROVAL and mint nothing yet (§28).
        needs_approval = (
            decision.require_human_approval
            or decision.risk_level >= self._require_approval_from_tier.value
        )
        if needs_approval:
            self._approvals.request(
                decision_id=decision_id,
                agent_id=request.agent_id,
                action_hash=action.action_hash(),
                risk_level=decision.risk_level,
                classification=action.data_classification.value,
                now=now,
            )
            appr = self._approvals.by_decision(decision_id)
            result = EvaluationResult(
                status=DecisionStatus.PENDING_APPROVAL,
                decision_id=decision_id,
                agent_id=request.agent_id,
                action_hash=action.action_hash(),
                audience=audience,
                risk_level=decision.risk_level,
                containment_state=state,
                reason_code=ErrorCode.APPROVAL_REQUIRED.value,
                approval_id=appr.approval_id if appr else None,
            )
            with self._lock:
                self._decisions[decision_id] = _DecisionEntry(
                    result=result,
                    pending=_PendingMint(
                        action=action, binding=binding, audience=audience,
                        policy_hash=request.policy_hash, risk_level=decision.risk_level,
                        containment_state=state, checks=checks,
                    ),
                )
            return result

        # 7. mint + present the execution-bound token under the current epochs.
        result = self._mint(
            decision_id=decision_id, action=action, binding=binding, audience=audience,
            policy_hash=request.policy_hash, risk_level=decision.risk_level,
            containment_state=state, reason_code=decision.reason_code, checks=checks, now=now,
        )
        with self._lock:
            self._decisions[decision_id] = _DecisionEntry(result=result)
        return result

    def _mint(
        self, *, decision_id: str, action: AgentAction, binding: AdapterBinding,
        audience: str, policy_hash: str, risk_level: int,
        containment_state: ContainmentState, reason_code: str, checks: TokenChecks,
        now: datetime,
    ) -> EvaluationResult:
        signed = self._authority.issue(
            action=action, binding=binding, audience=audience, policy_hash=policy_hash,
            epochs=self._containment.current_epochs(), decision=TokenDecision.ALLOW,
            risk_level=risk_level, containment_state=containment_state, checks=checks,
            request_id=decision_id, now=now,
        )
        self._store.present(signed)
        return EvaluationResult(
            status=DecisionStatus.ALLOW,
            decision_id=decision_id,
            agent_id=binding.agent_id,
            action_hash=action.action_hash(),
            audience=audience,
            risk_level=risk_level,
            containment_state=containment_state,
            reason_code=reason_code,
            token=signed,
        )

    def approve(
        self, decision_id: str, *, approver: str, now: datetime | None = None
    ) -> EvaluationResult:
        """POST /v3/approvals/{decision_id} — grant approval and mint the token."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            entry = self._decisions.get(decision_id)
            pending = entry.pending if entry else None
        if entry is None:
            raise CVZTTEError(ErrorCode.APPROVAL_REQUIRED, "unknown decision")
        if pending is None:
            raise CVZTTEError(
                ErrorCode.APPROVAL_REQUIRED, "decision does not require approval"
            )

        # Grant, then re-assert (defends against expiry between grant and mint).
        self._approvals.grant(decision_id, approver=approver, now=now)
        approval = self._approvals.assert_granted(decision_id, now=now)

        # Re-check containment at mint time — approval never overrides containment.
        subject = containment_subject(pending.binding)
        state = self._containment.state(subject)
        if self._containment.blocks_new_consequential_tokens(subject):
            raise CVZTTEError(
                _CONTAINMENT_BLOCK_CODES.get(state, ErrorCode.CONTAINMENT_RESTRICTED),
                "subject became contained; approval cannot mint",
                detail={"containment_state": state.value},
            )

        result = self._mint(
            decision_id=decision_id, action=pending.action, binding=pending.binding,
            audience=pending.audience, policy_hash=pending.policy_hash,
            risk_level=pending.risk_level, containment_state=state,
            reason_code="APPROVED", checks=pending.checks, now=now,
        )
        result = result.model_copy(update={"approval_id": approval.approval_id})
        with self._lock:
            self._decisions[decision_id] = _DecisionEntry(result=result)
        return result

    def deny_approval(
        self, decision_id: str, *, approver: str, reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecordView:
        """Deny a pending approval; the decision can never mint (fail-closed)."""
        rec = self._approvals.deny(decision_id, approver=approver, reason=reason, now=now)
        return ApprovalRecordView.model_validate(rec.public_view())

    def get_decision(self, decision_id: str) -> EvaluationResult:
        """GET /v3/decisions/{id}."""
        with self._lock:
            entry = self._decisions.get(decision_id)
        if entry is None:
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_INVALID, "unknown decision")
        return entry.result

    # -- evaluate + execute -------------------------------------------------

    def evaluate_execute(
        self,
        envelope: SignedEnvelope,
        *,
        grant: Grant,
        broker: EnforcementBroker,
        broker_request: Any,
        destination_domain: str | None = None,
        row_count: int | None = None,
        byte_count: int | None = None,
        now: datetime | None = None,
    ) -> ExecuteOutcome:
        """POST /v3/actions/evaluate-execute — authorize then mediate execution.

        The broker independently re-observes the operation and re-validates the
        token, so a token minted for action A cannot execute action B (§4.11).
        A PENDING_APPROVAL or non-ALLOW decision returns without executing.
        """
        evaluation = self.evaluate(
            envelope, grant=grant, audience=broker.audience,
            destination_domain=destination_domain, row_count=row_count,
            byte_count=byte_count, now=now,
        )
        if evaluation.status is not DecisionStatus.ALLOW:
            return ExecuteOutcome(evaluation=evaluation)

        binding = AdapterBinding(
            agent_id=envelope.request.agent_id,
            runtime_id=envelope.request.runtime_id,
            session_id=envelope.request.session_id,
            delegation_id=envelope.request.delegation_id or None,
        )
        outcome = broker.mediate(broker_request, binding)
        return ExecuteOutcome(evaluation=evaluation, outcome=outcome)

    # -- containment admin --------------------------------------------------

    def containment_status(self, subject: str) -> dict[str, Any]:
        """GET /v3/agents/{id}/containment (subject = agent|runtime|session)."""
        return {
            "subject": subject,
            "state": self._containment.state(subject).value,
            "blocks_new_consequential_tokens": self._containment.blocks_new_consequential_tokens(
                subject
            ),
            "transitions": [t.model_dump(mode="json") for t in self._containment.transitions(subject)],
            "epochs": self._containment.current_epochs().model_dump(mode="json"),
        }

    def quarantine(
        self, *, subject: str, agent_id: str, runtime_id: str | None,
        reason_codes: list[str], target: ContainmentState = ContainmentState.QUARANTINED,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """POST /v3/agents/{id}/quarantine — admin kill switch (§27)."""
        transition = self._containment.kill_switch(
            subject=subject, agent_id=agent_id, runtime_id=runtime_id,
            target_state=target, reason_codes=reason_codes, now=now,
        )
        return transition.model_dump(mode="json")

    def reset_containment(
        self, *, subject: str, agent_id: str, method: RecoveryMethod,
        approver: str | None = None, runtime_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """POST /v3/agents/{id}/containment/reset — method-gated recovery (§27, §60.19)."""
        transition = self._containment.recover(
            subject=subject, agent_id=agent_id, method=method, approver=approver,
            runtime_id=runtime_id, now=now,
        )
        return transition.model_dump(mode="json")

    # -- health -------------------------------------------------------------

    def health_live(self) -> dict[str, str]:
        """GET /health/live — process is up."""
        return {"status": "live"}

    def health_ready(self) -> dict[str, Any]:
        """GET /health/ready — required dependencies wired (fail-closed if not)."""
        checks = {
            "authority": self._authority is not None,
            "validator_store": self._store is not None,
            "opa": self._opa is not None,
            "containment": self._containment is not None,
            "identity": self._keys is not None,
        }
        return {"status": "ready" if all(checks.values()) else "not-ready", "checks": checks}


class ApprovalRecordView(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approval_id: str
    decision_id: str
    agent_id: str
    action_hash: str
    risk_level: int
    classification: str
    state: str
    approver: str | None = None
    requested_at: str
    expires_at: str
    decided_at: str | None = None
