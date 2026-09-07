"""Agent-plane / Admin-plane separation (spec §60.29).

The spec requires the **admin plane and agent plane MUST be separated**. This
module realizes that as two distinct facades over the same wiring:

* :class:`AgentPlane` — the agent-facing surface: open a session, evaluate /
  evaluate-execute an action, read a decision, and drive CAC. It exposes *no*
  administrative capability.
* :class:`AdminPlane` — administrative operations that MUST be admin-only (§60.29):
  agent registration, key rotation/revocation, policy activation, delegation
  issuance/revocation, FHE registry activation, containment kill-switch/reset,
  and approval grant/deny. Every method is gated by an :class:`AdminAuthorizer`
  and fails closed on an unknown principal (``ENFORCEMENT_DENIED``).

An agent holds only an :class:`AgentPlane`; it can never reach an admin method
because the object does not carry them. Privilege is a property of *which facade*
you were handed, not of a request flag an agent could set.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cvztte.cac.context import FHEContext, FHEContextRegistry
from cvztte.containment.engine import ContainmentEngine, RecoveryMethod
from cvztte.control_plane.cac_service import CACService
from cvztte.control_plane.plane import ControlPlane, EvaluationResult, ExecuteOutcome
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity.registry import KeyRecord, KeyRegistry
from cvztte.session.model import Session


class AdminAuthorizer:
    """Fail-closed admin principal gate (allowlist). Separate from agent auth."""

    def __init__(self, admins: set[str]) -> None:
        self._admins = set(admins)

    def require(self, principal: str) -> None:
        if principal not in self._admins:
            raise CVZTTEError(
                ErrorCode.ENFORCEMENT_DENIED, "principal is not an administrator"
            )


class AgentPlane:
    """Agent-facing surface. Carries no administrative capability."""

    def __init__(self, plane: ControlPlane, *, cac: CACService | None = None) -> None:
        self._plane = plane
        self._cac = cac

    # -- core ---------------------------------------------------------------

    def create_session(self, **kw: Any) -> Session:
        return self._plane.create_session(**kw)

    def evaluate(self, envelope, **kw: Any) -> EvaluationResult:
        return self._plane.evaluate(envelope, **kw)

    def evaluate_execute(self, envelope, **kw: Any) -> ExecuteOutcome:
        return self._plane.evaluate_execute(envelope, **kw)

    def get_decision(self, decision_id: str) -> EvaluationResult:
        return self._plane.get_decision(decision_id)

    def containment_status(self, subject: str) -> dict[str, Any]:
        return self._plane.containment_status(subject)

    # -- CAC ----------------------------------------------------------------

    @property
    def cac(self) -> CACService:
        if self._cac is None:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE, "CAC not enabled"
            )
        return self._cac

    # -- health -------------------------------------------------------------

    def health_live(self) -> dict[str, str]:
        return self._plane.health_live()

    def health_ready(self) -> dict[str, Any]:
        return self._plane.health_ready()


class AdminPlane:
    """Administrative surface. Every method requires an admin principal."""

    def __init__(
        self,
        plane: ControlPlane,
        *,
        authorizer: AdminAuthorizer,
        key_registry: KeyRegistry,
        containment: ContainmentEngine,
        fhe_context_registry: FHEContextRegistry | None = None,
    ) -> None:
        self._plane = plane
        self._authz = authorizer
        self._keys = key_registry
        self._containment = containment
        self._fhe_contexts = fhe_context_registry

    # -- identity / keys ----------------------------------------------------

    def register_agent(self, principal: str, agent_id: str) -> dict[str, Any]:
        self._authz.require(principal)
        rec = self._keys.register_agent(agent_id)
        return {"agent_id": rec.agent_id, "enabled": rec.enabled}

    def rotate_key(self, principal: str, agent_id: str) -> KeyRecord:
        self._authz.require(principal)
        return self._keys.rotate(agent_id)

    def revoke_key(self, principal: str, key_id: str, *, reason: str = "") -> KeyRecord:
        self._authz.require(principal)
        return self._keys.revoke(key_id, reason=reason)

    def revoke_agent(self, principal: str, agent_id: str, *, reason: str = "") -> list[KeyRecord]:
        self._authz.require(principal)
        return self._keys.revoke_agent(agent_id, reason=reason)

    # -- FHE registry activation -------------------------------------------

    def activate_fhe_context(self, principal: str, context: FHEContext) -> str:
        """Admin-only FHE context registration/activation (§37, §60.29)."""
        self._authz.require(principal)
        if self._fhe_contexts is None:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE, "FHE registry not enabled"
            )
        return self._fhe_contexts.register(context)

    # -- containment admin --------------------------------------------------

    def quarantine(
        self, principal: str, *, subject: str, agent_id: str,
        runtime_id: str | None = None, reason_codes: list[str] | None = None,
        target: ContainmentState = ContainmentState.QUARANTINED,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self._authz.require(principal)
        return self._plane.quarantine(
            subject=subject, agent_id=agent_id, runtime_id=runtime_id,
            reason_codes=reason_codes or ["ADMIN_QUARANTINE"], target=target, now=now,
        )

    def reset_containment(
        self, principal: str, *, subject: str, agent_id: str, method: RecoveryMethod,
        runtime_id: str | None = None, now: datetime | None = None,
    ) -> dict[str, Any]:
        self._authz.require(principal)
        # Recovery is itself an approval: the admin principal is the approver.
        return self._plane.reset_containment(
            subject=subject, agent_id=agent_id, method=method, approver=principal,
            runtime_id=runtime_id, now=now,
        )

    # -- approvals ----------------------------------------------------------

    def approve(
        self, principal: str, decision_id: str, *, now: datetime | None = None
    ) -> EvaluationResult:
        self._authz.require(principal)
        return self._plane.approve(decision_id, approver=principal, now=now)

    def deny_approval(
        self, principal: str, decision_id: str, *, reason: str | None = None,
        now: datetime | None = None,
    ) -> Any:
        self._authz.require(principal)
        return self._plane.deny_approval(decision_id, approver=principal, reason=reason, now=now)
