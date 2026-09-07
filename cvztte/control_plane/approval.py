"""Human-approval workflow (spec §28, §48, §60.29).

High-risk actions (OPA ``require_human_approval`` or a policy risk tier that
demands it) MUST NOT mint an executable Decision Token until a human approver
grants the request. This module is the stateful approval store the Control Plane
consults: an evaluation that requires approval parks a :class:`ApprovalRecord`
in ``PENDING``; ``POST /v3/approvals/{decision_id}`` grants (or denies) it; only
then does the plane mint the token.

Fail-closed (§4.20): a decision with no granted, unexpired approval can never
proceed. A pending/absent approval raises ``APPROVAL_REQUIRED``; a lapsed one
raises ``APPROVAL_EXPIRED``. Approvals never auto-grant and never resurrect after
expiry.
"""

from __future__ import annotations

import enum
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cvztte.errors import CVZTTEError, ErrorCode

#: Approvals are deliberately short-lived; a stale approval must not authorize a
#: much later action (§28). Config-controlled, not a hardcoded security floor.
DEFAULT_APPROVAL_TTL_SECONDS = 900


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalState(str, enum.Enum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    DENIED = "DENIED"


@dataclass
class ApprovalRecord:
    approval_id: str
    decision_id: str
    agent_id: str
    action_hash: str
    risk_level: int
    classification: str
    requested_at: datetime
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    approver: str | None = None
    decided_at: datetime | None = None
    reason: str | None = None

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def public_view(self) -> dict[str, object]:
        return {
            "approval_id": self.approval_id,
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "action_hash": self.action_hash,
            "risk_level": self.risk_level,
            "classification": self.classification,
            "state": self.state.value,
            "approver": self.approver,
            "requested_at": self.requested_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }


class ApprovalStore:
    """Thread-safe, in-memory approval workflow (DB-backed in production)."""

    def __init__(self, *, ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._by_id: dict[str, ApprovalRecord] = {}
        self._by_decision: dict[str, str] = {}

    def request(
        self,
        *,
        decision_id: str,
        agent_id: str,
        action_hash: str,
        risk_level: int,
        classification: str,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        now = now or _utcnow()
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        record = ApprovalRecord(
            approval_id="appr_" + uuid.uuid4().hex,
            decision_id=decision_id,
            agent_id=agent_id,
            action_hash=action_hash,
            risk_level=risk_level,
            classification=classification,
            requested_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )
        with self._lock:
            self._by_id[record.approval_id] = record
            self._by_decision[decision_id] = record.approval_id
        return record

    def get(self, approval_id: str) -> ApprovalRecord:
        with self._lock:
            rec = self._by_id.get(approval_id)
        if rec is None:
            raise CVZTTEError(ErrorCode.APPROVAL_REQUIRED, "unknown approval")
        return rec

    def by_decision(self, decision_id: str) -> ApprovalRecord | None:
        with self._lock:
            approval_id = self._by_decision.get(decision_id)
            return self._by_id.get(approval_id) if approval_id else None

    def _decide(
        self,
        decision_id: str,
        *,
        state: ApprovalState,
        approver: str,
        reason: str | None,
        now: datetime | None,
    ) -> ApprovalRecord:
        now = now or _utcnow()
        with self._lock:
            approval_id = self._by_decision.get(decision_id)
            rec = self._by_id.get(approval_id) if approval_id else None
            if rec is None:
                raise CVZTTEError(
                    ErrorCode.APPROVAL_REQUIRED, "no approval requested for decision"
                )
            if rec.state is not ApprovalState.PENDING:
                # An already-decided approval is not re-decidable (fail-closed).
                raise CVZTTEError(
                    ErrorCode.APPROVAL_REQUIRED,
                    f"approval already {rec.state.value.lower()}",
                )
            if rec.is_expired(now):
                raise CVZTTEError(ErrorCode.APPROVAL_EXPIRED, "approval window elapsed")
            rec.state = state
            rec.approver = approver
            rec.decided_at = now
            rec.reason = reason
            return rec

    def grant(
        self,
        decision_id: str,
        *,
        approver: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        return self._decide(
            decision_id, state=ApprovalState.GRANTED, approver=approver, reason=reason, now=now
        )

    def deny(
        self,
        decision_id: str,
        *,
        approver: str,
        reason: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        return self._decide(
            decision_id, state=ApprovalState.DENIED, approver=approver, reason=reason, now=now
        )

    def assert_granted(
        self, decision_id: str, *, now: datetime | None = None
    ) -> ApprovalRecord:
        """Return the granted, unexpired approval or fail closed.

        ``APPROVAL_REQUIRED`` if none/pending/denied; ``APPROVAL_EXPIRED`` if the
        approval lapsed before the token was minted.
        """
        now = now or _utcnow()
        rec = self.by_decision(decision_id)
        if rec is None or rec.state is ApprovalState.PENDING:
            raise CVZTTEError(ErrorCode.APPROVAL_REQUIRED, "human approval required")
        if rec.state is ApprovalState.DENIED:
            raise CVZTTEError(ErrorCode.APPROVAL_REQUIRED, "approval was denied")
        if rec.is_expired(now):
            raise CVZTTEError(ErrorCode.APPROVAL_EXPIRED, "approval expired before use")
        return rec
