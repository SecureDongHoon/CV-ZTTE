"""Containment escalation engine + capability-epoch driver (spec §25-§27, §60.18-§60.20).

The engine owns the per-subject containment state machine. Escalation is driven
by behavior/evasion features through the configured :class:`ThresholdPolicy`
(§25); it is *escalate-only* — features never auto-de-escalate a subject
(§60.18). Administrators force QUARANTINE/TERMINATED via the kill switch (§27),
and de-escalation only happens through explicit, method-gated, audited recovery
(§27, §60.19). Every state change is recorded as a :class:`ContainmentTransition`
(§60.20).

Capability epoch. Every transition (escalation, kill, or recovery) atomically
increments the ``capability_epoch`` carried by the shared :class:`EpochSource`,
which invalidates every Decision Token minted under the older epoch (Phase 8
validator step 6). This reference bumps a single *global* capability epoch, so a
transition on one subject over-invalidates tokens for all subjects. That is
coarse but strictly fail-closed — it can only revoke authority early, never
extend it — and is documented here deliberately; a production build would key
epochs per subject/capability class.

Containment can only ever *remove* authority (§26); nothing in this module can
grant a capability a subject did not already hold.
"""

from __future__ import annotations

import enum
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.containment.model import (
    CapabilityProfile,
    ContainmentTransition,
    blocks_new_consequential_tokens,
    effective_capabilities,
    more_severe,
    severity,
)
from cvztte.containment.policy import ThresholdPolicy
from cvztte.decision.model import ContainmentState, EpochSet
from cvztte.decision.validator import EpochSource
from cvztte.errors import CVZTTEError, ErrorCode


class RecoveryMethod(str, enum.Enum):
    """How a de-escalation is authorized (spec §60.19 recovery rules)."""

    #: Time cooldown + clean behavioral evidence (only sufficient for SUSPICIOUS).
    COOLDOWN_CLEAN = "COOLDOWN_CLEAN"
    #: Fresh authenticated session / delegation.
    FRESH_SESSION = "FRESH_SESSION"
    #: Explicit administrator approval.
    ADMIN_APPROVAL = "ADMIN_APPROVAL"
    #: Full re-onboarding on a new runtime (only path out of TERMINATED).
    REONBOARD = "REONBOARD"


#: Recovery methods accepted for each state (higher states demand stronger proof).
#: A TERMINATED subject cannot recover in place — only re-onboarding (a new
#: runtime identity) clears it (§27, §60.20).
_RECOVERY_ALLOWED: dict[ContainmentState, frozenset[RecoveryMethod]] = {
    ContainmentState.SUSPICIOUS: frozenset(
        {
            RecoveryMethod.COOLDOWN_CLEAN,
            RecoveryMethod.FRESH_SESSION,
            RecoveryMethod.ADMIN_APPROVAL,
            RecoveryMethod.REONBOARD,
        }
    ),
    ContainmentState.RESTRICTED: frozenset(
        {
            RecoveryMethod.FRESH_SESSION,
            RecoveryMethod.ADMIN_APPROVAL,
            RecoveryMethod.REONBOARD,
        }
    ),
    ContainmentState.QUARANTINED: frozenset(
        {RecoveryMethod.ADMIN_APPROVAL, RecoveryMethod.REONBOARD}
    ),
    ContainmentState.TERMINATED: frozenset({RecoveryMethod.REONBOARD}),
}


class _SubjectState:
    __slots__ = ("state", "agent_id", "runtime_id", "last_transition_at", "transitions")

    def __init__(self, agent_id: str, runtime_id: str | None) -> None:
        self.state = ContainmentState.NORMAL
        self.agent_id = agent_id
        self.runtime_id = runtime_id
        self.last_transition_at: datetime | None = None
        self.transitions: list[ContainmentTransition] = []


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


class ContainmentEngine:
    """Per-subject containment state machine driving the global capability epoch."""

    def __init__(
        self,
        *,
        policy: ThresholdPolicy | None = None,
        epoch_source: EpochSource | None = None,
        suspicious_cooldown_seconds: float = 300.0,
    ) -> None:
        self._policy = policy or ThresholdPolicy()
        self._epochs = epoch_source or EpochSource()
        self._cooldown = timedelta(seconds=suspicious_cooldown_seconds)
        self._subjects: dict[str, _SubjectState] = {}
        self._registry_lock = threading.Lock()
        self._locks: dict[str, threading.RLock] = {}
        self._epoch_lock = threading.Lock()

    # -- registry helpers ---------------------------------------------------

    def _subject(self, subject: str, agent_id: str, runtime_id: str | None) -> _SubjectState:
        with self._registry_lock:
            st = self._subjects.get(subject)
            if st is None:
                st = _SubjectState(agent_id, runtime_id)
                self._subjects[subject] = st
                self._locks[subject] = threading.RLock()
            else:
                # Keep the latest known agent/runtime identity for the subject.
                st.agent_id = agent_id or st.agent_id
                if runtime_id is not None:
                    st.runtime_id = runtime_id
            return st

    def _lock_for(self, subject: str) -> threading.RLock:
        with self._registry_lock:
            return self._locks[subject]

    # -- public read API ----------------------------------------------------

    def state(self, subject: str) -> ContainmentState:
        with self._registry_lock:
            st = self._subjects.get(subject)
            return st.state if st is not None else ContainmentState.NORMAL

    def transitions(self, subject: str) -> list[ContainmentTransition]:
        with self._registry_lock:
            st = self._subjects.get(subject)
            return list(st.transitions) if st is not None else []

    def blocks_new_consequential_tokens(self, subject: str) -> bool:
        return blocks_new_consequential_tokens(self.state(subject))

    def effective_capabilities(
        self,
        subject: str,
        *,
        delegated: set[str],
        enterprise_policy: set[str],
        runtime_profile: set[str],
        profile: CapabilityProfile | None = None,
    ) -> frozenset[str]:
        """Capability decay applied at the *current* containment state (§60.19)."""
        return effective_capabilities(
            delegated=delegated,
            enterprise_policy=enterprise_policy,
            runtime_profile=runtime_profile,
            state=self.state(subject),
            profile=profile,
        )

    # -- epoch bump ---------------------------------------------------------

    def _bump_capability_epoch(self) -> int:
        """Atomically advance the global capability epoch (invalidates stale tokens)."""
        with self._epoch_lock:
            cur = self._epochs.current()
            new = cur.model_copy(update={"capability_epoch": cur.capability_epoch + 1})
            self._epochs.set(new)
            return new.capability_epoch

    def current_epochs(self) -> EpochSet:
        return self._epochs.current()

    # -- transitions --------------------------------------------------------

    def _commit_transition(
        self,
        *,
        st: _SubjectState,
        subject: str,
        new_state: ContainmentState,
        reason_codes: list[str],
        evidence: dict[str, Any],
        now: datetime,
    ) -> ContainmentTransition:
        """Record a state change and advance the capability epoch (caller holds subject lock)."""
        old_state = st.state
        evidence_hash = commit(
            Domain.CONTAINMENT_TRANSITION,
            {
                "subject": subject,
                "agent_id": st.agent_id,
                "old_state": old_state.value,
                "new_state": new_state.value,
                "reason_codes": sorted(reason_codes),
                "evidence": evidence,
            },
        )
        capability_epoch = self._bump_capability_epoch()
        record = ContainmentTransition(
            subject=subject,
            agent_id=st.agent_id,
            runtime_id=st.runtime_id,
            old_state=old_state,
            new_state=new_state,
            reason_codes=list(reason_codes),
            evidence_hash=evidence_hash,
            capability_epoch=capability_epoch,
            at=now.astimezone(timezone.utc).isoformat(),
        )
        st.state = new_state
        st.last_transition_at = now
        st.transitions.append(record)
        return record

    def evaluate(
        self,
        *,
        subject: str,
        agent_id: str,
        features: dict[str, Any],
        runtime_id: str | None = None,
        reason_codes: list[str] | None = None,
        now: datetime | None = None,
    ) -> ContainmentTransition | None:
        """Escalate the subject if features warrant it. Returns the transition or None.

        Escalate-only: the assessed state can only raise, never lower, the
        current state (§60.18). De-escalation is exclusively via :meth:`recover`.
        """
        now = _now(now)
        st = self._subject(subject, agent_id, runtime_id)
        with self._lock_for(subject):
            warranted = self._policy.assess(features)
            target = more_severe(st.state, warranted)
            if severity(target) <= severity(st.state):
                return None
            codes = list(reason_codes or [])
            codes.append(f"ASSESSED_{warranted.value}")
            return self._commit_transition(
                st=st,
                subject=subject,
                new_state=target,
                reason_codes=codes,
                evidence={"features": features, "assessed": warranted.value},
                now=now,
            )

    def kill_switch(
        self,
        *,
        subject: str,
        agent_id: str,
        target_state: ContainmentState,
        reason_codes: list[str],
        runtime_id: str | None = None,
        now: datetime | None = None,
    ) -> ContainmentTransition:
        """Administrator kill switch — force QUARANTINE/TERMINATED (§27).

        Only QUARANTINED or TERMINATED are valid kill targets. The kill switch
        can only escalate: if the subject is already more contained than the
        requested target, the more severe state is kept.
        """
        if target_state not in (
            ContainmentState.QUARANTINED,
            ContainmentState.TERMINATED,
        ):
            raise CVZTTEError(
                ErrorCode.CONTAINMENT_QUARANTINED,
                "kill switch target must be QUARANTINED or TERMINATED",
            )
        now = _now(now)
        st = self._subject(subject, agent_id, runtime_id)
        with self._lock_for(subject):
            new_state = more_severe(st.state, target_state)
            codes = list(reason_codes)
            codes.append("KILL_SWITCH")
            return self._commit_transition(
                st=st,
                subject=subject,
                new_state=new_state,
                reason_codes=codes,
                evidence={"kill_switch": True, "requested": target_state.value},
                now=now,
            )

    def recover(
        self,
        *,
        subject: str,
        agent_id: str,
        method: RecoveryMethod,
        approver: str | None = None,
        runtime_id: str | None = None,
        now: datetime | None = None,
    ) -> ContainmentTransition:
        """Explicit, method-gated, audited de-escalation to NORMAL (§27, §60.19).

        Recovery is never automatic and never trivially time-based above
        SUSPICIOUS. If ``method`` is insufficient for the current state (or the
        cooldown/evidence gate is unmet), raises ``RECOVERY_APPROVAL_REQUIRED``
        and the state is left unchanged (fail-closed).
        """
        now = _now(now)
        st = self._subject(subject, agent_id, runtime_id)
        with self._lock_for(subject):
            current = st.state
            if current is ContainmentState.NORMAL:
                raise CVZTTEError(
                    ErrorCode.RECOVERY_APPROVAL_REQUIRED, "subject is not contained"
                )

            allowed = _RECOVERY_ALLOWED.get(current, frozenset())
            if method not in allowed:
                raise CVZTTEError(
                    ErrorCode.RECOVERY_APPROVAL_REQUIRED,
                    f"method {method.value} insufficient for {current.value}",
                )

            # Cooldown gate: COOLDOWN_CLEAN also requires the cooldown to elapse.
            if method is RecoveryMethod.COOLDOWN_CLEAN:
                last = st.last_transition_at
                if last is not None and (now - last) < self._cooldown:
                    raise CVZTTEError(
                        ErrorCode.RECOVERY_APPROVAL_REQUIRED, "cooldown not elapsed"
                    )

            # Admin/quarantine recovery must name an approver.
            if (
                method in (RecoveryMethod.ADMIN_APPROVAL,)
                or severity(current) >= severity(ContainmentState.QUARANTINED)
            ) and method is not RecoveryMethod.REONBOARD and not approver:
                raise CVZTTEError(
                    ErrorCode.RECOVERY_APPROVAL_REQUIRED, "approver required"
                )

            codes = [f"RECOVER_{method.value}"]
            if approver:
                codes.append(f"APPROVER:{approver}")
            return self._commit_transition(
                st=st,
                subject=subject,
                new_state=ContainmentState.NORMAL,
                reason_codes=codes,
                evidence={"method": method.value, "approver": approver, "from": current.value},
                now=now,
            )
