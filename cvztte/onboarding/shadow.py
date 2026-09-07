"""Shadow-mode reporting for OBSERVE/WARN rollout (spec §60.15).

While an agent runs in OBSERVE (or WARN), the platform records what enforcement
*would* have done without blocking anything (OBSERVE is explicitly not security
enforcement, §60.15). The aggregate report drives the recommended rollout
(OBSERVE → WARN → hard-rule enforcement → …) by surfacing what a switch to
ENFORCE would break.

Per §60.15 the report SHOULD include: false-positive review candidates, missing
policy, a normal-behavior baseline, unknown destinations, adapter coverage, and
bypass attempts. This aggregator tallies :class:`ShadowObservation` records into
that shape. It is a *reporting* aid only — it never authorizes and never relaxes
a control.
"""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from cvztte.onboarding.mode import ModeOutcome


class ShadowObservation(BaseModel):
    """One observed action under OBSERVE/WARN and what enforcement would do."""

    model_config = ConfigDict(extra="forbid")

    action_hash: str
    outcome: ModeOutcome
    #: True if this action was a direct-access / un-mediated bypass attempt.
    bypass_attempt: bool = False
    #: Set when the observed action had no matching enterprise policy.
    missing_policy: bool = False
    #: An external destination (host/URL/tool) not on any allowlist, if any.
    unknown_destination: str | None = None
    #: True if a semantic adapter supplied context for this action.
    adapter_present: bool = False
    #: Operator flagged this WOULD_DENY as a likely false positive.
    false_positive_candidate: bool = False


class ShadowReport(BaseModel):
    """Aggregated shadow-mode report (§60.15)."""

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    would_allow: int = 0
    would_deny: int = 0
    warn_allow: int = 0
    bypass_attempts: int = 0
    missing_policy: int = 0
    false_positive_candidates: int = 0
    unknown_destinations: list[str] = Field(default_factory=list)
    adapter_coverage: float = 0.0  # fraction of observations with adapter context

    @property
    def enforce_would_block(self) -> int:
        """How many observed actions a switch to ENFORCE would newly block."""
        return self.would_deny + self.warn_allow


class ShadowAggregator:
    """Accumulates :class:`ShadowObservation` records into a :class:`ShadowReport`."""

    def __init__(self) -> None:
        self._obs: list[ShadowObservation] = []

    def record(self, observation: ShadowObservation) -> None:
        self._obs.append(observation)

    def report(self) -> ShadowReport:
        total = len(self._obs)
        with_adapter = sum(1 for o in self._obs if o.adapter_present)
        dests: Counter[str] = Counter(
            o.unknown_destination for o in self._obs if o.unknown_destination
        )
        return ShadowReport(
            total=total,
            would_allow=sum(1 for o in self._obs if o.outcome is ModeOutcome.WOULD_ALLOW),
            would_deny=sum(1 for o in self._obs if o.outcome is ModeOutcome.WOULD_DENY),
            warn_allow=sum(1 for o in self._obs if o.outcome is ModeOutcome.WARN_ALLOW),
            bypass_attempts=sum(1 for o in self._obs if o.bypass_attempt),
            missing_policy=sum(1 for o in self._obs if o.missing_policy),
            false_positive_candidates=sum(
                1 for o in self._obs if o.false_positive_candidate
            ),
            unknown_destinations=sorted(dests),
            adapter_coverage=(with_adapter / total) if total else 0.0,
        )
