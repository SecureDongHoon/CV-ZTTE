"""Confidential Query Governor (spec §45, §60.27).

Fail-closed, config-driven governance of plaintext release to limit inference
leakage (§45). It is **not** differential privacy (see
:mod:`cvztte.confidential_query.dp`). The governor keeps per-scope history and,
for each request, applies — most-restrictive-wins:

1. minimum aggregation group size / individual-value denial;
2. decrypt rate limit over a rolling window;
3. differencing-pattern denial (small symmetric difference vs a prior subset);
4. repeated-overlapping-query denial (overlap coefficient above the limit);
5. approval requirement below a group size;
6. result rounding/minimization.

A DENY carries a stable :class:`ErrorCode`; ambiguity resolves to DENY.
"""

from __future__ import annotations

import threading

from cvztte.confidential_query.dp import NoDP, NoiseMechanism
from cvztte.confidential_query.models import (
    GovernanceAction,
    GovernanceDecision,
    QueryGovernancePolicy,
    QueryRequest,
    ReleaseKind,
)
from cvztte.errors import ErrorCode


class QueryGovernor:
    def __init__(
        self,
        policy: QueryGovernancePolicy | None = None,
        *,
        mechanism: NoiseMechanism | None = None,
    ) -> None:
        self._policy = policy or QueryGovernancePolicy()
        self._mechanism: NoiseMechanism = mechanism or NoDP()
        self._lock = threading.Lock()
        #: scope key -> list of (timestamp, subset_ids)
        self._history: dict[tuple[str, str, str, str], list[tuple[float, frozenset[str]]]] = {}

    # -- introspection ------------------------------------------------------

    def is_differential_privacy(self) -> bool:
        """True only if a real DP mechanism with accounting is plugged in (§45)."""
        return bool(getattr(self._mechanism, "accounts_privacy", False))

    # -- evaluation ---------------------------------------------------------

    def _recent(self, request: QueryRequest) -> list[tuple[float, frozenset[str]]]:
        window_start = request.timestamp - self._policy.window_seconds
        hist = self._history.get(request.scope.key(), [])
        return [(t, s) for (t, s) in hist if t >= window_start]

    def evaluate(self, request: QueryRequest) -> GovernanceDecision:
        """Decide whether a release may proceed. Read-only (does not record)."""
        p = self._policy
        with self._lock:
            recent = self._recent(request)

        # 1. Aggregation group size / individual-value release (§45).
        if request.release_kind is ReleaseKind.INDIVIDUAL and p.deny_individual_value:
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                reason=ErrorCode.FHE_QUERY_PATTERN_RISK,
                message="individual-value release denied by policy",
            )
        if request.aggregation_group_size < p.min_group_size:
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                reason=ErrorCode.FHE_QUERY_PATTERN_RISK,
                message="aggregation group smaller than minimum k",
            )

        # 2. Decrypt rate limit over the rolling window.
        if p.max_decrypts_per_window is not None and len(recent) >= p.max_decrypts_per_window:
            return GovernanceDecision(
                action=GovernanceAction.DENY,
                reason=ErrorCode.FHE_PRIVACY_BUDGET_EXCEEDED,
                message="decrypt rate limit exceeded for scope/window",
            )

        # 3 & 4. Differencing and repeated-overlap patterns vs prior subsets.
        cur = request.subset_ids
        for _, prev in recent:
            if not cur or not prev:
                continue
            sym_diff = len(cur ^ prev)
            if (
                p.differencing_min_symmetric_difference > 0
                and 0 < sym_diff < p.differencing_min_symmetric_difference
            ):
                return GovernanceDecision(
                    action=GovernanceAction.DENY,
                    reason=ErrorCode.FHE_QUERY_PATTERN_RISK,
                    message="differencing pattern detected vs a prior query",
                )
            if p.max_overlap_ratio is not None and cur != prev:
                overlap = len(cur & prev) / min(len(cur), len(prev))
                if overlap > p.max_overlap_ratio:
                    return GovernanceDecision(
                        action=GovernanceAction.DENY,
                        reason=ErrorCode.FHE_QUERY_PATTERN_RISK,
                        message="repeated overlapping query restricted",
                    )

        # 5. Approval requirement below a group size (§48).
        if (
            p.require_approval_below_group_size is not None
            and request.aggregation_group_size < p.require_approval_below_group_size
        ):
            return GovernanceDecision(
                action=GovernanceAction.REQUIRE_APPROVAL,
                reason=ErrorCode.APPROVAL_REQUIRED,
                message="release requires human approval for small group",
                round_decimals=p.round_decimals,
            )

        # 6. Result minimization (rounding).
        if p.round_decimals is not None:
            return GovernanceDecision(
                action=GovernanceAction.TRANSFORM,
                round_decimals=p.round_decimals,
                message="result rounded/minimized",
            )

        return GovernanceDecision(action=GovernanceAction.ALLOW)

    # -- recording ----------------------------------------------------------

    def record(self, request: QueryRequest) -> None:
        """Register that a governed release occurred (feeds future decisions)."""
        with self._lock:
            self._history.setdefault(request.scope.key(), []).append(
                (request.timestamp, request.subset_ids)
            )

    def governed_release(self, request: QueryRequest) -> GovernanceDecision:
        """Evaluate and, if not denied, record the query in one step."""
        decision = self.evaluate(request)
        if decision.allowed:
            self.record(request)
        return decision

    # -- output minimization ------------------------------------------------

    def minimize(self, values: list[float], decision: GovernanceDecision) -> list[float]:
        """Apply the decision's rounding to released values (result minimization)."""
        if decision.round_decimals is None:
            return values
        return [round(v, decision.round_decimals) for v in values]
