"""Confidential Query Governance models (spec §45, §60.27).

Governs **inference leakage from permitted plaintext outputs** — FHE does not
prevent it (§45). We track, per (agent, dataset, session, purpose): decrypt
count, query frequency, overlapping subsets, result precision, aggregation size,
and differencing patterns; and let policy rate-limit, require a minimum group
size, round/minimize, deny individual-value release, require approval, or
restrict repeated overlapping queries.

**This is NOT differential privacy.** No DP noise or privacy accounting is
implemented here; a DP mechanism is a pluggable extension point
(:mod:`cvztte.confidential_query.dp`). Thresholds are policy/config-controlled,
never hardcoded (§4).
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field

from cvztte.errors import ErrorCode


class ReleaseKind(str, enum.Enum):
    """Whether the released output is an aggregate or an individual value."""

    AGGREGATE = "AGGREGATE"
    INDIVIDUAL = "INDIVIDUAL"


class QueryScope(BaseModel):
    """The accounting key (§45: per agent/dataset/session/purpose)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    dataset_id: str
    session_id: str
    purpose: str

    def key(self) -> tuple[str, str, str, str]:
        return (self.agent_id, self.dataset_id, self.session_id, self.purpose)


class QueryRequest(BaseModel):
    """A decrypt/release request evaluated by the governor."""

    model_config = ConfigDict(extra="forbid")

    scope: QueryScope
    program_id: str
    #: Identifiers (NOT plaintext values) of the records aggregated — used for
    #: overlap/differencing analysis (§45).
    subset_ids: frozenset[str] = Field(default_factory=frozenset)
    #: Number of individuals aggregated into the released output.
    aggregation_group_size: int = Field(ge=0)
    release_kind: ReleaseKind = ReleaseKind.AGGREGATE
    #: Epoch seconds; supplied by the caller so evaluation is deterministic.
    timestamp: float


class GovernanceAction(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    TRANSFORM = "TRANSFORM"           # allow, but round/minimize the output
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class GovernanceDecision(BaseModel):
    """Outcome of governing a query. Fail-closed: DENY carries a stable code."""

    model_config = ConfigDict(extra="forbid")

    action: GovernanceAction
    reason: ErrorCode | None = None
    message: str = ""
    #: When set, the caller MUST round the released value to this many decimals
    #: before disclosure (result minimization, §45).
    round_decimals: int | None = None

    @property
    def allowed(self) -> bool:
        """True if the query may proceed (possibly transformed / pending approval)."""
        return self.action is not GovernanceAction.DENY


class QueryGovernancePolicy(BaseModel):
    """Config-controlled governance thresholds (§4, §45). All optional knobs
    default to the *safe* (more restrictive or no-op) setting."""

    model_config = ConfigDict(extra="forbid")

    #: Rolling window for count/frequency accounting.
    window_seconds: float = 3600.0
    #: Max decrypts per scope per window (rate limit). None => unlimited.
    max_decrypts_per_window: int | None = None
    #: Minimum aggregation group size k; releases below k are denied (§45).
    min_group_size: int = 1
    #: Deny release of an individual value outright.
    deny_individual_value: bool = True
    #: Two subsets differing by a symmetric difference in [1, threshold) are a
    #: differencing pattern and are denied. 0 disables the check.
    differencing_min_symmetric_difference: int = 0
    #: Overlap coefficient above which a repeated overlapping query is denied
    #: (0..1]. 1.0 (or None) disables the check (identical repeats handled by
    #: rate limiting).
    max_overlap_ratio: float | None = None
    #: If set, releases below this group size require human approval (§48).
    require_approval_below_group_size: int | None = None
    #: If set, allowed releases are rounded to this many decimals (minimization).
    round_decimals: int | None = None
