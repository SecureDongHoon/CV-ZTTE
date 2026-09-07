"""Confidential Query Governance (spec §45, §60.27).

Limits inference leakage from *permitted plaintext outputs* — decrypt-rate,
minimum aggregation group size, differencing/overlap patterns, approval, and
result minimization. **Not differential privacy**; a DP mechanism is a pluggable
extension point. See ``docs/CONFIDENTIAL_QUERY_GOVERNANCE.md``.
"""

from __future__ import annotations

from cvztte.confidential_query.dp import NoDP, NoiseMechanism
from cvztte.confidential_query.governance import QueryGovernor
from cvztte.confidential_query.models import (
    GovernanceAction,
    GovernanceDecision,
    QueryGovernancePolicy,
    QueryRequest,
    QueryScope,
    ReleaseKind,
)

__all__ = [
    "NoDP",
    "NoiseMechanism",
    "QueryGovernor",
    "GovernanceAction",
    "GovernanceDecision",
    "QueryGovernancePolicy",
    "QueryRequest",
    "QueryScope",
    "ReleaseKind",
]
