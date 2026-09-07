"""Unit tests for Confidential Query Governance (spec §45, §60.27).

These verify inference-leakage controls on *permitted plaintext outputs* — and
that we never overclaim differential privacy.
"""

from __future__ import annotations

import pytest

from cvztte.confidential_query import (
    GovernanceAction,
    NoDP,
    QueryGovernancePolicy,
    QueryGovernor,
    QueryRequest,
    QueryScope,
    ReleaseKind,
)
from cvztte.errors import ErrorCode

SCOPE = QueryScope(
    agent_id="agent-1", dataset_id="ds-1", session_id="sess-1", purpose="analytics"
)


def _req(
    *,
    subset_ids=frozenset({"a", "b", "c"}),
    group_size=3,
    release_kind=ReleaseKind.AGGREGATE,
    ts=1000.0,
):
    return QueryRequest(
        scope=SCOPE,
        program_id="SUM_V1",
        subset_ids=subset_ids,
        aggregation_group_size=group_size,
        release_kind=release_kind,
        timestamp=ts,
    )


def test_allow_happy_path():
    gov = QueryGovernor(QueryGovernancePolicy(min_group_size=2))
    decision = gov.evaluate(_req())
    assert decision.action is GovernanceAction.ALLOW
    assert decision.allowed
    assert decision.reason is None


def test_individual_value_release_denied():
    gov = QueryGovernor(QueryGovernancePolicy(deny_individual_value=True))
    decision = gov.evaluate(_req(release_kind=ReleaseKind.INDIVIDUAL, group_size=1))
    assert decision.action is GovernanceAction.DENY
    assert decision.reason is ErrorCode.FHE_QUERY_PATTERN_RISK
    assert not decision.allowed


def test_group_below_minimum_denied():
    gov = QueryGovernor(QueryGovernancePolicy(min_group_size=5))
    decision = gov.evaluate(_req(group_size=3))
    assert decision.action is GovernanceAction.DENY
    assert decision.reason is ErrorCode.FHE_QUERY_PATTERN_RISK


def test_rate_limit_exceeded():
    gov = QueryGovernor(
        QueryGovernancePolicy(min_group_size=1, max_decrypts_per_window=2)
    )
    for i in range(2):
        d = gov.governed_release(_req(subset_ids=frozenset({f"x{i}"}), ts=1000.0 + i))
        assert d.allowed
    d = gov.evaluate(_req(subset_ids=frozenset({"x9"}), ts=1002.0))
    assert d.action is GovernanceAction.DENY
    assert d.reason is ErrorCode.FHE_PRIVACY_BUDGET_EXCEEDED


def test_rate_limit_window_expiry_allows_again():
    gov = QueryGovernor(
        QueryGovernancePolicy(
            min_group_size=1, max_decrypts_per_window=1, window_seconds=100.0
        )
    )
    assert gov.governed_release(_req(ts=1000.0)).allowed
    # Same window -> denied.
    assert not gov.evaluate(_req(ts=1050.0)).allowed
    # After window -> allowed again.
    assert gov.evaluate(_req(ts=1101.0)).allowed


def test_differencing_pattern_denied():
    gov = QueryGovernor(
        QueryGovernancePolicy(
            min_group_size=1, differencing_min_symmetric_difference=2
        )
    )
    gov.governed_release(_req(subset_ids=frozenset({"a", "b", "c"}), ts=1000.0))
    # New subset differs by a single element -> classic differencing attack.
    d = gov.evaluate(_req(subset_ids=frozenset({"a", "b", "c", "d"}), ts=1001.0))
    assert d.action is GovernanceAction.DENY
    assert d.reason is ErrorCode.FHE_QUERY_PATTERN_RISK


def test_overlapping_query_restricted():
    gov = QueryGovernor(
        QueryGovernancePolicy(min_group_size=1, max_overlap_ratio=0.5)
    )
    gov.governed_release(_req(subset_ids=frozenset({"a", "b", "c", "d"}), ts=1000.0))
    # 3/4 overlap coefficient > 0.5.
    d = gov.evaluate(_req(subset_ids=frozenset({"a", "b", "c", "e"}), ts=1001.0))
    assert d.action is GovernanceAction.DENY
    assert d.reason is ErrorCode.FHE_QUERY_PATTERN_RISK


def test_approval_required_below_group_size():
    gov = QueryGovernor(
        QueryGovernancePolicy(min_group_size=1, require_approval_below_group_size=10)
    )
    d = gov.evaluate(_req(group_size=5))
    assert d.action is GovernanceAction.REQUIRE_APPROVAL
    assert d.reason is ErrorCode.APPROVAL_REQUIRED
    assert d.allowed  # not a DENY


def test_rounding_transform_and_minimize():
    gov = QueryGovernor(QueryGovernancePolicy(min_group_size=1, round_decimals=1))
    d = gov.evaluate(_req())
    assert d.action is GovernanceAction.TRANSFORM
    assert d.round_decimals == 1
    assert gov.minimize([3.14159, 2.71828], d) == [3.1, 2.7]


def test_minimize_is_noop_without_rounding():
    gov = QueryGovernor(QueryGovernancePolicy(min_group_size=1))
    d = gov.evaluate(_req())
    assert gov.minimize([3.14159], d) == [3.14159]


def test_governed_release_does_not_record_denied_query():
    gov = QueryGovernor(
        QueryGovernancePolicy(min_group_size=1, max_decrypts_per_window=1)
    )
    gov.governed_release(_req(ts=1000.0))  # records
    denied = gov.governed_release(_req(ts=1001.0))  # denied, must NOT record
    assert not denied.allowed
    # History still has only one entry -> a later query in a fresh window works.
    assert gov.evaluate(_req(ts=99999.0)).allowed


def test_default_is_not_differential_privacy():
    gov = QueryGovernor(QueryGovernancePolicy())
    assert gov.is_differential_privacy() is False
    assert NoDP().accounts_privacy is False


def test_is_differential_privacy_true_only_with_accounting_mechanism():
    class FakeDP:
        name = "gaussian"
        accounts_privacy = True

        def perturb(self, value: float, *, sensitivity: float) -> float:
            return value

    gov = QueryGovernor(QueryGovernancePolicy(), mechanism=FakeDP())
    assert gov.is_differential_privacy() is True


def test_most_restrictive_wins_denial_over_approval():
    # A tiny group triggers both min_group_size denial and approval; DENY wins.
    gov = QueryGovernor(
        QueryGovernancePolicy(
            min_group_size=5, require_approval_below_group_size=10
        )
    )
    d = gov.evaluate(_req(group_size=3))
    assert d.action is GovernanceAction.DENY


def test_negative_group_size_rejected_by_model():
    with pytest.raises(ValueError):
        _req(group_size=-1)
