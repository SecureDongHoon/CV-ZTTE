"""Phase 3 structured delegation (spec §12, §23, §60)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from cvztte.action.model import DataClassification
from cvztte.delegation import AuthorityKind, DelegationRegistry, PolicyAuthority
from cvztte.delegation.model import _utcnow
from cvztte.errors import CVZTTEError, ErrorCode


@pytest.fixture()
def reg() -> DelegationRegistry:
    r = DelegationRegistry(
        [PolicyAuthority("admin_1", AuthorityKind.SECURITY_ADMIN)]
    )
    return r


def _root(reg: DelegationRegistry, **over):
    now = _utcnow()
    kwargs = dict(
        authority_id="admin_1",
        subject_agent_id="agt_alice",
        capabilities={"db:read", "fs:read"},
        resource_scopes={"db:customers", "fs:/data"},
        clearance=DataClassification.CONFIDENTIAL,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(hours=1),
        max_chain_depth=2,
    )
    kwargs.update(over)
    return reg.issue_root(**kwargs)


def test_root_from_trusted_authority(reg: DelegationRegistry) -> None:
    d = _root(reg)
    assert reg.validate_for_agent(d.delegation_id, "agt_alice").delegation_id == d.delegation_id


def test_no_self_authorization(reg: DelegationRegistry) -> None:
    # An agent id that is not a registered authority cannot issue root authority.
    with pytest.raises(CVZTTEError) as exc:
        _root(reg, authority_id="agt_alice")
    assert exc.value.code == ErrorCode.DELEGATION_INVALID


def test_delegation_bound_to_agent(reg: DelegationRegistry) -> None:
    d = _root(reg)
    with pytest.raises(CVZTTEError):
        reg.validate_for_agent(d.delegation_id, "agt_bob")


def test_child_subset_ok(reg: DelegationRegistry) -> None:
    parent = _root(reg)
    now = _utcnow()
    child = reg.issue_child(
        parent_id=parent.delegation_id,
        subject_agent_id="agt_child",
        capabilities={"db:read"},
        resource_scopes={"db:customers"},
        clearance=DataClassification.INTERNAL,
        not_before=now,
        not_after=now + timedelta(minutes=30),
    )
    assert child.depth == 1
    reg.validate_for_agent(child.delegation_id, "agt_child")


def test_child_cannot_widen_capabilities(reg: DelegationRegistry) -> None:
    parent = _root(reg)
    now = _utcnow()
    with pytest.raises(CVZTTEError) as exc:
        reg.issue_child(
            parent_id=parent.delegation_id,
            subject_agent_id="agt_child",
            capabilities={"db:read", "db:write"},  # db:write not in parent
            resource_scopes={"db:customers"},
            clearance=DataClassification.INTERNAL,
            not_before=now,
            not_after=now + timedelta(minutes=30),
        )
    assert exc.value.code == ErrorCode.DELEGATION_INVALID


def test_child_cannot_widen_scope(reg: DelegationRegistry) -> None:
    parent = _root(reg)
    now = _utcnow()
    with pytest.raises(CVZTTEError):
        reg.issue_child(
            parent_id=parent.delegation_id,
            subject_agent_id="agt_child",
            capabilities={"db:read"},
            resource_scopes={"db:secrets"},  # not in parent
            clearance=DataClassification.INTERNAL,
            not_before=now,
            not_after=now + timedelta(minutes=30),
        )


def test_child_clearance_cannot_exceed_parent(reg: DelegationRegistry) -> None:
    parent = _root(reg)
    now = _utcnow()
    with pytest.raises(CVZTTEError):
        reg.issue_child(
            parent_id=parent.delegation_id,
            subject_agent_id="agt_child",
            capabilities={"db:read"},
            resource_scopes={"db:customers"},
            clearance=DataClassification.SECRET,  # > CONFIDENTIAL
            not_before=now,
            not_after=now + timedelta(minutes=30),
        )


def test_child_expiry_cannot_exceed_parent(reg: DelegationRegistry) -> None:
    parent = _root(reg)
    now = _utcnow()
    with pytest.raises(CVZTTEError):
        reg.issue_child(
            parent_id=parent.delegation_id,
            subject_agent_id="agt_child",
            capabilities={"db:read"},
            resource_scopes={"db:customers"},
            clearance=DataClassification.INTERNAL,
            not_before=now,
            not_after=now + timedelta(days=2),  # beyond parent's 1h window
        )


def test_chain_depth_bound(reg: DelegationRegistry) -> None:
    parent = _root(reg, max_chain_depth=1)
    now = _utcnow()
    child = reg.issue_child(
        parent_id=parent.delegation_id,
        subject_agent_id="agt_child",
        capabilities={"db:read"},
        resource_scopes={"db:customers"},
        clearance=DataClassification.INTERNAL,
        not_before=now,
        not_after=now + timedelta(minutes=30),
    )
    with pytest.raises(CVZTTEError):
        reg.issue_child(
            parent_id=child.delegation_id,
            subject_agent_id="agt_grandchild",
            capabilities={"db:read"},
            resource_scopes={"db:customers"},
            clearance=DataClassification.INTERNAL,
            not_before=now,
            not_after=now + timedelta(minutes=15),
        )


def test_revocation_propagates_to_descendants(reg: DelegationRegistry) -> None:
    parent = _root(reg)
    now = _utcnow()
    child = reg.issue_child(
        parent_id=parent.delegation_id,
        subject_agent_id="agt_child",
        capabilities={"db:read"},
        resource_scopes={"db:customers"},
        clearance=DataClassification.INTERNAL,
        not_before=now,
        not_after=now + timedelta(minutes=30),
    )
    revoked = reg.revoke(parent.delegation_id)
    assert parent.delegation_id in revoked
    assert child.delegation_id in revoked  # propagation / no authority laundering
    with pytest.raises(CVZTTEError):
        reg.validate_for_agent(child.delegation_id, "agt_child")


def test_expired_root_rejected(reg: DelegationRegistry) -> None:
    now = _utcnow()
    d = _root(reg, not_before=now - timedelta(hours=2), not_after=now - timedelta(hours=1))
    with pytest.raises(CVZTTEError):
        reg.validate_for_agent(d.delegation_id, "agt_alice")
