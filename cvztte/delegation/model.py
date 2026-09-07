"""Structured delegation and Policy Authority (spec §12, §23, §60).

Core rules enforced here (all fail closed):

* **No self-authorization** (spec §12, §60): an agent cannot mint its own root
  authority. Root delegations are issued only by a *trusted* Policy Authority
  (security admin / authorized user / orchestrator-IAM).
* **Sub-agent delegation cannot widen** (spec §23): a child's capabilities and
  resource scopes are subsets of its parent's, its clearance is ≤ the parent's,
  and its expiry is ≤ the parent's.
* **Bounded chain depth** and **revocation propagation**: revoking a delegation
  revokes all descendants (prevents authority laundering).

This module owns delegation *structure and integrity*. Fine-grained runtime
authorization (path/domain matching, row/byte limits, time windows) is OPA's
job in Phase 4; delegation defines the outer envelope OPA operates within.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cvztte.action.model import DataClassification
from cvztte.errors import CVZTTEError, ErrorCode

# Ordering for clearance comparisons (higher index = more sensitive).
_CLEARANCE_ORDER = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.SECRET: 3,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthorityKind(str, enum.Enum):
    """Trusted issuers of root authority (spec §12)."""

    SECURITY_ADMIN = "SECURITY_ADMIN"
    AUTHORIZED_USER = "AUTHORIZED_USER"
    ORCHESTRATOR_IAM = "ORCHESTRATOR_IAM"


@dataclass(frozen=True)
class PolicyAuthority:
    """A trusted principal permitted to grant root authority."""

    authority_id: str
    kind: AuthorityKind


@dataclass
class Delegation:
    delegation_id: str
    subject_agent_id: str
    capabilities: frozenset[str]
    resource_scopes: frozenset[str]
    clearance: DataClassification
    not_before: datetime
    not_after: datetime
    max_chain_depth: int
    depth: int = 0
    parent_id: str | None = None
    issuer_id: str = ""
    revoked: bool = False
    revoked_at: datetime | None = None

    def is_valid_at(self, now: datetime) -> bool:
        return (
            not self.revoked
            and self.not_before <= now < self.not_after
        )


class DelegationRegistry:
    """Issues and validates delegations; enforces the no-widen invariants."""

    def __init__(self, authorities: list[PolicyAuthority] | None = None) -> None:
        self._authorities: dict[str, PolicyAuthority] = {
            a.authority_id: a for a in (authorities or [])
        }
        self._delegations: dict[str, Delegation] = {}

    def register_authority(self, authority: PolicyAuthority) -> None:
        self._authorities[authority.authority_id] = authority

    # ------------------------------------------------------------------ #
    # issuance
    # ------------------------------------------------------------------ #
    def issue_root(
        self,
        *,
        authority_id: str,
        subject_agent_id: str,
        capabilities: set[str],
        resource_scopes: set[str],
        clearance: DataClassification,
        not_before: datetime,
        not_after: datetime,
        max_chain_depth: int = 4,
    ) -> Delegation:
        """Issue a root delegation from a TRUSTED authority (no self-auth)."""
        authority = self._authorities.get(authority_id)
        if authority is None:
            # Untrusted issuer (or the agent trying to self-authorize).
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "root delegation from untrusted issuer"
            )
        if authority_id == subject_agent_id:
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "authority cannot delegate to itself"
            )
        if not_after <= not_before:
            raise CVZTTEError(ErrorCode.DELEGATION_INVALID, "empty validity window")
        if max_chain_depth < 0:
            raise CVZTTEError(ErrorCode.DELEGATION_INVALID, "invalid chain depth")
        dele = Delegation(
            delegation_id="dlg_" + uuid.uuid4().hex,
            subject_agent_id=subject_agent_id,
            capabilities=frozenset(capabilities),
            resource_scopes=frozenset(resource_scopes),
            clearance=clearance,
            not_before=not_before,
            not_after=not_after,
            max_chain_depth=max_chain_depth,
            depth=0,
            parent_id=None,
            issuer_id=authority_id,
        )
        self._delegations[dele.delegation_id] = dele
        return dele

    def issue_child(
        self,
        *,
        parent_id: str,
        subject_agent_id: str,
        capabilities: set[str],
        resource_scopes: set[str],
        clearance: DataClassification,
        not_before: datetime,
        not_after: datetime,
    ) -> Delegation:
        """Delegate a SUBSET of a parent delegation to a sub-agent (spec §23)."""
        parent = self._require(parent_id)
        now = _utcnow()
        if not parent.is_valid_at(now):
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "parent delegation invalid/expired/revoked"
            )
        # Chain depth bound.
        child_depth = parent.depth + 1
        if child_depth > parent.max_chain_depth:
            raise CVZTTEError(ErrorCode.DELEGATION_INVALID, "chain depth exceeded")
        # Capabilities: child ⊆ parent.
        caps = frozenset(capabilities)
        if not caps <= parent.capabilities:
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "child capabilities exceed parent"
            )
        # Resource scopes: child ⊆ parent (cannot widen).
        scopes = frozenset(resource_scopes)
        if not scopes <= parent.resource_scopes:
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "child resource scope widens parent"
            )
        # Clearance: child ≤ parent.
        if _CLEARANCE_ORDER[clearance] > _CLEARANCE_ORDER[parent.clearance]:
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "child clearance exceeds parent"
            )
        # Expiry: child ≤ parent.
        if not_before < parent.not_before or not_after > parent.not_after:
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "child validity exceeds parent"
            )
        if not_after <= not_before:
            raise CVZTTEError(ErrorCode.DELEGATION_INVALID, "empty validity window")
        dele = Delegation(
            delegation_id="dlg_" + uuid.uuid4().hex,
            subject_agent_id=subject_agent_id,
            capabilities=caps,
            resource_scopes=scopes,
            clearance=clearance,
            not_before=not_before,
            not_after=not_after,
            max_chain_depth=parent.max_chain_depth,
            depth=child_depth,
            parent_id=parent_id,
            issuer_id=parent.subject_agent_id,
        )
        self._delegations[dele.delegation_id] = dele
        return dele

    # ------------------------------------------------------------------ #
    # validation / revocation
    # ------------------------------------------------------------------ #
    def _require(self, delegation_id: str) -> Delegation:
        dele = self._delegations.get(delegation_id)
        if dele is None:
            raise CVZTTEError(ErrorCode.DELEGATION_INVALID, "unknown delegation")
        return dele

    def get(self, delegation_id: str) -> Delegation:
        return self._require(delegation_id)

    def validate_for_agent(
        self, delegation_id: str, agent_id: str, *, now: datetime | None = None
    ) -> Delegation:
        """Return the delegation iff it is valid and bound to ``agent_id``.

        Walks the ancestry so a child whose ancestor was revoked/expired is
        itself rejected (revocation propagation / no authority laundering).
        """
        now = now or _utcnow()
        dele = self._require(delegation_id)
        if dele.subject_agent_id != agent_id:
            raise CVZTTEError(
                ErrorCode.DELEGATION_INVALID, "delegation not bound to agent"
            )
        node: Delegation | None = dele
        seen: set[str] = set()
        while node is not None:
            if node.delegation_id in seen:  # cycle guard
                raise CVZTTEError(ErrorCode.DELEGATION_INVALID, "delegation cycle")
            seen.add(node.delegation_id)
            if not node.is_valid_at(now):
                raise CVZTTEError(
                    ErrorCode.DELEGATION_INVALID, "delegation chain invalid/expired/revoked"
                )
            node = self._delegations.get(node.parent_id) if node.parent_id else None
        return dele

    def revoke(self, delegation_id: str) -> list[str]:
        """Revoke a delegation and propagate to all descendants (spec §23)."""
        root = self._require(delegation_id)
        revoked_ids: list[str] = []
        now = _utcnow()

        def _revoke(d: Delegation) -> None:
            if not d.revoked:
                d.revoked = True
                d.revoked_at = now
                revoked_ids.append(d.delegation_id)

        _revoke(root)
        # Repeatedly sweep for children of anything already revoked.
        changed = True
        while changed:
            changed = False
            for d in self._delegations.values():
                if (
                    not d.revoked
                    and d.parent_id is not None
                    and self._delegations.get(d.parent_id, None) is not None
                    and self._delegations[d.parent_id].revoked
                ):
                    _revoke(d)
                    changed = True
        return revoked_ids
