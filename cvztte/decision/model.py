"""Decision Token v3 data model (spec §31, §60.11).

The Decision Token is a short-lived, single-use *execution capability*. It binds
one canonical action (by ActionHash + exact target/operation/payload
constraints) to one agent/runtime/session, one enforcement audience, and a
snapshot of the revocation/policy/capability/risk epochs it was minted under.

The token body carries every §60.11 field. Authenticity is provided separately
by a keyed MAC (see :mod:`cvztte.decision.authority`) computed over the token's
canonical bytes; the MAC key is gateway-only and never leaves the token
authority / enforcement boundary. A :class:`SignedDecisionToken` is the token
plus its MAC — the artifact an agent presents at an enforcement point.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cvztte.canonical.jcs import canonicalize


class TokenDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REDACT = "REDACT"


class ContainmentState(str, enum.Enum):
    """Agent containment state (spec §30). Phase 10 owns the state machine;
    the token records the state under which it was authorized."""

    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    RESTRICTED = "RESTRICTED"
    QUARANTINED = "QUARANTINED"
    TERMINATED = "TERMINATED"


class EpochSet(BaseModel):
    """Revocation/policy/capability/risk epochs (spec §27).

    Enforcement points reject a token whose epochs no longer match the current
    epochs (a revocation, policy change, capability decay, or risk bump advances
    an epoch and invalidates every token minted under the older value).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_revocation_epoch: int = 0
    runtime_revocation_epoch: int = 0
    policy_epoch: int = 0
    capability_epoch: int = 0
    risk_epoch: int = 0


class TokenChecks(BaseModel):
    """Which control-plane checks were performed before issuance (§60.11)."""

    model_config = ConfigDict(extra="forbid")

    mldsa: bool = False
    opa: bool = False
    gnark: bool = False
    behavior: bool = False
    judge: str = "UNKNOWN"
    ezkl: bool = False


class DecisionToken(BaseModel):
    """Decision Token v3 body — all §60.11 minimum fields."""

    model_config = ConfigDict(extra="forbid")

    token_version: int = 3
    decision_id: str
    request_id: str
    agent_id: str
    runtime_id: str
    session_id: str
    action_hash: str
    action_type: str
    target_constraint: str
    operation_constraint: str | None = None
    payload_hash: str | None = None
    policy_hash: str
    risk_level: int = 0
    containment_state: ContainmentState = ContainmentState.NORMAL
    decision: TokenDecision = TokenDecision.ALLOW
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    max_uses: int = 1
    nonce: str
    audience: str
    epochs: EpochSet = Field(default_factory=EpochSet)
    checks: TokenChecks = Field(default_factory=TokenChecks)

    def canonical_bytes(self) -> bytes:
        """RFC 8785 canonical bytes of the token body (input to the MAC)."""
        return canonicalize(self.model_dump(mode="json", exclude_none=True))

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class SignedDecisionToken(BaseModel):
    """A Decision Token plus its keyed MAC (the presented artifact)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token: DecisionToken
    mac: str  # "hmac-sha256:<hex>"
