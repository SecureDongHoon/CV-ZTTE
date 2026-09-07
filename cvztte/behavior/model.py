"""Behavior events and canonical state snapshot (spec §24, §60.6).

Single-action authorization is insufficient (§24): the Behavior Engine keeps
per-scope rolling state so sequences (probing, exfiltration ramps, fanout,
destination switching after denial) are visible to risk/containment/Judge.

Event kinds are kept distinct (§60.6): a cooperative *proposal* and its eventual
*execution* must not be double-counted as two independent attacks. Windowed
"what the agent actually did" features count ``EXECUTED`` events; "what was
blocked/attempted" features count ``DENIED`` / ``BYPASS_ATTEMPTED`` / attempts.

The snapshot has a canonical, versioned hash (`Domain.BEHAVIOR_STATE`) so it can
be bound into high-risk Judge/proof flows and checked for equality by a verifier
(§24). The hash excludes wall-clock ``computed_at`` so identical behavioral
content hashes identically.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cvztte.action.model import DataClassification
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit

#: Rolling window sizes (seconds), spec §60.6.
WINDOW_10S = 10
WINDOW_60S = 60
WINDOW_5M = 300


class BehaviorEventKind(str, enum.Enum):
    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    BYPASS_ATTEMPTED = "BYPASS_ATTEMPTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class BehaviorEvent(BaseModel):
    """One observed lifecycle event for a scope."""

    model_config = ConfigDict(extra="forbid")

    kind: BehaviorEventKind
    action_type: str
    at: datetime
    resource: str | None = None
    external_destination: str | None = None
    data_classification: DataClassification = DataClassification.INTERNAL
    bytes_read: int = 0
    bytes_written: int = 0
    external_bytes: int = 0
    sensitive_read: bool = False
    secret_access: bool = False
    privilege_escalation: bool = False
    destructive: bool = False
    message_recipient: str | None = None


class BehaviorScope(BaseModel):
    """State-partitioning key (spec §24): agent/session/runtime/delegation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    session_id: str
    runtime_id: str
    delegation_id: str | None = None


class BehaviorSnapshot(BaseModel):
    """Canonical, hashable behavior-state snapshot (spec §60.6)."""

    model_config = ConfigDict(extra="forbid")

    snapshot_version: int = 1
    scope: BehaviorScope
    windows_seconds: dict[str, int] = Field(
        default_factory=lambda: {"s10": WINDOW_10S, "s60": WINDOW_60S, "m5": WINDOW_5M}
    )
    # Windowed "did" features.
    actions_last_10s: int = 0
    actions_last_60s: int = 0
    actions_last_5m: int = 0
    sensitive_reads_last_5m: int = 0
    # Cumulative (session-lifetime) features.
    bytes_read: int = 0
    bytes_written: int = 0
    external_bytes: int = 0
    unique_resources: int = 0
    secret_access_count: int = 0
    policy_denials: int = 0
    privilege_escalation_attempts: int = 0
    new_external_destination: int = 0
    destructive_action_count: int = 0
    agent_message_fanout: int = 0
    bypass_attempts: int = 0
    computed_at: str

    def _hashable_dict(self) -> dict[str, Any]:
        d = self.model_dump(mode="json", exclude_none=True)
        d.pop("computed_at", None)  # content-addressed, not time-addressed
        return d

    def snapshot_hash(self) -> str:
        return commit(Domain.BEHAVIOR_STATE, self._hashable_dict())
