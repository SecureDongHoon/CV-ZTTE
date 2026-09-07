"""Canonical AgentContext and provenance (spec §7, §60.10).

Adapters are semantic sensors, not trust boundaries (§4.2). Missing semantic
context never lowers protection (§4.3); high-risk actions with insufficient
required context default to DENY/ESCALATE (§60.10). For high-risk effects the
enforcement-point (boundary) observation is authoritative (§7).
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict

from cvztte.action.model import DataClassification


class SemanticContextQuality(str, enum.Enum):
    RICH = "RICH"
    PARTIAL = "PARTIAL"
    BOUNDARY_ONLY = "BOUNDARY_ONLY"
    UNKNOWN = "UNKNOWN"


class ObservationSource(str, enum.Enum):
    """Where the action was observed (spec §7 provenance)."""

    ADAPTER = "ADAPTER"
    MCP_GATEWAY = "MCP_GATEWAY"
    EGRESS_PROXY = "EGRESS_PROXY"
    FILE_BROKER = "FILE_BROKER"
    PROCESS_BROKER = "PROCESS_BROKER"
    OUTPUT_PROXY = "OUTPUT_PROXY"
    MESSAGE_BROKER = "MESSAGE_BROKER"
    FHE_BROKER = "FHE_BROKER"
    SECRET_BROKER = "SECRET_BROKER"


class Provenance(BaseModel):
    """Identifies how/where an action was observed (spec §7, §60.10)."""

    model_config = ConfigDict(extra="forbid")

    source: ObservationSource
    adapter_id: str | None = None
    runtime_id: str
    observed_at: str  # RFC3339 timestamp
    # True only when an actual enforcement-point boundary observed the effect.
    boundary_observed: bool = False


class AgentContext(BaseModel):
    """Rich (or degraded) semantic context around an action (spec §7)."""

    model_config = ConfigDict(extra="forbid")

    context_version: int = 1
    agent_id: str
    runtime_id: str
    session_id: str
    delegation_id: str | None = None
    framework: str | None = None
    adapter_id: str | None = None
    workflow_id: str | None = None
    node_id: str | None = None
    intent_hash: str | None = None
    purpose_code: str | None = None
    data_classification: DataClassification = DataClassification.INTERNAL
    semantic_context_quality: SemanticContextQuality = SemanticContextQuality.UNKNOWN
