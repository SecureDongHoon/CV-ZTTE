"""CV-ZTTE Control Plane (spec §54 Phase 17, §60.29).

Wires the phase-by-phase library into one fail-closed authorization pipeline and
exposes it through the agent/admin-separated planes and the §60.29 HTTP API. See
``docs/CONTROL_PLANE.md``.
"""

from __future__ import annotations

from cvztte.control_plane.approval import (
    ApprovalRecord,
    ApprovalState,
    ApprovalStore,
)
from cvztte.control_plane.cac_service import CACService, DecryptStatus
from cvztte.control_plane.plane import (
    ControlPlane,
    DecisionStatus,
    EvaluationResult,
    ExecuteOutcome,
    containment_subject,
)
from cvztte.control_plane.planes import AdminAuthorizer, AdminPlane, AgentPlane
from cvztte.control_plane.replay import InMemoryReplayGuard, ReplayGuardProtocol

__all__ = [
    "ApprovalRecord",
    "ApprovalState",
    "ApprovalStore",
    "CACService",
    "DecryptStatus",
    "ControlPlane",
    "DecisionStatus",
    "EvaluationResult",
    "ExecuteOutcome",
    "containment_subject",
    "AdminAuthorizer",
    "AdminPlane",
    "AgentPlane",
    "InMemoryReplayGuard",
    "ReplayGuardProtocol",
]
