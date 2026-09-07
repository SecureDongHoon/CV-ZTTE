"""Deterministic Safety-Judge feature extraction (spec §29, §60.8).

The Judge must reach a verdict from *deterministic* features — no LLM-only
security judgment (§29) — so the same action/policy/behavior/containment snapshot
always produces the identical feature vector. That determinism is what lets EZKL
(Phase 12) prove the Judge computation: the gateway independently re-derives
these exact features and the verifier checks equality (§30).

Features are drawn from: the canonical action, the OPA policy result,
resource/data risk, the behavior snapshot, the containment state,
intent/delegation, and destination attributes (§29). Every feature is a bounded
float in ``[0, 1]`` (saturating/log-scaled) so quantization for the ZK circuit is
stable and boundary flips are contained by the inference margin guard (§60.8).

The ordered ``FEATURE_NAMES`` list plus ``FEATURE_VERSION`` define the extractor
identity; :func:`feature_extractor_hash` pins it into the EZKL artifact manifest.
Changing the feature set MUST bump the version and re-pin.
"""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.containment.model import severity
from cvztte.decision.model import ContainmentState
from cvztte.policy.model import PolicyDecision

FEATURE_VERSION = 1

#: Ordered feature names — order is part of the extractor identity (§60.8).
FEATURE_NAMES: list[str] = [
    # --- canonical action shape ---
    "act_write",
    "act_external_network",
    "act_secret_access",
    "act_destructive",
    "act_code_or_shell",
    "act_message_out",
    "data_classification",
    # --- policy result ---
    "policy_risk_level",
    "policy_require_human_approval",
    "policy_require_ezkl",
    # --- containment / context ---
    "containment_severity",
    "destination_external",
    "destination_unknown",
    "has_delegation",
    # --- behavior snapshot (rolling/cumulative) ---
    "beh_actions_10s",
    "beh_actions_60s",
    "beh_sensitive_reads_5m",
    "beh_external_bytes",
    "beh_secret_access_count",
    "beh_policy_denials",
    "beh_priv_escalation_attempts",
    "beh_new_external_destination",
    "beh_destructive_count",
    "beh_message_fanout",
    "beh_bypass_attempts",
]

N_FEATURES = len(FEATURE_NAMES)

_WRITE_ACTIONS = {
    ActionType.FILE_WRITE,
    ActionType.FILE_DELETE,
    ActionType.MEMORY_WRITE,
    ActionType.DB_OPERATION,
    ActionType.CLOUD_CONTROL_ACTION,
}
_EXTERNAL_NET_ACTIONS = {
    ActionType.NETWORK_REQUEST,
    ActionType.API_REQUEST,
    ActionType.EXTERNAL_MESSAGE,
}
_DESTRUCTIVE_ACTIONS = {ActionType.FILE_DELETE}
_CODE_SHELL_ACTIONS = {
    ActionType.SHELL_EXEC,
    ActionType.PROCESS_EXEC,
    ActionType.CODE_EXECUTION,
}
_MESSAGE_OUT_ACTIONS = {ActionType.AGENT_MESSAGE, ActionType.EXTERNAL_MESSAGE}

_CLASSIFICATION_LEVEL = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.SECRET: 3,
}


class JudgeInput(BaseModel):
    """Everything the deterministic extractor needs (spec §29 feature sources)."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    action: AgentAction
    policy: PolicyDecision
    containment_state: ContainmentState = ContainmentState.NORMAL
    #: Whether the destination is outside the enterprise boundary.
    destination_external: bool = False
    #: Whether the destination is on a known/approved allowlist.
    destination_known: bool = True
    has_delegation: bool = True
    # Behavior snapshot features (defaults model "no adverse history").
    actions_last_10s: int = 0
    actions_last_60s: int = 0
    sensitive_reads_last_5m: int = 0
    external_bytes: int = 0
    secret_access_count: int = 0
    policy_denials: int = 0
    privilege_escalation_attempts: int = 0
    new_external_destination: int = 0
    destructive_action_count: int = 0
    agent_message_fanout: int = 0
    bypass_attempts: int = 0


def _sat(x: float, cap: float) -> float:
    """Saturating linear scale into [0, 1]."""
    if cap <= 0:
        return 0.0
    return max(0.0, min(x / cap, 1.0))


def _log_sat(x: float, decades: float) -> float:
    """Log10 scale into [0, 1] (for byte-count style features)."""
    if x <= 0:
        return 0.0
    return max(0.0, min(math.log10(1.0 + x) / decades, 1.0))


def extract(inp: JudgeInput) -> list[float]:
    """Deterministic feature vector of length :data:`N_FEATURES`."""
    a = inp.action
    at = a.action_type
    vec = [
        1.0 if at in _WRITE_ACTIONS else 0.0,
        1.0 if at in _EXTERNAL_NET_ACTIONS else 0.0,
        1.0 if at in (_secret_types := {ActionType.SECRET_ACCESS}) else 0.0,
        1.0 if at in _DESTRUCTIVE_ACTIONS else 0.0,
        1.0 if at in _CODE_SHELL_ACTIONS else 0.0,
        1.0 if at in _MESSAGE_OUT_ACTIONS else 0.0,
        _CLASSIFICATION_LEVEL.get(a.data_classification, 1) / 3.0,
        _sat(inp.policy.risk_level, 4.0),
        1.0 if inp.policy.require_human_approval else 0.0,
        1.0 if inp.policy.require_ezkl else 0.0,
        _sat(severity(inp.containment_state), 4.0),
        1.0 if inp.destination_external else 0.0,
        1.0 if (inp.destination_external and not inp.destination_known) else 0.0,
        1.0 if inp.has_delegation else 0.0,
        _sat(inp.actions_last_10s, 20.0),
        _sat(inp.actions_last_60s, 60.0),
        _sat(inp.sensitive_reads_last_5m, 20.0),
        _log_sat(inp.external_bytes, 7.0),
        _sat(inp.secret_access_count, 5.0),
        _sat(inp.policy_denials, 10.0),
        _sat(inp.privilege_escalation_attempts, 3.0),
        _sat(inp.new_external_destination, 5.0),
        _sat(inp.destructive_action_count, 5.0),
        _sat(inp.agent_message_fanout, 10.0),
        _sat(inp.bypass_attempts, 3.0),
    ]
    assert len(vec) == N_FEATURES  # extractor/vector length must stay in sync
    return vec


def feature_extractor_hash() -> str:
    """Domain-separated commitment pinning the extractor identity (§60.8)."""
    return commit(
        Domain.MODEL,
        {"kind": "judge_feature_extractor", "version": FEATURE_VERSION, "names": FEATURE_NAMES},
    )
