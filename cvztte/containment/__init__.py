"""Containment escalation + dynamic capability decay (spec §25-§27, §60.18-§60.20)."""

from __future__ import annotations

from cvztte.containment.engine import ContainmentEngine, RecoveryMethod
from cvztte.containment.model import (
    STATE_ORDER,
    CapabilityAttributes,
    CapabilityProfile,
    ContainmentTransition,
    blocks_new_consequential_tokens,
    effective_capabilities,
    more_severe,
    severity,
)
from cvztte.containment.policy import ContainmentThresholds, ThresholdPolicy
from cvztte.decision.model import ContainmentState

__all__ = [
    "ContainmentEngine",
    "RecoveryMethod",
    "ContainmentState",
    "ContainmentTransition",
    "CapabilityAttributes",
    "CapabilityProfile",
    "STATE_ORDER",
    "severity",
    "more_severe",
    "effective_capabilities",
    "blocks_new_consequential_tokens",
    "ContainmentThresholds",
    "ThresholdPolicy",
]
