"""Containment threshold policy (spec §25, §60.18).

Transition thresholds MUST be policy/config controlled, not hardcoded in the
engine (§60.18). This module holds them in a dataclass the deployment supplies
(reference defaults provided); the engine only *applies* them. In a full
deployment these values come from OPA/config.

Assessment maps evasion/behavior features to the highest warranted state. It
never returns TERMINATED — termination is reserved for a sandbox-escape
indicator or explicit administrator kill (§60.18), handled by the kill switch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cvztte.decision.model import ContainmentState


@dataclass(frozen=True)
class ContainmentThresholds:
    """Config-controlled thresholds (spec §60.18 feature set)."""

    # NORMAL -> SUSPICIOUS
    suspicious_denials_60s: int = 3
    suspicious_bypass_5m: int = 1
    # SUSPICIOUS -> RESTRICTED
    restricted_denials_5m: int = 8
    restricted_bypass_5m: int = 2
    # RESTRICTED -> QUARANTINED
    quarantine_bypass_5m: int = 3
    quarantine_secret_probe: int = 3
    #: Feature flags that force QUARANTINED regardless of counts.
    quarantine_signal_flags: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"sensitive_read_to_egress_sequence", "secret_exfiltration_attempt"}
        )
    )


def _get(features: dict[str, Any], key: str) -> int:
    v = features.get(key, 0)
    return int(v) if isinstance(v, (int, float, bool)) else 0


class ThresholdPolicy:
    """Applies configured thresholds to a feature map to assess a warranted state."""

    def __init__(self, thresholds: ContainmentThresholds | None = None) -> None:
        self._t = thresholds or ContainmentThresholds()

    def assess(self, features: dict[str, Any]) -> ContainmentState:
        t = self._t
        warranted = ContainmentState.NORMAL

        if (
            _get(features, "denials_60s") >= t.suspicious_denials_60s
            or _get(features, "bypass_attempts_5m") >= t.suspicious_bypass_5m
        ):
            warranted = ContainmentState.SUSPICIOUS

        if (
            _get(features, "denials_5m") >= t.restricted_denials_5m
            or _get(features, "bypass_attempts_5m") >= t.restricted_bypass_5m
        ):
            warranted = ContainmentState.RESTRICTED

        signal = any(bool(features.get(f)) for f in t.quarantine_signal_flags)
        if (
            signal
            or _get(features, "bypass_attempts_5m") >= t.quarantine_bypass_5m
            or _get(features, "secret_probe_count") >= t.quarantine_secret_probe
        ):
            warranted = ContainmentState.QUARANTINED

        return warranted
