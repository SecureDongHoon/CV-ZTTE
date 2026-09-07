"""Containment state + dynamic capability decay model (spec §25-§27, §60.18-§60.20).

The containment state machine is a first-class ordered ladder
``NORMAL -> SUSPICIOUS -> RESTRICTED -> QUARANTINED -> TERMINATED`` (§25). It is
not a mere severity label: it changes *effective authority* through capability
decay (§26). Containment can only ever *remove* authority — it can never grant
it (§26).

Effective capability (§60.19) is:

    intersection(delegated, enterprise_policy, runtime_profile,
                 containment_capability_ceiling)

The ceiling is applied last and monotonically tightens as the state escalates.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

# Reuse the single ContainmentState definition (also carried by Decision Tokens).
from cvztte.decision.model import ContainmentState

#: Escalation order (index = severity). Higher index = less authority.
STATE_ORDER: list[ContainmentState] = [
    ContainmentState.NORMAL,
    ContainmentState.SUSPICIOUS,
    ContainmentState.RESTRICTED,
    ContainmentState.QUARANTINED,
    ContainmentState.TERMINATED,
]


def severity(state: ContainmentState) -> int:
    return STATE_ORDER.index(state)


def more_severe(a: ContainmentState, b: ContainmentState) -> ContainmentState:
    return a if severity(a) >= severity(b) else b


class CapabilityAttributes(BaseModel):
    """How a named capability is classified for decay (enterprise-defined)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    optional_high_risk: bool = False
    writes: bool = False
    external_network: bool = False
    secret_access: bool = False
    new_subagent: bool = False
    diagnostic: bool = False


#: Capability with no attributes = a plain internal read.
_DEFAULT_ATTRS = CapabilityAttributes()


def _ceiling_allows(state: ContainmentState, attrs: CapabilityAttributes) -> bool:
    """Whether the containment ceiling for ``state`` permits this capability (§60.19)."""
    if state is ContainmentState.NORMAL:
        return True
    if state is ContainmentState.SUSPICIOUS:
        # Remove optional high-risk capabilities.
        return not attrs.optional_high_risk
    if state is ContainmentState.RESTRICTED:
        # Read-only, no external network, no secret access, no new sub-agents.
        return not (
            attrs.optional_high_risk
            or attrs.writes
            or attrs.external_network
            or attrs.secret_access
            or attrs.new_subagent
        )
    if state is ContainmentState.QUARANTINED:
        # Diagnostic / status only.
        return attrs.diagnostic
    # TERMINATED: no runtime authority.
    return False


CapabilityProfile = dict[str, CapabilityAttributes]


def effective_capabilities(
    *,
    delegated: set[str],
    enterprise_policy: set[str],
    runtime_profile: set[str],
    state: ContainmentState,
    profile: CapabilityProfile | None = None,
) -> frozenset[str]:
    """Compute effective capability per §60.19. Containment only removes (§26)."""
    profile = profile or {}
    base = set(delegated) & set(enterprise_policy) & set(runtime_profile)
    return frozenset(
        c for c in base if _ceiling_allows(state, profile.get(c, _DEFAULT_ATTRS))
    )


class ContainmentTransition(BaseModel):
    """Auditable transition record (spec §60.20)."""

    model_config = ConfigDict(extra="forbid")

    subject: str
    agent_id: str
    runtime_id: str | None = None
    old_state: ContainmentState
    new_state: ContainmentState
    reason_codes: list[str]
    evidence_hash: str
    capability_epoch: int
    at: str


def blocks_new_consequential_tokens(state: ContainmentState) -> bool:
    """QUARANTINED/TERMINATED deny new consequential tokens (§60.20)."""
    return severity(state) >= severity(ContainmentState.QUARANTINED)
