"""CAC permission model (spec §35).

CAC (Confidential Agent Collaboration) allows approved computation on sensitive
data without disclosing plaintext to compute-only agents. The permission model
distinguishes three *separate* capabilities (§35) — critically, **compute
authority does not imply decrypt authority** (§42):

    READ_PLAINTEXT        — may see the underlying plaintext
    COMPUTE_ON_CIPHERTEXT — may run approved programs over ciphertext
    DECRYPT_RESULT        — may obtain plaintext of an (approved) result

These are enforced *in addition* to the normal CV-ZTTE pipeline (identity,
policy, authorization, behavior, containment, token, audit) — CAC does not
replace any of it (§35).
"""

from __future__ import annotations

import enum

from cvztte.decision.model import ContainmentState


class CACPermission(str, enum.Enum):
    READ_PLAINTEXT = "READ_PLAINTEXT"
    COMPUTE_ON_CIPHERTEXT = "COMPUTE_ON_CIPHERTEXT"
    DECRYPT_RESULT = "DECRYPT_RESULT"


#: Reference role → permission grants (§35 example). The data owner may do
#: everything; an analytics agent computes only; a security supervisor may
#: decrypt approved results; an unauthorized agent has nothing.
REFERENCE_ROLE_GRANTS: dict[str, frozenset[CACPermission]] = {
    "data_owner": frozenset(CACPermission),
    "analytics_agent": frozenset({CACPermission.COMPUTE_ON_CIPHERTEXT}),
    "security_supervisor": frozenset({CACPermission.DECRYPT_RESULT}),
    "unauthorized": frozenset(),
}


#: Containment ceilings for CAC (spec §47). A subject may exercise a CAC
#: permission only if it is within the ceiling for its current containment state.
#: RESTRICTED forbids decrypt; QUARANTINED/TERMINATED forbid all CAC.
_CONTAINMENT_CEILING: dict[ContainmentState, frozenset[CACPermission]] = {
    ContainmentState.NORMAL: frozenset(CACPermission),
    # SUSPICIOUS: lower-risk approved compute only — no decrypt (§47).
    ContainmentState.SUSPICIOUS: frozenset({CACPermission.COMPUTE_ON_CIPHERTEXT}),
    # RESTRICTED: pre-approved datasets/programs, no decrypt (§47).
    ContainmentState.RESTRICTED: frozenset({CACPermission.COMPUTE_ON_CIPHERTEXT}),
    ContainmentState.QUARANTINED: frozenset(),
    ContainmentState.TERMINATED: frozenset(),
}


def ceiling_for(state: ContainmentState) -> frozenset[CACPermission]:
    """CAC permissions allowed at a containment state (§47). Fail-closed default: none."""
    return _CONTAINMENT_CEILING.get(state, frozenset())


def effective_cac_permissions(
    granted: frozenset[CACPermission], state: ContainmentState
) -> frozenset[CACPermission]:
    """Decay CAC grants by the containment ceiling (§47). Containment only removes."""
    return granted & ceiling_for(state)
