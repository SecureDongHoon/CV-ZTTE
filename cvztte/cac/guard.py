"""CAC permission gate (spec §35, §42, §47).

Pure, fail-closed checks the control plane applies *before* invoking the FHE
broker. They enforce the three-way permission split and the containment ceiling:
compute authority never implies decrypt (§42), and a contained subject loses CAC
capability per the ceiling (§47). These do not replace the normal pipeline — the
caller still runs identity/policy/token — they add the CAC-specific gate.
"""

from __future__ import annotations

from cvztte.cac.permissions import (
    CACPermission,
    effective_cac_permissions,
)
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode


def _effective(
    granted: frozenset[CACPermission], state: ContainmentState
) -> frozenset[CACPermission]:
    return effective_cac_permissions(granted, state)


def require_compute(
    granted: frozenset[CACPermission], state: ContainmentState
) -> None:
    """Require COMPUTE_ON_CIPHERTEXT after containment decay, else FHE_COMPUTE_DENIED."""
    if CACPermission.COMPUTE_ON_CIPHERTEXT not in _effective(granted, state):
        raise CVZTTEError(
            ErrorCode.FHE_COMPUTE_DENIED,
            "compute-on-ciphertext not permitted at current containment state",
        )


def require_decrypt(
    granted: frozenset[CACPermission], state: ContainmentState
) -> None:
    """Require DECRYPT_RESULT after containment decay, else FHE_DECRYPT_DENIED.

    Compute authority does not imply decrypt (§42): holding
    COMPUTE_ON_CIPHERTEXT alone never satisfies this.
    """
    if CACPermission.DECRYPT_RESULT not in _effective(granted, state):
        raise CVZTTEError(
            ErrorCode.FHE_DECRYPT_DENIED,
            "decrypt-result not permitted at current containment state",
        )


def require_read_plaintext(
    granted: frozenset[CACPermission], state: ContainmentState
) -> None:
    """Require READ_PLAINTEXT after containment decay, else FHE_DECRYPT_DENIED."""
    if CACPermission.READ_PLAINTEXT not in _effective(granted, state):
        raise CVZTTEError(
            ErrorCode.FHE_DECRYPT_DENIED,
            "read-plaintext not permitted at current containment state",
        )
