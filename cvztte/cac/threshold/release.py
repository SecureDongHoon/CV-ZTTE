"""Decryption release policy (spec §42, §60.26).

Decryption is a **separate high-risk action** from computation. Before any
plaintext is released, this gate enforces — fail-closed — the release-time
checks the spec calls out (§60.26):

* the requester holds ``DECRYPT_RESULT`` *after* containment decay (§42, §47) —
  compute authority never suffices;
* the result envelope is intact — the ciphertext bytes about to be fused still
  match the hash the control plane authorized (no result substitution, §38);
* human approval is present when the data classification requires it (§48).

This is the release gate only. It is **not** differential privacy and does not
itself do query-frequency/aggregation accounting — that is Confidential Query
Governance (Phase 16, §45/§60.27), which plugs in as an additional gate. Output
Proxy / DLP wiring is Phase 17 (§60.26). Those deferrals are documented, not
silently skipped: this gate refuses to release unless its own checks pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cvztte.action.model import DataClassification
from cvztte.cac.guard import require_decrypt
from cvztte.cac.permissions import CACPermission
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import domain_hash_hex
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode

#: Classifications whose plaintext release requires explicit human approval (§48).
_APPROVAL_REQUIRED_CLASSES = frozenset(
    {DataClassification.CONFIDENTIAL, DataClassification.SECRET}
)


@dataclass(frozen=True)
class DecryptReleaseRequest:
    """Everything the release gate needs to judge a plaintext release (§60.26)."""

    recipient: str
    purpose: str
    classification: DataClassification
    granted: frozenset[CACPermission]
    containment_state: ContainmentState
    #: Bytes of the ciphertext about to be fused, for tamper/substitution check.
    result_ciphertext_bytes: bytes
    #: The result hash the control plane authorized (from the ResultEnvelope, §38).
    expected_result_hash: str
    #: Present iff a human approval was granted for this release (§48).
    approval_granted: bool = False
    approval_id: str | None = None
    metadata: dict = field(default_factory=dict)


class ThresholdReleasePolicy:
    """Default fail-closed release gate for threshold decryption."""

    def authorize(self, request: DecryptReleaseRequest) -> None:
        """Raise ``CVZTTEError`` unless plaintext release is permitted."""
        # 1. Decrypt capability after containment decay (§42, §47).
        require_decrypt(request.granted, request.containment_state)

        # 2. Result integrity: reject a substituted result ciphertext (§38).
        actual = domain_hash_hex(Domain.FHE_RESULT, request.result_ciphertext_bytes)
        if actual != request.expected_result_hash:
            raise CVZTTEError(
                ErrorCode.FHE_RESULT_RELEASE_DENIED,
                "result ciphertext does not match authorized envelope",
            )

        # 3. Human approval where classification requires it (§48).
        if request.classification in _APPROVAL_REQUIRED_CLASSES and not request.approval_granted:
            raise CVZTTEError(
                ErrorCode.APPROVAL_REQUIRED,
                "human approval required to release plaintext at this classification",
                detail={"classification": request.classification.value},
            )
