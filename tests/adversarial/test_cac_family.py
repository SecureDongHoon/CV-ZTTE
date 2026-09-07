"""Adversarial family: FHE/CAC permission split and containment decay
(§51 FHE/CAC, §60.31 #122-124, #133-134).

The security heart of CAC is pure and testable without the native OpenFHE broker:
compute authority never implies decrypt (§42), and a contained subject loses CAC
capability per the ceiling (§47). The real-crypto substitution / threshold cases
(#120-121, #125-141, #145-150) are covered by tests/integration/test_cac_e2e.py,
tests/integration/test_threshold_e2e.py, test_confidential_query.py and
test_lineage.py — see docs/ADVERSARIAL_SUITE.md for the case map.
"""

from __future__ import annotations

import pytest

from cvztte.action.model import DataClassification
from cvztte.cac.guard import require_compute, require_decrypt, require_read_plaintext
from cvztte.cac.permissions import CACPermission as P
from cvztte.control_plane import CACService
from cvztte.decision.model import ContainmentState as C
from cvztte.errors import CVZTTEError, ErrorCode

COMPUTE_ONLY = frozenset({P.COMPUTE_ON_CIPHERTEXT})
DECRYPT_ONLY = frozenset({P.DECRYPT_RESULT})
FULL = frozenset({P.READ_PLAINTEXT, P.COMPUTE_ON_CIPHERTEXT, P.DECRYPT_RESULT})


# #122 Analytics agent computes but sees no plaintext ------------------------


def test_case122_compute_without_read():
    require_compute(COMPUTE_ONLY, C.NORMAL)  # allowed
    with pytest.raises(CVZTTEError) as exc:
        require_read_plaintext(COMPUTE_ONLY, C.NORMAL)
    assert exc.value.code is ErrorCode.FHE_DECRYPT_DENIED


# #123 compute does not grant decrypt ---------------------------------------


def test_case123_compute_does_not_grant_decrypt():
    require_compute(COMPUTE_ONLY, C.NORMAL)
    with pytest.raises(CVZTTEError) as exc:
        require_decrypt(COMPUTE_ONLY, C.NORMAL)
    assert exc.value.code is ErrorCode.FHE_DECRYPT_DENIED


# #124 decrypt checked separately from compute ------------------------------


def test_case124_decrypt_checked_separately():
    require_decrypt(DECRYPT_ONLY, C.NORMAL)
    with pytest.raises(CVZTTEError) as exc:
        require_compute(DECRYPT_ONLY, C.NORMAL)
    assert exc.value.code is ErrorCode.FHE_COMPUTE_DENIED


# #133 quarantined agent cannot compute -------------------------------------


def test_case133_quarantined_cannot_compute():
    with pytest.raises(CVZTTEError) as exc:
        require_compute(FULL, C.QUARANTINED)
    assert exc.value.code is ErrorCode.FHE_COMPUTE_DENIED


# #134 quarantined agent cannot decrypt -------------------------------------


def test_case134_quarantined_cannot_decrypt():
    with pytest.raises(CVZTTEError) as exc:
        require_decrypt(FULL, C.QUARANTINED)
    assert exc.value.code is ErrorCode.FHE_DECRYPT_DENIED


def test_suspicious_decays_decrypt_keeps_compute():
    require_compute(FULL, C.SUSPICIOUS)  # compute survives
    with pytest.raises(CVZTTEError):
        require_decrypt(FULL, C.SUSPICIOUS)  # decrypt decayed


# #147 CAC fails closed when the FHE broker is unavailable -------------------


def test_case147_cac_broker_unavailable_fails_closed():
    svc = CACService(broker=None)
    with pytest.raises(CVZTTEError) as exc:
        svc.encrypt(
            granted=FULL, containment_state=C.NORMAL, context_id="ctx",
            expected_context_hash="sha256:" + "0" * 64, values=[1.0],
            dataset_id="ds", owner="o",
            classification=DataClassification.CONFIDENTIAL, allowed_programs=[],
        )
    assert exc.value.code is ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE
