"""Unit tests for threshold FHE release policy + coordinator guards (§41, §42).

These exercise the fail-closed decision logic without the native broker: the
release gate and the N-of-N presence check both run before any crypto, so no
secret share or binary is involved.
"""

from __future__ import annotations

import pytest

from cvztte.action.model import DataClassification
from cvztte.cac.permissions import CACPermission
from cvztte.cac.threshold.coordinator import DecryptCoordinator
from cvztte.cac.threshold.release import DecryptReleaseRequest, ThresholdReleasePolicy
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import domain_hash_hex
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode

_RESULT_BYTES = b"opaque-ckks-result-ciphertext"
_RESULT_HASH = domain_hash_hex(Domain.FHE_RESULT, _RESULT_BYTES)


def _request(**overrides) -> DecryptReleaseRequest:
    base = dict(
        recipient="sec-supervisor",
        purpose="incident-review",
        classification=DataClassification.INTERNAL,
        granted=frozenset({CACPermission.DECRYPT_RESULT}),
        containment_state=ContainmentState.NORMAL,
        result_ciphertext_bytes=_RESULT_BYTES,
        expected_result_hash=_RESULT_HASH,
    )
    base.update(overrides)
    return DecryptReleaseRequest(**base)


class FakeParticipant:
    """Records calls; never touches a share or binary."""

    def __init__(self, party_id: str) -> None:
        self.party_id = party_id
        self.partials = 0

    def keygen_lead(self, **_):  # pragma: no cover - unused here
        return {}

    def keygen_join(self, **_):  # pragma: no cover - unused here
        return {}

    def partial_decrypt(self, **_):
        self.partials += 1
        return {"partial": "fake"}


# -- release policy ---------------------------------------------------------


def test_release_allows_internal_with_decrypt():
    ThresholdReleasePolicy().authorize(_request())


def test_release_denies_without_decrypt_permission():
    with pytest.raises(CVZTTEError) as ei:
        ThresholdReleasePolicy().authorize(
            _request(granted=frozenset({CACPermission.COMPUTE_ON_CIPHERTEXT}))
        )
    assert ei.value.code is ErrorCode.FHE_DECRYPT_DENIED


def test_release_denies_when_containment_strips_decrypt():
    # RESTRICTED forbids decrypt even if the role granted it (§47).
    with pytest.raises(CVZTTEError) as ei:
        ThresholdReleasePolicy().authorize(
            _request(containment_state=ContainmentState.RESTRICTED)
        )
    assert ei.value.code is ErrorCode.FHE_DECRYPT_DENIED


def test_release_denies_on_result_substitution():
    with pytest.raises(CVZTTEError) as ei:
        ThresholdReleasePolicy().authorize(
            _request(result_ciphertext_bytes=b"different-bytes")
        )
    assert ei.value.code is ErrorCode.FHE_RESULT_RELEASE_DENIED


def test_release_requires_approval_for_confidential():
    with pytest.raises(CVZTTEError) as ei:
        ThresholdReleasePolicy().authorize(
            _request(classification=DataClassification.CONFIDENTIAL)
        )
    assert ei.value.code is ErrorCode.APPROVAL_REQUIRED


def test_release_allows_confidential_with_approval():
    ThresholdReleasePolicy().authorize(
        _request(
            classification=DataClassification.CONFIDENTIAL,
            approval_granted=True,
            approval_id="appr-1",
        )
    )


def test_release_requires_approval_for_secret():
    with pytest.raises(CVZTTEError) as ei:
        ThresholdReleasePolicy().authorize(
            _request(classification=DataClassification.SECRET)
        )
    assert ei.value.code is ErrorCode.APPROVAL_REQUIRED


# -- coordinator guards -----------------------------------------------------


def test_decrypt_requires_all_parties(tmp_path):
    parts = [FakeParticipant("A"), FakeParticipant("B")]
    coord = DecryptCoordinator(
        participants=parts,
        workspace_root=tmp_path,
        expected_parties=3,  # one party missing
    )
    with pytest.raises(CVZTTEError) as ei:
        coord.decrypt(
            context_dir=str(tmp_path / "ctx"),
            result_path=str(tmp_path / "res.bin"),
            length=1,
            release_request=_request(),
        )
    assert ei.value.code is ErrorCode.FHE_THRESHOLD_INSUFFICIENT
    # No partial decryption should have been attempted.
    assert all(p.partials == 0 for p in parts)


def test_decrypt_release_gate_runs_before_partials(tmp_path):
    parts = [FakeParticipant("A"), FakeParticipant("B"), FakeParticipant("C")]
    coord = DecryptCoordinator(
        participants=parts, workspace_root=tmp_path, expected_parties=3
    )
    with pytest.raises(CVZTTEError) as ei:
        coord.decrypt(
            context_dir=str(tmp_path / "ctx"),
            result_path=str(tmp_path / "res.bin"),
            length=1,
            # Missing DECRYPT_RESULT → release gate denies.
            release_request=_request(granted=frozenset()),
        )
    assert ei.value.code is ErrorCode.FHE_DECRYPT_DENIED
    assert all(p.partials == 0 for p in parts)
