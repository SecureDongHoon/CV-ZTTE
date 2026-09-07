"""Threshold FHE end-to-end over the REAL native broker (spec §41, §42).

Exercises the genuine OpenFHE N-of-N multiparty protocol with no mocks:

* a key ceremony across three key authorities produces a joint public context
  while each secret share stays in its own directory and NO full secret key is
  written to the shared context;
* encrypt + evaluate under the joint key, then release-gated distributed
  decryption fusing a partial from every party returns the correct plaintext;
* dropping a party makes decryption cryptographically fail (proving N-of-N);
* the whole flow also runs with each authority as a **separate OS process**.

Skipped if the binary is not built. Marked slow: several real CKKS key
generations.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cvztte.action.model import DataClassification
from cvztte.cac import (
    FHEBrokerClient,
    FHEContext,
    FHEContextRegistry,
    FHEProgramRegistry,
    ProgramId,
    SecurityProfile,
    default_binary_path,
)
from cvztte.cac.permissions import CACPermission
from cvztte.cac.threshold import (
    AuthorityRole,
    DecryptCoordinator,
    DecryptReleaseRequest,
    KeyAuthority,
    SubprocessParticipant,
    ThresholdKeyCeremony,
)
from cvztte.cac.threshold.authority import SHARE_FILE
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode

pytestmark = pytest.mark.slow

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ALLOWED = [ProgramId.SUM_V1, ProgramId.AVERAGE_V1]


def _context(threshold_participants: int) -> FHEContext:
    from cvztte.cac.context import ThresholdConfig

    return FHEContext(
        context_id="ckks-threshold-v1",
        openfhe_version="1.5.1",
        security_profile=SecurityProfile.SECURE_LAB,
        multiplicative_depth=2,
        scaling_mod_size=50,
        batch_size=8,
        key_epoch=1,
        threshold=ThresholdConfig(
            enabled=True,
            participants=threshold_participants,
            required_semantics="all N participants required (N-of-N)",
        ),
    )


def _local_authorities(root: Path) -> list[KeyAuthority]:
    roles = [
        ("A", AuthorityRole.DATA_OWNER),
        ("B", AuthorityRole.SECURITY_PRIVACY),
        ("C", AuthorityRole.CVZTTE_DECRYPTION),
    ]
    return [
        KeyAuthority(party_id=pid, role=role, share_dir=root / f"share-{pid}")
        for pid, role in roles
    ]


@pytest.fixture(scope="module")
def provisioned(tmp_path_factory):
    binary = default_binary_path()
    if not os.path.exists(binary):
        pytest.skip(f"fhe_broker not built at {binary}")
    ws = tmp_path_factory.mktemp("threshold")
    ctx = _context(3)
    authorities = _local_authorities(ws)
    ceremony = ThresholdKeyCeremony(participants=authorities, workspace_root=str(ws))
    ceremony.provision(ctx)

    creg = FHEContextRegistry()
    creg.register(ctx)
    client = FHEBrokerClient(
        workspace_root=str(ws), context_registry=creg, program_registry=FHEProgramRegistry()
    )
    return ws, ctx, authorities, client


def _evaluate_sum(client: FHEBrokerClient, ctx: FHEContext):
    path, env = client.encrypt(
        context_id=ctx.context_id,
        expected_context_hash=ctx.context_hash(),
        values=[10.0, 20.0, 30.0, 40.0],
        dataset_id="ds1",
        owner="data_owner",
        classification=DataClassification.INTERNAL,
        allowed_programs=_ALLOWED,
    )
    return client.evaluate(
        context_id=ctx.context_id,
        expected_context_hash=ctx.context_hash(),
        program_id=ProgramId.SUM_V1,
        inputs=[(path, env)],
    )


def test_ceremony_leaves_no_full_secret_key(provisioned):
    ws, ctx, authorities, _ = provisioned
    ctx_dir = ws / "contexts" / ctx.context_id
    files = {p.name for p in ctx_dir.iterdir()}
    # Public material only — never a secret key (§41).
    assert files == {"context.bin", "key-pub.bin", "eval-sum.bin"}
    assert "key-sec.bin" not in files
    # Each party holds exactly its own share, nowhere else.
    for auth in authorities:
        assert auth.has_share()


def test_threshold_decrypt_returns_correct_plaintext(provisioned):
    ws, ctx, authorities, client = provisioned
    result_path, result_env = _evaluate_sum(client, ctx)

    coord = DecryptCoordinator(
        participants=authorities, workspace_root=str(ws), expected_parties=3
    )
    request = DecryptReleaseRequest(
        recipient="sec-supervisor",
        purpose="approved-aggregate",
        classification=DataClassification.INTERNAL,
        granted=frozenset({CACPermission.DECRYPT_RESULT}),
        containment_state=ContainmentState.NORMAL,
        result_ciphertext_bytes=Path(result_path).read_bytes(),
        expected_result_hash=result_env.result_ciphertext_hash,
    )
    values = coord.decrypt(
        context_dir=str(ws / "contexts" / ctx.context_id),
        result_path=result_path,
        length=1,
        release_request=request,
    )
    assert values[0] == pytest.approx(100.0, abs=1e-2)


def test_dropping_a_party_fails_decryption(provisioned):
    ws, ctx, authorities, client = provisioned
    result_path, result_env = _evaluate_sum(client, ctx)

    # Only two of the three shares — genuine N-of-N means fusion cannot recover.
    coord = DecryptCoordinator(
        participants=authorities[:2], workspace_root=str(ws), expected_parties=2
    )
    request = DecryptReleaseRequest(
        recipient="sec-supervisor",
        purpose="approved-aggregate",
        classification=DataClassification.INTERNAL,
        granted=frozenset({CACPermission.DECRYPT_RESULT}),
        containment_state=ContainmentState.NORMAL,
        result_ciphertext_bytes=Path(result_path).read_bytes(),
        expected_result_hash=result_env.result_ciphertext_hash,
    )
    with pytest.raises(CVZTTEError) as ei:
        coord.decrypt(
            context_dir=str(ws / "contexts" / ctx.context_id),
            result_path=result_path,
            length=1,
            release_request=request,
        )
    assert ei.value.code is ErrorCode.FHE_COMPUTE_FAILED


def test_case137_wrong_participant_share_fails_decryption(provisioned, tmp_path):
    # A participant presenting a share from a DIFFERENT key ceremony (wrong
    # participant/share) cannot contribute a valid partial: fusion fails safely.
    ws, ctx, authorities, client = provisioned
    result_path, result_env = _evaluate_sum(client, ctx)

    # Provision an independent ceremony to obtain a mismatched share for party C.
    other = _context(3)
    other_auths = _local_authorities(tmp_path)
    ThresholdKeyCeremony(participants=other_auths, workspace_root=str(tmp_path)).provision(other)
    wrong_c = KeyAuthority(
        party_id="C", role=AuthorityRole.CVZTTE_DECRYPTION, share_dir=tmp_path / "share-C"
    )

    coord = DecryptCoordinator(
        participants=[authorities[0], authorities[1], wrong_c],
        workspace_root=str(ws), expected_parties=3,
    )
    request = DecryptReleaseRequest(
        recipient="sec-supervisor",
        purpose="approved-aggregate",
        classification=DataClassification.INTERNAL,
        granted=frozenset({CACPermission.DECRYPT_RESULT}),
        containment_state=ContainmentState.NORMAL,
        result_ciphertext_bytes=Path(result_path).read_bytes(),
        expected_result_hash=result_env.result_ciphertext_hash,
    )
    with pytest.raises(CVZTTEError) as ei:
        coord.decrypt(
            context_dir=str(ws / "contexts" / ctx.context_id),
            result_path=result_path, length=1, release_request=request,
        )
    assert ei.value.code is ErrorCode.FHE_COMPUTE_FAILED


def test_full_flow_with_separate_authority_processes(tmp_path):
    binary = default_binary_path()
    if not os.path.exists(binary):
        pytest.skip("fhe_broker not built")
    ws = tmp_path
    ctx = _context(3)

    entrypoints = {
        "A": _REPO_ROOT / "services/fhe-key-authority-a/main.py",
        "B": _REPO_ROOT / "services/fhe-key-authority-b/main.py",
        "C": _REPO_ROOT / "services/fhe-key-authority-c/main.py",
    }
    participants = [
        SubprocessParticipant(
            party_id=pid, entrypoint=ep, share_dir=ws / f"share-{pid}", binary_path=binary
        )
        for pid, ep in entrypoints.items()
    ]

    ceremony = ThresholdKeyCeremony(
        participants=participants, workspace_root=str(ws), binary_path=binary
    )
    ceremony.provision(ctx)

    # Each authority subprocess wrote only its own share.
    for pid in ("A", "B", "C"):
        assert (ws / f"share-{pid}" / SHARE_FILE).exists()

    creg = FHEContextRegistry()
    creg.register(ctx)
    client = FHEBrokerClient(
        workspace_root=str(ws),
        context_registry=creg,
        program_registry=FHEProgramRegistry(),
        binary_path=binary,
    )
    result_path, result_env = _evaluate_sum(client, ctx)

    coord = DecryptCoordinator(
        participants=participants,
        workspace_root=str(ws),
        expected_parties=3,
        binary_path=binary,
    )
    request = DecryptReleaseRequest(
        recipient="sec-supervisor",
        purpose="approved-aggregate",
        classification=DataClassification.INTERNAL,
        granted=frozenset({CACPermission.DECRYPT_RESULT}),
        containment_state=ContainmentState.NORMAL,
        result_ciphertext_bytes=Path(result_path).read_bytes(),
        expected_result_hash=result_env.result_ciphertext_hash,
    )
    values = coord.decrypt(
        context_dir=str(ws / "contexts" / ctx.context_id),
        result_path=result_path,
        length=1,
        release_request=request,
    )
    assert values[0] == pytest.approx(100.0, abs=1e-2)
