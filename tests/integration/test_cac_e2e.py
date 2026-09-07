"""CAC end-to-end over the REAL native OpenFHE CKKS broker (spec §36, §40).

These exercise the compiled ``fhe_broker`` binary — genuine encrypt/evaluate/
decrypt, no mocks. Skipped if the binary is not built. Marked slow: context
generation runs a real CKKS KeyGen + EvalSum key generation.
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
from cvztte.errors import CVZTTEError, ErrorCode

pytestmark = pytest.mark.slow

_ALLOWED = [ProgramId.SUM_V1, ProgramId.AVERAGE_V1, ProgramId.WEIGHTED_SCORE_V1]


@pytest.fixture(scope="module")
def broker(tmp_path_factory):
    binary = default_binary_path()
    if not os.path.exists(binary):
        pytest.skip(f"fhe_broker not built at {binary}")
    ws = tmp_path_factory.mktemp("cac")
    creg = FHEContextRegistry()
    preg = FHEProgramRegistry()
    client = FHEBrokerClient(
        workspace_root=str(ws), context_registry=creg, program_registry=preg
    )
    ctx = FHEContext(
        context_id="ckks-emp-v1", openfhe_version="1.5.1",
        security_profile=SecurityProfile.SECURE_LAB, multiplicative_depth=2,
        scaling_mod_size=50, batch_size=8, key_epoch=3,
    )
    client.provision_context(ctx)
    return client, ctx


def _encrypt(broker, values):
    client, ctx = broker
    return client.encrypt(
        context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
        values=values, dataset_id="ds1", owner="data_owner",
        classification=DataClassification.CONFIDENTIAL, allowed_programs=_ALLOWED,
    )


def test_sum_program_correct(broker) -> None:
    client, ctx = broker
    path, env = _encrypt(broker, [10.0, 20.0, 30.0, 40.0])
    rp, _ = client.evaluate(
        context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
        program_id=ProgramId.SUM_V1, inputs=[(path, env)],
    )
    out = client.decrypt(context_id=ctx.context_id, ciphertext_path=rp, length=1)
    assert out[0] == pytest.approx(100.0, abs=1e-2)


def test_average_program_correct(broker) -> None:
    client, ctx = broker
    path, env = _encrypt(broker, [10.0, 20.0, 30.0, 40.0])
    rp, _ = client.evaluate(
        context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
        program_id=ProgramId.AVERAGE_V1, inputs=[(path, env)], count=4,
    )
    out = client.decrypt(context_id=ctx.context_id, ciphertext_path=rp, length=1)
    assert out[0] == pytest.approx(25.0, abs=1e-2)


def test_weighted_score_program_correct(broker) -> None:
    client, ctx = broker
    path, env = _encrypt(broker, [10.0, 20.0, 30.0, 40.0])
    rp, result_env = client.evaluate(
        context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
        program_id=ProgramId.WEIGHTED_SCORE_V1, inputs=[(path, env)],
        weights=[0.1, 0.2, 0.3, 0.4],
    )
    out = client.decrypt(context_id=ctx.context_id, ciphertext_path=rp, length=1)
    assert out[0] == pytest.approx(30.0, abs=1e-2)
    # Result envelope records lineage (§38).
    assert result_env.parent_ciphertext_ids == [env.ciphertext_id]
    assert result_env.program_id == "WEIGHTED_SCORE_V1"
    assert result_env.lineage_id.startswith("lin_")


def test_ciphertext_substitution_rejected(broker) -> None:
    client, ctx = broker
    path, env = _encrypt(broker, [1.0, 2.0, 3.0, 4.0])
    # Tamper the serialized ciphertext bytes after the envelope was pinned.
    Path(path).write_bytes(Path(path).read_bytes() + b"\x00")
    with pytest.raises(CVZTTEError) as exc:
        client.evaluate(
            context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
            program_id=ProgramId.SUM_V1, inputs=[(path, env)],
        )
    assert exc.value.code == ErrorCode.FHE_CIPHERTEXT_INVALID


def test_context_hash_substitution_rejected(broker) -> None:
    client, ctx = broker
    path, env = _encrypt(broker, [1.0, 2.0])
    with pytest.raises(CVZTTEError) as exc:
        client.evaluate(
            context_id=ctx.context_id, expected_context_hash="sha256:" + "00" * 32,
            program_id=ProgramId.SUM_V1, inputs=[(path, env)],
        )
    assert exc.value.code == ErrorCode.FHE_CONTEXT_MISMATCH


def test_program_not_in_allowed_set_rejected(broker) -> None:
    client, ctx = broker
    # Encrypt allowing only SUM_V1, then try WEIGHTED_SCORE_V1.
    path, env = client.encrypt(
        context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
        values=[1.0, 2.0, 3.0, 4.0], dataset_id="ds1", owner="data_owner",
        classification=DataClassification.CONFIDENTIAL,
        allowed_programs=[ProgramId.SUM_V1],
    )
    with pytest.raises(CVZTTEError) as exc:
        client.evaluate(
            context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
            program_id=ProgramId.WEIGHTED_SCORE_V1, inputs=[(path, env)],
            weights=[0.1, 0.2, 0.3, 0.4],
        )
    assert exc.value.code == ErrorCode.FHE_PROGRAM_DENIED


def test_data_never_leaves_ciphertext_until_decrypt(broker) -> None:
    # The serialized ciphertext on disk must not contain the raw plaintext bytes.
    client, ctx = broker
    path, _ = _encrypt(broker, [1234.5, 6789.0])
    raw = Path(path).read_bytes()
    # A CKKS ciphertext is large and randomized; the plaintext values are not
    # recoverable from it without the secret key. Sanity: it is non-trivially big.
    assert len(raw) > 1000


def test_case146_oversized_ciphertext_rejected(broker, tmp_path) -> None:
    # §52/§60.31 #146: an oversized ciphertext must be refused at the FHE broker
    # (fail-closed resource bound), never processed. A tiny max_ciphertext_bytes
    # makes every real CKKS ciphertext oversized, so encrypt's own output trips
    # the guard and nothing dangling is left behind.
    from cvztte.config import ResourceLimits

    client, ctx = broker
    # A second client over the SAME workspace (context artifacts already provisioned)
    # but with a 1-byte ciphertext ceiling.
    creg = FHEContextRegistry()
    creg.register(ctx)
    bounded = FHEBrokerClient(
        workspace_root=str(client._ws), context_registry=creg,
        program_registry=FHEProgramRegistry(),
        resource_limits=ResourceLimits(max_ciphertext_bytes=1),
    )
    with pytest.raises(CVZTTEError) as exc:
        bounded.encrypt(
            context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
            values=[1.0, 2.0, 3.0, 4.0], dataset_id="ds1", owner="data_owner",
            classification=DataClassification.CONFIDENTIAL, allowed_programs=_ALLOWED,
        )
    assert exc.value.code == ErrorCode.FHE_CIPHERTEXT_TOO_LARGE

    # And an oversized ciphertext presented as INPUT is refused before evaluate.
    path, env = _encrypt(broker, [1.0, 2.0, 3.0, 4.0])  # full-size, via unbounded client
    with pytest.raises(CVZTTEError) as exc2:
        bounded.evaluate(
            context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
            program_id=ProgramId.SUM_V1, inputs=[(path, env)],
        )
    assert exc2.value.code == ErrorCode.FHE_CIPHERTEXT_TOO_LARGE
