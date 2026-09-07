"""Native-crypto benchmarks: OpenFHE + gnark (spec §52, §60.32).

Real compiled binaries, no mocks. Skipped when a binary is absent so the suite
stays green on a bare checkout; marked ``slow`` because CKKS key generation and a
Groth16 trusted setup are genuinely expensive. Observed medians only — never a
fabricated throughput figure (§52).
"""

from __future__ import annotations

import os
import shutil
import subprocess
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

pytestmark = pytest.mark.slow

_REPO = Path(__file__).resolve().parents[2]
_ALLOWED = [ProgramId.SUM_V1, ProgramId.AVERAGE_V1]


# --- OpenFHE CKKS ------------------------------------------------------------


@pytest.fixture(scope="module")
def fhe(tmp_path_factory):
    binary = default_binary_path()
    if not os.path.exists(binary):
        pytest.skip(f"fhe_broker not built at {binary}")
    ws = tmp_path_factory.mktemp("perf_cac")
    creg, preg = FHEContextRegistry(), FHEProgramRegistry()
    client = FHEBrokerClient(workspace_root=str(ws), context_registry=creg,
                             program_registry=preg)
    ctx = FHEContext(
        context_id="ckks-perf-v1", openfhe_version="1.5.1",
        security_profile=SecurityProfile.SECURE_LAB, multiplicative_depth=2,
        scaling_mod_size=50, batch_size=8, key_epoch=1,
    )
    return client, ctx


def _encrypt(client, ctx, values):
    return client.encrypt(
        context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
        values=values, dataset_id="ds1", owner="data_owner",
        classification=DataClassification.CONFIDENTIAL, allowed_programs=_ALLOWED,
    )


def test_bench_openfhe(fhe, recorder):
    client, ctx = fhe

    recorder.measure("openfhe-context+key-setup",
                     lambda: client.provision_context(ctx), iters=2, warmup=0, max_ms=60000.0)

    vals = [10.0, 20.0, 30.0, 40.0]
    recorder.measure("openfhe-encrypt", lambda: _encrypt(client, ctx, vals),
                     iters=5, warmup=1, max_ms=30000.0)

    path, env = _encrypt(client, ctx, vals)
    ct_bytes = Path(path).stat().st_size
    print(f"\nobserved ciphertext size: {ct_bytes} bytes")
    assert ct_bytes > 0

    def sum_eval():
        client.evaluate(context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
                        program_id=ProgramId.SUM_V1, inputs=[(path, env)])

    def avg_eval():
        client.evaluate(context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
                        program_id=ProgramId.AVERAGE_V1, inputs=[(path, env)], count=4)

    recorder.measure("openfhe-SUM", sum_eval, iters=5, warmup=1, max_ms=30000.0)
    recorder.measure("openfhe-AVERAGE", avg_eval, iters=5, warmup=1, max_ms=30000.0)

    rp, _ = client.evaluate(context_id=ctx.context_id, expected_context_hash=ctx.context_hash(),
                            program_id=ProgramId.SUM_V1, inputs=[(path, env)])
    recorder.measure("openfhe-decrypt",
                     lambda: client.decrypt(context_id=ctx.context_id, ciphertext_path=rp, length=1),
                     iters=5, warmup=1, max_ms=30000.0)


# --- gnark Groth16 -----------------------------------------------------------


@pytest.fixture(scope="module")
def zk(tmp_path_factory):
    from cvztte.zkauthz import ZKAuthzClient, ZKRegistry

    bin_path = _REPO / "services" / "zk-authz" / "bin" / "zk-authz"
    binary = str(bin_path) if bin_path.is_file() else shutil.which("zk-authz")
    if not binary:
        pytest.skip("zk-authz binary not built")
    d = tmp_path_factory.mktemp("perf_zk")
    proc = subprocess.run([binary, "setup", str(d)], capture_output=True, timeout=600)
    if proc.returncode != 0:
        pytest.skip(f"zk setup failed: {proc.stderr.decode()[:200]}")
    return ZKAuthzClient(ZKRegistry(str(d)), binary=binary)


def test_bench_gnark(zk, recorder):
    import hashlib

    from cvztte.zkauthz import Assignment, capability_field, sha256_to_field_pair

    def sc(s):
        return "sha256:" + hashlib.sha256(s.encode()).hexdigest()

    agent_hi, agent_lo = sha256_to_field_pair(sc("agt_alice"))
    scope_hi, scope_lo = sha256_to_field_pair(sc("scope:db/customers"))
    pol_hi, pol_lo = sha256_to_field_pair(sc("policy-v3"))
    act_hi, act_lo = sha256_to_field_pair(sc("action-A"))
    cap = capability_field("db:read")
    issued = zk.issue({
        "agent_hi": agent_hi, "agent_lo": agent_lo, "capability": cap, "clearance": 3,
        "expiry_epoch": 2000, "scope_hi": scope_hi, "scope_lo": scope_lo,
        "policy_hi": pol_hi, "policy_lo": pol_lo, "salt": 1234567890,
        "action_hi": act_hi, "action_lo": act_lo, "epoch": 1000, "circuit_ver": 3,
    })
    a = Assignment(
        agent_hi=agent_hi, agent_lo=agent_lo, credential_commitment=int(issued["credential_commitment"]),
        required_capability=cap, required_clearance=2, current_epoch=1000,
        action_hi=act_hi, action_lo=act_lo, policy_hi=pol_hi, policy_lo=pol_lo,
        scope_hi=scope_hi, scope_lo=scope_lo, circuit_ver=3,
        session_binding=int(issued["session_binding"]), capability=cap, clearance=3,
        expiry_epoch=2000, salt=1234567890,
    )
    proof, pub = zk.prove(a)
    recorder.measure("gnark-prove", lambda: zk.prove(a), iters=5, warmup=1, max_ms=30000.0)
    recorder.measure("gnark-verify", lambda: zk.verify(proof, pub), iters=10, warmup=1,
                     max_ms=10000.0)
