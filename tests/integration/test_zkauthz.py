"""Integration + substitution tests for gnark ZK authorization (spec §14, §60.5).

Real artifacts and a real prover/verifier — no mocks (spec §0 rule 10):

* Substitution: the Python bridge MUST equal the Go ``encode`` output on shared
  vectors (the SHA-256 -> BN254 bridge is identical on both sides).
* End-to-end: setup -> issue -> prove -> verify round trip through the real
  Groth16 service.
* Action binding (§4.11): a proof for one action does not verify against another
  action's public inputs.
* Fail-closed: a missing binary maps to SECURITY_DEPENDENCY_UNAVAILABLE.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.zkauthz import (
    Assignment,
    ZKAuthzClient,
    ZKRegistry,
    capability_field,
    sha256_to_field_pair,
)

_REPO = Path(__file__).resolve().parents[2]
_BIN = _REPO / "services" / "zk-authz" / "bin" / "zk-authz"


def _require_binary() -> str:
    if _BIN.is_file():
        return str(_BIN)
    found = shutil.which("zk-authz")
    if found:
        return found
    pytest.skip("zk-authz binary not built (run: go build -o bin/zk-authz ./cmd/zk-authz)")


def _sha_commit(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode()).hexdigest()


@pytest.fixture(scope="session")
def zk_binary() -> str:
    return _require_binary()


@pytest.fixture(scope="session")
def artifact_dir(zk_binary: str, tmp_path_factory: pytest.TempPathFactory) -> str:
    d = tmp_path_factory.mktemp("zk_artifacts")
    proc = subprocess.run(
        [zk_binary, "setup", str(d)], capture_output=True, timeout=300
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return str(d)


@pytest.fixture()
def client(artifact_dir: str, zk_binary: str) -> ZKAuthzClient:
    return ZKAuthzClient(ZKRegistry(artifact_dir), binary=zk_binary)


def _go_encode(binary: str, obj: dict) -> dict:
    proc = subprocess.run(
        [binary, "encode"], input=json.dumps(obj).encode(), capture_output=True
    )
    assert proc.returncode == 0, proc.stderr.decode()
    return json.loads(proc.stdout.decode().strip().splitlines()[-1])


# --- substitution: Python bridge == Go encode --------------------------------


@pytest.mark.parametrize(
    "value",
    ["agt_alice", "scope:db/customers", "policy-v3", "", "action:FHE_EVAL/x"],
)
def test_bridge_sha256_matches_go(zk_binary: str, value: str) -> None:
    commit = _sha_commit(value)
    py_hi, py_lo = sha256_to_field_pair(commit)
    go = _go_encode(zk_binary, {"sha256": commit})
    assert str(py_hi) == go["hi"]
    assert str(py_lo) == go["lo"]


@pytest.mark.parametrize("cap", ["db:read", "db:write", "shell:exec", "net:external"])
def test_bridge_capability_matches_go(zk_binary: str, cap: str) -> None:
    py = capability_field(cap)
    go = _go_encode(zk_binary, {"capability": cap})
    assert str(py) == go["cap_field"]


# --- registry pinning --------------------------------------------------------


def test_registry_loads_and_pins(artifact_dir: str) -> None:
    reg = ZKRegistry(artifact_dir)
    assert reg.circuit_version == 3
    assert reg.verification_key_hash.startswith("sha256:")


def test_registry_rejects_tampered_vk(artifact_dir: str, tmp_path: Path) -> None:
    # Copy artifacts, corrupt the VK, and confirm the pin check fails closed.
    dst = tmp_path / "tampered"
    dst.mkdir()
    for name in ("manifest.json", "vk.bin", "cs.bin", "pk.bin"):
        shutil.copy(Path(artifact_dir) / name, dst / name)
    vk = dst / "vk.bin"
    data = bytearray(vk.read_bytes())
    data[0] ^= 0xFF
    vk.write_bytes(bytes(data))
    with pytest.raises(CVZTTEError) as exc:
        ZKRegistry(dst)
    assert exc.value.code == ErrorCode.GNARK_ARTIFACT_UNAPPROVED


# --- end-to-end prove / verify ----------------------------------------------


def _assignment(
    client: ZKAuthzClient,
    action: str,
    *,
    policy: str = "policy-v3",
    clearance: int = 3,
    required_clearance: int = 2,
    expiry_epoch: int = 2000,
    current_epoch: int = 1000,
    forge_commitment: bool = False,
) -> Assignment:
    agent_hi, agent_lo = sha256_to_field_pair(_sha_commit("agt_alice"))
    scope_hi, scope_lo = sha256_to_field_pair(_sha_commit("scope:db/customers"))
    pol_hi, pol_lo = sha256_to_field_pair(_sha_commit(policy))
    act_hi, act_lo = sha256_to_field_pair(_sha_commit(action))
    cap = capability_field("db:read")

    issued = client.issue(
        {
            "agent_hi": agent_hi,
            "agent_lo": agent_lo,
            "capability": cap,
            "clearance": clearance,
            "expiry_epoch": expiry_epoch,
            "scope_hi": scope_hi,
            "scope_lo": scope_lo,
            "policy_hi": pol_hi,
            "policy_lo": pol_lo,
            "salt": 1234567890,
            "action_hi": act_hi,
            "action_lo": act_lo,
            "epoch": current_epoch,
            "circuit_ver": 3,
        }
    )
    commitment = int(issued["credential_commitment"])
    if forge_commitment:
        # A credential not produced by the trusted issuer: forge the commitment.
        commitment ^= 0x1
    return Assignment(
        agent_hi=agent_hi,
        agent_lo=agent_lo,
        credential_commitment=commitment,
        required_capability=cap,
        required_clearance=required_clearance,
        current_epoch=current_epoch,
        action_hi=act_hi,
        action_lo=act_lo,
        policy_hi=pol_hi,
        policy_lo=pol_lo,
        scope_hi=scope_hi,
        scope_lo=scope_lo,
        circuit_ver=3,
        session_binding=int(issued["session_binding"]),
        capability=cap,
        clearance=clearance,
        expiry_epoch=expiry_epoch,
        salt=1234567890,
    )


def test_prove_verify_roundtrip(client: ZKAuthzClient) -> None:
    a = _assignment(client, "action-A")
    proof, pub = client.prove(a)
    assert client.verify(proof, pub) is True
    client.authorize(proof, pub)  # does not raise


def test_action_binding_rejects_cross_action(client: ZKAuthzClient) -> None:
    a = _assignment(client, "action-A")
    proof_a, _ = client.prove(a)
    b = _assignment(client, "action-B")
    _, pub_b = client.prove(b)
    # Action-A proof against Action-B public inputs must not verify (§4.11).
    assert client.verify(proof_a, pub_b) is False
    with pytest.raises(CVZTTEError) as exc:
        client.authorize(proof_a, pub_b)
    assert exc.value.code == ErrorCode.GNARK_PROOF_INVALID


# --- adversarial negatives (§60.31 #22, #23, #25, #26, #27) ------------------


def test_case22_fake_private_clearance_cannot_prove(client: ZKAuthzClient) -> None:
    # The agent holds clearance 1 but the action requires 2: the witness does not
    # satisfy the clearance constraint, so no proof can be produced (fail-closed).
    a = _assignment(client, "action-A", clearance=1, required_clearance=2)
    with pytest.raises(CVZTTEError):
        client.prove(a)


def test_case23_untrusted_issuer_credential_cannot_prove(client: ZKAuthzClient) -> None:
    # A credential commitment not produced by the trusted issuer does not match
    # the hash of the private witness, so proving fails (fail-closed).
    a = _assignment(client, "action-A", forge_commitment=True)
    with pytest.raises(CVZTTEError):
        client.prove(a)


def test_case25_proof_bound_to_policy_rejected_under_other_policy(client: ZKAuthzClient) -> None:
    a = _assignment(client, "action-A", policy="policy-v3")
    proof_a, _ = client.prove(a)
    b = _assignment(client, "action-A", policy="policy-v4")
    _, pub_b = client.prove(b)
    # Proof bound to policy-v3 must not verify against policy-v4 public inputs.
    assert client.verify(proof_a, pub_b) is False
    with pytest.raises(CVZTTEError) as exc:
        client.authorize(proof_a, pub_b)
    assert exc.value.code == ErrorCode.GNARK_PROOF_INVALID


def test_case26_expired_credential_cannot_prove(client: ZKAuthzClient) -> None:
    # current_epoch is past the credential's expiry_epoch: the expiry constraint
    # is violated and no proof can be produced (fail-closed).
    a = _assignment(client, "action-A", expiry_epoch=2000, current_epoch=3000)
    with pytest.raises(CVZTTEError):
        client.prove(a)


def test_case27_mutated_proof_does_not_verify(client: ZKAuthzClient) -> None:
    a = _assignment(client, "action-A")
    proof, pub = client.prove(a)
    # Flip a character in the middle of the base64 proof transcript.
    mid = len(proof) // 2
    swap = "B" if proof[mid] != "B" else "C"
    mutated = proof[:mid] + swap + proof[mid + 1:]
    with pytest.raises(CVZTTEError) as exc:
        client.authorize(mutated, pub)
    assert exc.value.code in (
        ErrorCode.GNARK_PROOF_INVALID, ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE
    )


# --- fail closed -------------------------------------------------------------


def test_missing_binary_fails_closed(artifact_dir: str) -> None:
    reg = ZKRegistry(artifact_dir)
    client = ZKAuthzClient(reg, binary="/nonexistent/zk-authz-xyz")
    with pytest.raises(CVZTTEError) as exc:
        client.verify("AAAA", "AAAA")
    assert exc.value.code == ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE
