"""End-to-end path through the integrated stack (§51 E2E requirement).

One complete path exercises real ML-DSA identity, the real DecisionTokenAuthority
+ validator over a shared EpochSource, the real ContainmentEngine, and the real
FileBroker enforcement point with a hash-chained audit log — all behind the
Phase 17 ControlPlane. The real-crypto CAC E2E path (genuine OpenFHE + configured
threshold decryption) lives in tests/integration/test_cac_e2e.py and
tests/integration/test_threshold_e2e.py; the real OPA / gnark / EZKL paths live in
their guarded integration tests (skipped when the native binaries are absent).
"""

from __future__ import annotations

import pytest

from cvztte.control_plane import DecisionStatus
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.file_broker import FileRequest

from lab import AGENT, RUNTIME, AdversarialLab, make_allow_decision


@pytest.fixture()
def stack(registry, tmp_path):
    return AdversarialLab(registry, tmp_path, decision=make_allow_decision())


def test_e2e_allow_path_executes_and_audits(stack):
    # 1. open a session for a registered agent.
    sess = stack.open_session()
    binding = stack.binding(sess.session_id)

    # 2. the broker's canonical view of the operation drives the signed request.
    req = FileRequest("report.txt", "write", b"quarterly numbers")
    action = stack.observe(req, binding)
    env = stack.sign(sess.session_id, action=action)

    # 3. evaluate through the full pipeline -> ALLOW + minted token.
    result = stack.agent.evaluate(env, grant=stack.grant(), audience=stack.broker.audience)
    assert result.status is DecisionStatus.ALLOW
    assert result.token is not None

    # 4. the enforcement broker independently re-validates and executes.
    outcome = stack.broker.mediate(req, binding)
    assert outcome.receipt.outcome == "EXECUTED"
    assert (stack.workspace / "report.txt").read_bytes() == b"quarterly numbers"

    # 5. the hash-chained audit log verifies end to end.
    assert stack.broker._receipts._log.verify() is True


def test_e2e_deny_path_quarantine_blocks_everything(stack):
    sess = stack.open_session()
    subject = f"{AGENT}|{RUNTIME}|{sess.session_id}"

    # Contain the subject, then attempt a fresh consequential action.
    stack.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)
    env = stack.sign(sess.session_id, action=stack.file_action(operation="write",
                                                               target="fs:/blocked.txt"))
    with pytest.raises(CVZTTEError) as exc:
        stack.agent.evaluate(env, grant=stack.grant(), audience=stack.broker.audience)
    assert exc.value.code is ErrorCode.CONTAINMENT_QUARANTINED

    # And nothing was executed anywhere (protected side-effect count = 0).
    stack.assert_no_side_effects()
