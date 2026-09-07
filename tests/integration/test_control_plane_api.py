"""Integration tests for the Control Plane HTTP API and evaluate-execute (§60.29).

Drives the real stdlib HTTP server on a background thread with real ML-DSA
identity, and exercises the full evaluate → mint → mediate path through a real
FileBroker. Confirms plane separation and fail-closed error mapping over HTTP.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.containment.engine import ContainmentEngine
from cvztte.control_plane import (
    AdminAuthorizer,
    AdminPlane,
    AgentPlane,
    ControlPlane,
    DecisionStatus,
)
from cvztte.control_plane.http_api import ControlPlaneAPI, make_server
from cvztte.decision.authority import DecisionTokenAuthority
from cvztte.decision.validator import EpochSource, PresentedTokenStore
from cvztte.identity import KeyState
from cvztte.policy.model import PolicyDecision, RiskTier
from cvztte.policy.opa_input import Grant
from cvztte.request import RequestBuilder
from cvztte.session.model import SessionStore

from cvztte.audit import AuditReceiptSink, HashChainedAuditLog
from enforcement.file_broker import FileBroker, FileRequest

KEY = b"k" * 32
POLICY_HASH = "sha256:" + "0" * 64
ADMIN = "admin_root"


class _FakeOPA:
    def __init__(self, decision: PolicyDecision) -> None:
        self._decision = decision

    def authorize(self, input_doc: dict) -> PolicyDecision:
        return self._decision


def _grant() -> Grant:
    return Grant(
        capabilities={"fs:read", "fs:write"}, resource_scopes={"fs:/"},
        clearance=DataClassification.CONFIDENTIAL,
    )


@pytest.fixture()
def wired(registry, tmp_path):
    registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    source = EpochSource()
    authority = DecisionTokenAuthority(KEY)
    store = PresentedTokenStore()
    sessions = SessionStore()
    containment = ContainmentEngine(epoch_source=source)
    decision = PolicyDecision(allow=True, reason_code="ALLOW_OK", risk_level=1)
    plane = ControlPlane(
        key_registry=registry, session_store=sessions, opa_client=_FakeOPA(decision),
        authority=authority, presented_store=store, containment=containment,
        require_approval_from_tier=RiskTier.L4,
    )
    agent = AgentPlane(plane)
    admin = AdminPlane(
        plane, authorizer=AdminAuthorizer({ADMIN}), key_registry=registry,
        containment=containment,
    )
    return {
        "registry": registry, "builder": RequestBuilder(registry), "plane": plane,
        "agent": agent, "admin": admin, "store": store, "authority": authority,
        "source": source, "tmp_path": tmp_path,
    }


@pytest.fixture()
def server(wired):
    api = ControlPlaneAPI(agent=wired["agent"], admin=wired["admin"], plane=wired["plane"])
    srv = make_server(api, port=0)
    host, port = srv.server_address
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://{host}:{port}", wired
    srv.shutdown()
    thread.join(timeout=5)


def _http(method, url, *, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def _action():
    return AgentAction(
        action_type=ActionType.FILE_READ, target="fs:/data/report.csv", operation="read"
    )


# -- HTTP surface -----------------------------------------------------------


def test_health_live_and_ready_over_http(server):
    base, _ = server
    assert _http("GET", f"{base}/health/live") == (200, {"status": "live"})
    status, body = _http("GET", f"{base}/health/ready")
    assert status == 200 and body["status"] == "ready"


def test_full_evaluate_flow_over_http(server):
    base, wired = server
    status, sess = _http("POST", f"{base}/v3/sessions",
                         body={"agent_id": "agt_alice", "runtime_id": "runtime_1"})
    assert status == 201
    env = wired["builder"].build_and_sign(
        agent_id="agt_alice", runtime_id="runtime_1", session_id=sess["session_id"],
        delegation_id="dlg_1", policy_hash=POLICY_HASH, action=_action(),
    )
    status, result = _http("POST", f"{base}/v3/actions/evaluate", body={
        "envelope": json.loads(env.model_dump_json()),
        "grant": {"capabilities": ["fs:read"], "resource_scopes": ["fs:/data"],
                  "clearance": "CONFIDENTIAL"},
        "audience": "file-broker-01",
    })
    assert status == 200
    assert result["status"] == DecisionStatus.ALLOW.value
    assert result["token_issued"] is True
    # And the decision is fetchable.
    status, fetched = _http("GET", f"{base}/v3/decisions/{result['decision_id']}")
    assert status == 200 and fetched["decision_id"] == result["decision_id"]


def test_admin_route_requires_principal_header(server):
    base, _ = server
    # No X-CVZTTE-Admin header => fail closed (403 ENFORCEMENT_DENIED).
    status, body = _http("POST", f"{base}/v3/agents/x%7Cy%7Cz/quarantine",
                         body={"agent_id": "agt_alice", "runtime_id": "runtime_1"})
    assert status == 403
    assert body["error_code"] == "ENFORCEMENT_DENIED"


def test_admin_route_with_principal_quarantines(server):
    base, _ = server
    subject = "agt_alice|runtime_1|ses_x"
    status, body = _http(
        "POST", f"{base}/v3/agents/{subject}/quarantine",
        body={"agent_id": "agt_alice", "runtime_id": "runtime_1"},
        headers={"X-CVZTTE-Admin": ADMIN},
    )
    assert status == 200
    status, cont = _http("GET", f"{base}/v3/agents/{subject}/containment")
    assert status == 200 and cont["state"] == "QUARANTINED"


def test_unknown_route_and_bad_body_fail_closed(server):
    base, _ = server
    status, body = _http("GET", f"{base}/v3/does-not-exist")
    assert status == 404 and body["error_code"] == "SCHEMA_INVALID"
    # Malformed JSON body.
    req = urllib.request.Request(
        f"{base}/v3/sessions", data=b"{not json", method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        raise AssertionError("expected HTTPError")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        assert json.loads(exc.read().decode())["error_code"] == "SCHEMA_INVALID"


def test_missing_field_is_schema_error(server):
    base, _ = server
    status, body = _http("POST", f"{base}/v3/sessions", body={"agent_id": "agt_alice"})
    assert status == 400 and body["error_code"] == "SCHEMA_INVALID"


# -- evaluate_execute through a real FileBroker -----------------------------


def test_evaluate_execute_mediates_real_file_broker(wired):
    tmp = wired["tmp_path"]
    # The broker re-validates the presented token independently: a validator over
    # the same MAC key, the shared EpochSource, and the plane's presented store.
    from cvztte.decision.validator import DecisionTokenValidator

    validator = DecisionTokenValidator(
        mac_key=KEY, epoch_source=wired["source"], store=wired["store"]
    )
    broker = FileBroker(str(tmp), validator, AuditReceiptSink(HashChainedAuditLog()))

    sess = wired["plane"].create_session(agent_id="agt_alice", runtime_id="runtime_1")
    file_req = FileRequest("out.txt", "write", b"hello control plane")
    # The canonical action the broker will observe drives the signed envelope.
    binding = AdapterBinding(agent_id="agt_alice", runtime_id="runtime_1",
                             session_id=sess.session_id, delegation_id="dlg_1")
    action = broker.observe(file_req, binding)
    env = wired["builder"].build_and_sign(
        agent_id="agt_alice", runtime_id="runtime_1", session_id=sess.session_id,
        delegation_id="dlg_1", policy_hash=POLICY_HASH, action=action,
    )
    outcome = wired["plane"].evaluate_execute(
        env, grant=_grant(), broker=broker, broker_request=file_req
    )
    assert outcome.evaluation.status is DecisionStatus.ALLOW
    assert outcome.outcome is not None
    assert outcome.outcome.receipt.outcome == "EXECUTED"
    assert (tmp / "out.txt").read_bytes() == b"hello control plane"
