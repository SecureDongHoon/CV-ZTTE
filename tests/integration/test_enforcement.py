"""Enforcement Fabric tests (spec §16-§23, §60.12).

The Decision Token validator is injected; Phase 8 provides the real cryptographic
one. Here a deterministic reference validator drives the common flow so the
security-relevant broker behavior (canonicalization, independent hash recompute,
exact-match binding, traversal/symlink defense, use-without-disclosure, DLP,
command allowlist, anti-laundering) is exercised end to end. Fail-closed paths
are asserted directly.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from datetime import datetime, timedelta, timezone

from cvztte.action.model import AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.delegation.model import DelegationRegistry, PolicyAuthority, AuthorityKind
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import (
    AuthorizedDecision,
    DecisionEffect,
    InMemoryReceiptSink,
)
from enforcement.egress_proxy import EgressConfig, EgressProxy, EgressRequest
from enforcement.file_broker import FileBroker, FileRequest
from enforcement.mcp_gateway import MCPGateway, MCPRequest, ProtectedServer
from enforcement.message_broker import MessageBroker, MessageConfig, MessageRequest
from enforcement.output_proxy import OutputProxy, OutputRequest
from enforcement.process_broker import ProcessBroker, ProcessConfig, ProcessRequest
from enforcement.secret_broker import SecretBroker, SecretRequest


class RefValidator:
    """Deterministic reference DecisionValidator (test-only stand-in for Phase 8).

    Produces an ALLOW decision whose constraints exactly match the observed
    action. Variants force denial or a constraint mismatch.
    """

    def __init__(self, *, effect: DecisionEffect = DecisionEffect.ALLOW,
                 target_override: str | None = None, deny: bool = False) -> None:
        self._effect = effect
        self._target_override = target_override
        self._deny = deny
        self._n = 0

    def authorize(self, *, action: AgentAction, action_hash: str,
                  binding: AdapterBinding, audience: str) -> AuthorizedDecision:
        if self._deny:
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_INVALID, "denied by policy")
        self._n += 1
        return AuthorizedDecision(
            decision_id=f"dec_{self._n}",
            effect=self._effect,
            action_hash=action_hash,
            target_constraint=self._target_override or action.target,
            operation_constraint=action.operation,
            payload_hash=action.payload_ref.hash if action.payload_ref else None,
            risk_level=1,
            audience=audience,
        )


BINDING = AdapterBinding(agent_id="agt_alice", runtime_id="runtime_1", session_id="ses_1")


def _sink():
    return InMemoryReceiptSink()


# --- File Broker -------------------------------------------------------------


def test_file_broker_write_read_roundtrip(tmp_path: Path) -> None:
    sink = _sink()
    fb = FileBroker(str(tmp_path), RefValidator(), sink)
    fb.mediate(FileRequest("a.txt", "write", b"hello"), BINDING)
    out = fb.mediate(FileRequest("a.txt", "read"), BINDING)
    assert (tmp_path / "a.txt").read_bytes() == b"hello"
    assert out.result.result_hash and out.result.result_hash.startswith("sha256:")
    assert sink.receipts[-1].outcome == "EXECUTED"


def test_file_broker_blocks_traversal(tmp_path: Path) -> None:
    fb = FileBroker(str(tmp_path), RefValidator(), _sink())
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(FileRequest("../../etc/passwd", "read"), BINDING)
    assert exc.value.code in (ErrorCode.FILE_PATH_ESCAPE, ErrorCode.FINAL_ACTION_BINDING_FAILED)


def test_file_broker_blocks_absolute(tmp_path: Path) -> None:
    fb = FileBroker(str(tmp_path), RefValidator(), _sink())
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(FileRequest("/etc/passwd", "read"), BINDING)
    assert exc.value.code == ErrorCode.FILE_PATH_ESCAPE


def test_file_broker_blocks_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    secret = tmp_path / "outside.txt"
    secret.write_text("TOPSECRET")
    os.symlink(str(secret), str(root / "link.txt"))
    fb = FileBroker(str(root), RefValidator(), _sink())
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(FileRequest("link.txt", "read"), BINDING)
    assert exc.value.code == ErrorCode.FILE_PATH_ESCAPE


def test_file_broker_denied_token_no_write(tmp_path: Path) -> None:
    sink = _sink()
    fb = FileBroker(str(tmp_path), RefValidator(deny=True), sink)
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(FileRequest("x.txt", "write", b"data"), BINDING)
    assert exc.value.code == ErrorCode.DECISION_TOKEN_INVALID
    assert not (tmp_path / "x.txt").exists()
    assert sink.receipts[-1].outcome == "DENIED"


def test_file_broker_exact_match_mismatch(tmp_path: Path) -> None:
    # Validator authorizes a DIFFERENT target than observed (§4.11 boundary check).
    fb = FileBroker(str(tmp_path), RefValidator(target_override="other.txt"), _sink())
    with pytest.raises(CVZTTEError) as exc:
        fb.mediate(FileRequest("x.txt", "write", b"data"), BINDING)
    assert exc.value.code == ErrorCode.FINAL_ACTION_BINDING_FAILED


# --- Egress Proxy ------------------------------------------------------------


def _egress(cfg: EgressConfig) -> EgressProxy:
    return EgressProxy(cfg, RefValidator(), _sink())


def test_egress_external_needs_allowlist() -> None:
    proxy = _egress(EgressConfig(allowed_domains=frozenset()))
    with pytest.raises(CVZTTEError) as exc:
        proxy.mediate(EgressRequest("https://evil.example/x"), BINDING)
    assert exc.value.code == ErrorCode.EGRESS_DENIED


def test_egress_allowlisted_ok() -> None:
    proxy = _egress(EgressConfig(allowed_domains=frozenset({"api.ok.example"})))
    out = proxy.mediate(EgressRequest("https://api.ok.example/v1"), BINDING)
    assert out.receipt.outcome == "EXECUTED"


def test_egress_byte_limit() -> None:
    proxy = _egress(EgressConfig(allowed_domains=frozenset({"api.ok.example"}), max_bytes=4))
    with pytest.raises(CVZTTEError) as exc:
        proxy.mediate(EgressRequest("https://api.ok.example/", method="POST", body=b"toolong"), BINDING)
    assert exc.value.code == ErrorCode.EGRESS_DENIED


def test_egress_secret_external_denied() -> None:
    proxy = _egress(EgressConfig(allowed_domains=frozenset({"api.ok.example"})))
    with pytest.raises(CVZTTEError) as exc:
        proxy.mediate(
            EgressRequest("https://api.ok.example/", data_classification=DataClassification.SECRET),
            BINDING,
        )
    assert exc.value.code == ErrorCode.EGRESS_DENIED


def test_egress_internal_allowed_without_allowlist() -> None:
    proxy = _egress(EgressConfig())
    out = proxy.mediate(EgressRequest("http://10.0.0.5/health"), BINDING)
    assert out.receipt.outcome == "EXECUTED"


# --- Secret Broker (use-without-disclosure) ----------------------------------


def test_secret_use_without_disclosure() -> None:
    sink = _sink()
    # Downstream op uses the secret but returns only a non-secret result.
    def db_query(secret: str, params: dict) -> dict:
        assert secret == "s3cr3t-pw"  # used internally
        return {"rows": params.get("limit", 0), "ok": True}

    broker = SecretBroker(
        RefValidator(), sink,
        secrets={"db_password": "s3cr3t-pw"},
        operations={"db_query": db_query},
    )
    out = broker.mediate(SecretRequest("db_password", "db_query", {"limit": 3}), BINDING)
    assert out.result.detail["result"] == {"rows": 3, "ok": True}
    # Secret never appears in the receipt.
    assert "s3cr3t-pw" not in out.receipt.model_dump_json()


def test_secret_raw_disclosure_denied() -> None:
    broker = SecretBroker(
        RefValidator(), _sink(), secrets={"h": "v"}, operations={},
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(SecretRequest("h", "reveal"), BINDING)
    assert exc.value.code == ErrorCode.SECRET_DISCLOSURE_FORBIDDEN


def test_secret_leak_refused() -> None:
    def leaky(secret: str, params: dict) -> dict:
        return {"echo": secret}  # tries to leak

    broker = SecretBroker(
        RefValidator(), _sink(), secrets={"h": "topsecret"}, operations={"op": leaky},
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(SecretRequest("h", "op"), BINDING)
    assert exc.value.code == ErrorCode.SECRET_DISCLOSURE_FORBIDDEN


def test_secret_unknown_handle() -> None:
    broker = SecretBroker(RefValidator(), _sink(), secrets={}, operations={"op": lambda s, p: {}})
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(SecretRequest("nope", "op"), BINDING)
    assert exc.value.code == ErrorCode.SECRET_UNKNOWN


# --- Output Proxy ------------------------------------------------------------


def test_output_denies_credentials() -> None:
    proxy = OutputProxy(RefValidator(), _sink())
    with pytest.raises(CVZTTEError) as exc:
        proxy.mediate(OutputRequest("here is my key AKIAABCDEFGHIJKLMNOP"), BINDING)
    assert exc.value.code == ErrorCode.OUTPUT_DENIED


def test_output_redacts_pii() -> None:
    proxy = OutputProxy(RefValidator(), _sink())
    out = proxy.mediate(OutputRequest("contact me at alice@example.com please"), BINDING)
    assert out.result.detail["effect"] == "REDACT"
    assert "alice@example.com" not in out.result.detail["content"]


def test_output_allows_clean() -> None:
    proxy = OutputProxy(RefValidator(), _sink())
    out = proxy.mediate(OutputRequest("the build succeeded"), BINDING)
    assert out.result.detail["effect"] == "ALLOW"


# --- Process Broker ----------------------------------------------------------


def test_process_allowed_command_runs() -> None:
    broker = ProcessBroker(
        ProcessConfig(allowed_commands=frozenset({"echo"})), RefValidator(), _sink()
    )
    out = broker.mediate(ProcessRequest(["echo", "hello"]), BINDING)
    assert "hello" in out.result.detail["stdout"]
    assert out.result.detail["returncode"] == 0


def test_process_command_not_allowlisted() -> None:
    broker = ProcessBroker(
        ProcessConfig(allowed_commands=frozenset({"echo"})), RefValidator(), _sink()
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(ProcessRequest(["rm", "-rf", "/"]), BINDING)
    assert exc.value.code == ErrorCode.PROCESS_COMMAND_DENIED


# --- Message Broker ----------------------------------------------------------


def test_message_external_needs_allowlist() -> None:
    broker = MessageBroker(MessageConfig(), RefValidator(), _sink())
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(MessageRequest("partner", "COORDINATION", "hi", external=True), BINDING)
    assert exc.value.code == ErrorCode.MESSAGE_DENIED


def test_message_internal_ok() -> None:
    broker = MessageBroker(MessageConfig(), RefValidator(), _sink())
    out = broker.mediate(MessageRequest("agt_bob", "COORDINATION", "hi"), BINDING)
    assert out.receipt.outcome == "EXECUTED"


def test_message_anti_laundering() -> None:
    broker = MessageBroker(
        MessageConfig(), RefValidator(), _sink(), delegations=DelegationRegistry()
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(
            MessageRequest("agt_bob", "DELEGATE", "take this", propagate_delegation_id="dlg_fake"),
            BINDING,
        )
    assert exc.value.code == ErrorCode.MESSAGE_DENIED


def test_message_valid_propagation() -> None:
    reg = DelegationRegistry([PolicyAuthority("adm_1", AuthorityKind.SECURITY_ADMIN)])
    now = datetime.now(timezone.utc)
    root = reg.issue_root(
        authority_id="adm_1", subject_agent_id="agt_alice",
        capabilities={"db:read"}, resource_scopes={"db/x"},
        clearance=DataClassification.CONFIDENTIAL,
        not_before=now - timedelta(minutes=1), not_after=now + timedelta(hours=1),
    )
    child = reg.issue_child(
        parent_id=root.delegation_id, subject_agent_id="agt_bob",
        capabilities={"db:read"}, resource_scopes={"db/x"},
        clearance=DataClassification.INTERNAL,
        not_before=now - timedelta(minutes=1), not_after=now + timedelta(hours=1),
    )
    broker = MessageBroker(MessageConfig(), RefValidator(), _sink(), delegations=reg)
    out = broker.mediate(
        MessageRequest("agt_bob", "DELEGATE", "here", propagate_delegation_id=child.delegation_id),
        BINDING,
    )
    assert out.receipt.outcome == "EXECUTED"


# --- MCP Gateway -------------------------------------------------------------


def test_mcp_gateway_forwards_and_hides_credential() -> None:
    seen = {}
    def handler(tool: str, args: dict, credential: str):
        seen["credential"] = credential
        return {"tool": tool, "args": args, "status": "ok"}

    gw = MCPGateway(
        RefValidator(), _sink(),
        servers={"crm": ProtectedServer("https://crm.internal", "CRED-XYZ", handler)},
    )
    out = gw.mediate(MCPRequest("crm", "lookup", {"id": 7}), BINDING)
    assert out.result.detail["result"]["status"] == "ok"
    assert seen["credential"] == "CRED-XYZ"  # gateway injected it internally
    # Credential never surfaces in the receipt.
    assert "CRED-XYZ" not in out.receipt.model_dump_json()


def test_mcp_gateway_unknown_server_denied() -> None:
    gw = MCPGateway(RefValidator(), _sink(), servers={})
    with pytest.raises(CVZTTEError) as exc:
        gw.mediate(MCPRequest("secret-server", "x"), BINDING)
    assert exc.value.code == ErrorCode.MCP_BYPASS_DENIED
