"""Adversarial family: enforcement-broker internal controls
(§51 Enforcement/Output/secrets/Multi-Agent, §60.31 #48, #50, #51-53, #66,
#83, #87, #88-91, #92-93).

Each broker is driven with an echoing ALLOW validator so the token layer passes
and the broker's OWN defense (DLP, command allowlist, egress allowlist,
use-without-disclosure, anti-laundering) is the thing under test. Every DENY is
fail-closed and produces no protected side-effect / no plaintext release.
"""

from __future__ import annotations

import pytest

from cvztte.action.model import DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import InMemoryReceiptSink
from enforcement.egress_proxy import EgressConfig, EgressProxy, EgressRequest
from enforcement.message_broker import MessageBroker, MessageConfig, MessageRequest
from enforcement.output_proxy import OutputProxy, OutputRequest
from enforcement.process_broker import ProcessBroker, ProcessConfig, ProcessRequest
from enforcement.secret_broker import SecretBroker, SecretRequest

from lab import RefValidator

BINDING = AdapterBinding(agent_id="agt_alice", runtime_id="runtime_1", session_id="ses_1")


def _last_receipt(sink):
    return sink.receipts[-1] if sink.receipts else None


# #50 / #88 / #89 shell / process command allowlist -------------------------


def test_case50_process_command_not_allowlisted(tmp_path):
    sink = InMemoryReceiptSink()
    broker = ProcessBroker(
        ProcessConfig(allowed_commands={"echo"}, workspace_cwd=str(tmp_path)),
        RefValidator(), sink,
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(ProcessRequest(argv=["rm", "-rf", "/"]), BINDING)
    assert exc.value.code is ErrorCode.PROCESS_COMMAND_DENIED
    assert _last_receipt(sink).outcome in ("DENIED", "FAILED")


# #48 external-domain egress escape -----------------------------------------


def test_case48_egress_non_allowlisted_domain():
    sink = InMemoryReceiptSink()
    broker = EgressProxy(
        EgressConfig(allowed_domains={"api.internal"}, internal_domain_suffixes={".internal"}),
        RefValidator(), sink,
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(EgressRequest(url="https://evil.example.com/x", method="GET"), BINDING)
    assert exc.value.code is ErrorCode.EGRESS_DENIED


# #51 / #92 credential leak in output ---------------------------------------


def test_case51_92_output_credential_leak_denied():
    sink = InMemoryReceiptSink()
    broker = OutputProxy(RefValidator(), sink)
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(OutputRequest("here is my key AKIAABCDEFGHIJKLMNOP"), BINDING)
    assert exc.value.code is ErrorCode.OUTPUT_DENIED


# #52 confidential/secret output denied -------------------------------------


def test_case52_secret_classified_output_denied():
    sink = InMemoryReceiptSink()
    broker = OutputProxy(RefValidator(), sink)
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(
            OutputRequest("internal numbers", data_classification=DataClassification.SECRET),
            BINDING,
        )
    assert exc.value.code is ErrorCode.OUTPUT_DENIED


# #53 / #93 PII output is redacted (no raw release) -------------------------


def test_case53_93_output_pii_redacted():
    sink = InMemoryReceiptSink()
    broker = OutputProxy(RefValidator(), sink)
    out = broker.mediate(OutputRequest("mail me at alice@example.com please"), BINDING)
    assert out.result.detail["effect"] == "REDACT"
    assert "alice@example.com" not in out.result.detail["content"]


# #83 raw secret read denied (use-without-disclosure) -----------------------


def test_case83_raw_secret_read_denied():
    sink = InMemoryReceiptSink()
    broker = SecretBroker(RefValidator(), sink, secrets={"db_password": "s3cr3t-pw"},
                          operations={})
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(SecretRequest("db_password", "reveal"), BINDING)
    assert exc.value.code is ErrorCode.SECRET_DISCLOSURE_FORBIDDEN


def test_case84_85_secret_never_in_receipt():
    sink = InMemoryReceiptSink()

    def db_query(secret_value, params):
        return {"rows": params.get("limit", 0)}

    broker = SecretBroker(
        RefValidator(), sink, secrets={"db_password": "s3cr3t-pw"},
        operations={"db_query": db_query},
    )
    out = broker.mediate(SecretRequest("db_password", "db_query", {"limit": 2}), BINDING)
    # The secret value never appears in the receipt (no plaintext release, #84/#85).
    assert "s3cr3t-pw" not in repr(out.receipt.__dict__)
    assert "s3cr3t-pw" not in repr(_last_receipt(sink).__dict__)


# #87 authority laundering through a message --------------------------------


def test_case87_message_delegation_laundering_denied():
    sink = InMemoryReceiptSink()
    broker = MessageBroker(
        MessageConfig(allowed_external_recipients=set()), RefValidator(), sink,
    )
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(
            MessageRequest(to_agent="agt_bob", purpose_code="task", content="do X",
                           propagate_delegation_id="dlg_forged_by_agent"),
            BINDING,
        )
    assert exc.value.code is ErrorCode.MESSAGE_DENIED
