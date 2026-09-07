"""Framework adapter layer tests (spec §15, §60.9).

Adapters normalize framework events into canonical actions and PROPOSE ONLY —
the proposal is inert (no signature/token/decision) and never boundary-observed.
"""

from __future__ import annotations

import pytest

from cvztte.action.model import ActionType, DataClassification
from cvztte.adapters import (
    ActionProposal,
    AdapterBinding,
    AdapterRegistry,
    AgentMessageAdapter,
    BrowserAdapter,
    FrameworkEvent,
    GenericSDKAdapter,
    LangGraphAdapter,
    MCPAdapter,
    boundary_only_context,
    boundary_provenance,
)
from cvztte.context.model import ObservationSource, SemanticContextQuality
from cvztte.errors import CVZTTEError, ErrorCode


def _binding() -> AdapterBinding:
    return AdapterBinding(
        agent_id="agt_alice", runtime_id="runtime_1", session_id="ses_1"
    )


def _event(payload: dict, **kw) -> FrameworkEvent:
    return FrameworkEvent(binding=_binding(), payload=payload, **kw)


def test_mcp_adapter_maps_to_mcp_call() -> None:
    prop = MCPAdapter().propose(
        _event({"server": "srv", "tool": "search", "arguments": {"q": "x"}})
    )
    assert prop.action.action_type == ActionType.MCP_CALL
    assert prop.action.target == "srv/search"
    assert prop.action.resource == "srv"
    assert prop.context.semantic_context_quality == SemanticContextQuality.RICH


def test_proposal_is_propose_only() -> None:
    prop = MCPAdapter().propose(_event({"server": "s", "tool": "t"}))
    # Provenance: observed by an adapter, NOT a boundary (§7).
    assert prop.provenance.source == ObservationSource.ADAPTER
    assert prop.provenance.boundary_observed is False
    # Inert: no authorization artifacts on the model, and it is frozen.
    fields = set(ActionProposal.model_fields)
    assert fields == {"action", "context", "provenance"}
    with pytest.raises(Exception):
        prop.action = None  # type: ignore[misc]


def test_langgraph_known_kind_and_quality() -> None:
    prop = LangGraphAdapter().propose(
        _event({"kind": "http", "target": "https://api.example"})
    )
    assert prop.action.action_type == ActionType.NETWORK_REQUEST
    assert prop.context.semantic_context_quality == SemanticContextQuality.RICH


def test_langgraph_unknown_kind_degrades_quality() -> None:
    prop = LangGraphAdapter().propose(_event({"kind": "mystery", "target": "t"}))
    # Unknown kind -> conservative TOOL_CALL + degraded quality (§60.10), never
    # a silently-trusted low-risk guess.
    assert prop.action.action_type == ActionType.TOOL_CALL
    assert prop.context.semantic_context_quality == SemanticContextQuality.PARTIAL


def test_generic_explicit_action_type() -> None:
    prop = GenericSDKAdapter().propose(
        _event({"action_type": "FILE_WRITE", "target": "/tmp/x"})
    )
    assert prop.action.action_type == ActionType.FILE_WRITE


def test_generic_unknown_action_type_falls_back() -> None:
    prop = GenericSDKAdapter().propose(
        _event({"action_type": "NOT_A_TYPE", "target": "x"})
    )
    assert prop.action.action_type == ActionType.TOOL_CALL


def test_agent_message_external_vs_internal() -> None:
    internal = AgentMessageAdapter().propose(_event({"to": "agt_bob"}))
    external = AgentMessageAdapter().propose(
        _event({"to": "partner", "external": True})
    )
    assert internal.action.action_type == ActionType.AGENT_MESSAGE
    assert external.action.action_type == ActionType.EXTERNAL_MESSAGE


def test_browser_adapter_experimental() -> None:
    adapter = BrowserAdapter()
    assert adapter.experimental is True
    prop = adapter.propose(_event({"event": "navigate", "url": "https://x"}))
    assert prop.action.action_type == ActionType.NETWORK_REQUEST
    assert prop.provenance.boundary_observed is False


def test_missing_required_field_fails_closed() -> None:
    with pytest.raises(CVZTTEError) as exc:
        MCPAdapter().propose(_event({"server": "s"}))  # missing "tool"
    assert exc.value.code == ErrorCode.SCHEMA_INVALID


def test_registry_known_and_unknown() -> None:
    reg = AdapterRegistry()
    assert isinstance(reg.get("mcp"), MCPAdapter)
    assert reg.get("no-such-framework") is None
    assert "langgraph" in reg.frameworks()


def test_boundary_only_context_and_provenance() -> None:
    b = _binding()
    ctx = boundary_only_context(b, data_classification=DataClassification.CONFIDENTIAL)
    assert ctx.semantic_context_quality == SemanticContextQuality.BOUNDARY_ONLY
    assert ctx.adapter_id is None
    prov = boundary_provenance(b, ObservationSource.EGRESS_PROXY)
    # A real boundary observation IS authoritative (§7).
    assert prov.boundary_observed is True
    assert prov.source == ObservationSource.EGRESS_PROXY


def test_action_hash_binds_distinct_actions() -> None:
    a = MCPAdapter().propose(_event({"server": "s", "tool": "read"}))
    b = MCPAdapter().propose(_event({"server": "s", "tool": "delete"}))
    assert a.action_hash() != b.action_hash()
    assert a.action_hash() == a.action.action_hash()
