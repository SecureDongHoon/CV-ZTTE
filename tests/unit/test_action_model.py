"""Unit tests for AgentAction / AgentContext canonical models (spec §6, §7)."""

import pytest
from pydantic import ValidationError

from cvztte.action import ActionType, AgentAction, DataClassification
from cvztte.context import AgentContext, ObservationSource, Provenance, SemanticContextQuality


def _db_action(**over):
    base = dict(
        action_type=ActionType.DB_OPERATION,
        target="prod-security-db",
        operation="select",
        resource="security_events",
        arguments={"columns": ["id", "severity"], "limit": 50},
        data_classification=DataClassification.INTERNAL,
    )
    base.update(over)
    return AgentAction(**base)


def test_action_hash_is_domain_prefixed():
    assert _db_action().action_hash().startswith("sha256:")


def test_action_hash_stable_regardless_of_arg_order():
    a = _db_action(arguments={"columns": ["id"], "limit": 5})
    b = _db_action(arguments={"limit": 5, "columns": ["id"]})
    assert a.action_hash() == b.action_hash()


def test_action_hash_changes_with_target():
    assert _db_action(target="prod-db").action_hash() != _db_action(target="staging-db").action_hash()


def test_action_hash_changes_with_type():
    a = _db_action().action_hash()
    b = _db_action(action_type=ActionType.FILE_READ).action_hash()
    assert a != b


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        AgentAction(action_type=ActionType.FILE_READ, target="/tmp/x", bogus=1)


def test_invalid_action_type_rejected():
    with pytest.raises(ValidationError):
        AgentAction(action_type="NOT_A_TYPE", target="x")


def test_all_required_action_types_present():
    required = {
        "TOOL_CALL", "MCP_CALL", "API_REQUEST", "DB_OPERATION", "FILE_READ",
        "FILE_WRITE", "FILE_DELETE", "PROCESS_EXEC", "SHELL_EXEC", "CODE_EXECUTION",
        "NETWORK_REQUEST", "USER_OUTPUT", "AGENT_MESSAGE", "MEMORY_READ",
        "MEMORY_WRITE", "SECRET_ACCESS", "CLOUD_CONTROL_ACTION", "EXTERNAL_MESSAGE",
        "FHE_ENCRYPT", "FHE_COMPUTE", "FHE_DECRYPT_REQUEST", "FHE_PARTIAL_DECRYPT",
        "FHE_COMBINE_DECRYPT", "FHE_KEY_ROTATE", "FHE_CONTEXT_CREATE",
    }
    assert required.issubset({t.value for t in ActionType})


def test_context_defaults_unknown_quality():
    ctx = AgentContext(agent_id="agt_1", runtime_id="rt_1", session_id="ses_1")
    assert ctx.semantic_context_quality is SemanticContextQuality.UNKNOWN


def test_provenance_boundary_flag_defaults_false():
    p = Provenance(source=ObservationSource.ADAPTER, runtime_id="rt_1", observed_at="2026-09-07T00:00:00Z")
    assert p.boundary_observed is False
