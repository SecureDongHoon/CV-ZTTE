"""Phase 4 OPA authorization against the real opa binary (spec §13, §60.4)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.policy import Grant, OPAClient, build_authz_input

BUNDLE = Path(__file__).resolve().parents[2] / "policy" / "rego"

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None, reason="opa not on PATH (source env.sh)"
)


@pytest.fixture()
def client() -> OPAClient:
    return OPAClient(BUNDLE)


def _grant(**over) -> Grant:
    base = dict(
        capabilities={"fs:read"},
        resource_scopes={"fs:/data"},
        clearance=DataClassification.CONFIDENTIAL,
        max_db_rows=1000,
        max_external_bytes=1048576,
    )
    base.update(over)
    return Grant(**base)


def _read_action(**over) -> AgentAction:
    kwargs = dict(action_type=ActionType.FILE_READ, target="fs:/data/report.csv", operation="read")
    kwargs.update(over)
    return AgentAction(**kwargs)


def test_allow_read_internal(client: OPAClient) -> None:
    d = client.evaluate(build_authz_input(_read_action(), _grant()))
    assert d.allow is True
    assert d.reason_code == "ALLOW"
    assert d.risk_level == 2
    assert d.require_behavior_check is True
    assert d.require_gnark_authz is False


def test_deny_capability_missing(client: OPAClient) -> None:
    d = client.evaluate(build_authz_input(_read_action(), _grant(capabilities=set())))
    assert d.allow is False
    assert d.reason_code == "CAPABILITY_MISSING"


def test_deny_scope_not_covered(client: OPAClient) -> None:
    action = _read_action(target="fs:/etc/shadow")
    d = client.evaluate(build_authz_input(action, _grant()))
    assert d.allow is False
    assert d.reason_code == "SCOPE_NOT_COVERED"


def test_deny_clearance_insufficient(client: OPAClient) -> None:
    action = _read_action(data_classification=DataClassification.SECRET)
    d = client.evaluate(build_authz_input(action, _grant(clearance=DataClassification.INTERNAL)))
    assert d.allow is False
    assert d.reason_code == "CLEARANCE_INSUFFICIENT"


def test_external_network_forbidden(client: OPAClient) -> None:
    action = AgentAction(
        action_type=ActionType.NETWORK_REQUEST, target="net:api.example.com", operation="get"
    )
    # No net:external capability => external network is forbidden.
    d = client.evaluate(
        build_authz_input(
            action,
            _grant(capabilities=set(), resource_scopes={"net:api.example.com"}),
            destination_domain="api.example.com",
        )
    )
    assert d.allow is False
    # EXTERNAL_NETWORK_FORBIDDEN sorts before others when present.
    assert d.reason_code in {"EXTERNAL_NETWORK_FORBIDDEN", "DOMAIN_NOT_ALLOWLISTED", "CAPABILITY_MISSING"}


def test_network_allowed_when_permitted(client: OPAClient) -> None:
    action = AgentAction(
        action_type=ActionType.NETWORK_REQUEST, target="net:api.example.com", operation="get"
    )
    grant = _grant(
        capabilities={"net:external"},
        resource_scopes={"net:api.example.com"},
        allow_external_network=True,
        network_allowlist={"api.example.com"},
    )
    d = client.evaluate(build_authz_input(action, grant, destination_domain="api.example.com"))
    assert d.allow is True
    assert d.risk_level == 3
    assert d.require_gnark_authz is True
    assert d.require_ezkl is True


def test_domain_not_allowlisted(client: OPAClient) -> None:
    action = AgentAction(
        action_type=ActionType.NETWORK_REQUEST, target="net:evil.example.com", operation="get"
    )
    grant = _grant(
        capabilities={"net:external"},
        resource_scopes={"net:evil.example.com"},
        allow_external_network=True,
        network_allowlist={"api.example.com"},
    )
    d = client.evaluate(build_authz_input(action, grant, destination_domain="evil.example.com"))
    assert d.allow is False
    assert d.reason_code == "DOMAIN_NOT_ALLOWLISTED"


def test_shell_requires_permission_and_is_l4(client: OPAClient) -> None:
    action = AgentAction(action_type=ActionType.SHELL_EXEC, target="shell:/bin/ls", operation="exec")
    denied = client.evaluate(
        build_authz_input(action, _grant(capabilities={"shell:exec"}, resource_scopes={"shell:/bin"}))
    )
    assert denied.allow is False
    assert denied.reason_code == "SHELL_FORBIDDEN"
    assert denied.risk_level == 4
    assert denied.require_human_approval is True


def test_write_is_l3(client: OPAClient) -> None:
    action = AgentAction(action_type=ActionType.FILE_WRITE, target="fs:/data/out.txt", operation="write")
    d = client.evaluate(
        build_authz_input(action, _grant(capabilities={"fs:write"}))
    )
    assert d.allow is True
    assert d.risk_level == 3
    assert d.require_gnark_authz and d.require_ezkl and d.require_behavior_check


def test_authorize_raises_on_hard_deny(client: OPAClient) -> None:
    with pytest.raises(CVZTTEError) as exc:
        client.authorize(build_authz_input(_read_action(), _grant(capabilities=set())))
    assert exc.value.code == ErrorCode.OPA_DENY


def test_opa_unavailable_fails_closed() -> None:
    client = OPAClient(BUNDLE, opa_bin="/nonexistent/opa")
    with pytest.raises(CVZTTEError) as exc:
        client.evaluate(build_authz_input(_read_action(), _grant()))
    assert exc.value.code == ErrorCode.OPA_UNAVAILABLE
