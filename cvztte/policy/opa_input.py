"""Build the OPA authorization input from CV-ZTTE domain objects (spec §60.4).

A ``Grant`` is the authorization envelope the Policy Authority binds to an
agent (derived from a validated delegation plus policy configuration). It maps
directly onto the ``input.grant`` shape consumed by ``policy/rego/cvztte/authz.rego``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cvztte.action.model import AgentAction, DataClassification
from cvztte.delegation.model import Delegation


@dataclass
class Grant:
    capabilities: set[str]
    resource_scopes: set[str]
    clearance: DataClassification
    allow_external_network: bool = False
    network_allowlist: set[str] = field(default_factory=set)
    shell_permitted: bool = False
    secret_access_permitted: bool = False
    max_db_rows: int = 0
    max_external_bytes: int = 0

    def to_input(self) -> dict[str, Any]:
        return {
            "capabilities": sorted(self.capabilities),
            "resource_scopes": sorted(self.resource_scopes),
            "clearance": self.clearance.value,
            "allow_external_network": self.allow_external_network,
            "network_allowlist": sorted(self.network_allowlist),
            "shell_permitted": self.shell_permitted,
            "secret_access_permitted": self.secret_access_permitted,
            "max_db_rows": self.max_db_rows,
            "max_external_bytes": self.max_external_bytes,
        }


def grant_from_delegation(
    delegation: Delegation,
    *,
    network_allowlist: set[str] | None = None,
    max_db_rows: int = 0,
    max_external_bytes: int = 0,
) -> Grant:
    """Derive a :class:`Grant` from a validated delegation.

    Boolean gates are derived from the delegated capability set so they cannot
    exceed what was delegated; quantitative limits/allowlists are policy config.
    """
    caps = set(delegation.capabilities)
    return Grant(
        capabilities=caps,
        resource_scopes=set(delegation.resource_scopes),
        clearance=delegation.clearance,
        allow_external_network="net:external" in caps,
        network_allowlist=set(network_allowlist or set()),
        shell_permitted="shell:exec" in caps,
        secret_access_permitted="secret:read" in caps,
        max_db_rows=max_db_rows,
        max_external_bytes=max_external_bytes,
    )


def build_authz_input(
    action: AgentAction,
    grant: Grant,
    *,
    destination_domain: str | None = None,
    row_count: int | None = None,
    byte_count: int | None = None,
) -> dict[str, Any]:
    """Assemble the deterministic ``input`` document for OPA."""
    action_doc: dict[str, Any] = {
        "action_type": action.action_type.value,
        "operation": action.operation or "",
        # resource falls back to target so scope matching always has a subject.
        "resource": action.resource or action.target,
        "data_classification": action.data_classification.value,
    }
    if destination_domain is not None:
        action_doc["destination_domain"] = destination_domain
    if row_count is not None:
        action_doc["row_count"] = row_count
    if byte_count is not None:
        action_doc["byte_count"] = byte_count
    return {"action": action_doc, "grant": grant.to_input()}
