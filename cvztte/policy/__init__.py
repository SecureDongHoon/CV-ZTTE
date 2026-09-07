"""Authoritative OPA/Rego policy (spec §13, §28, §60.4)."""

from cvztte.policy.bundle import (
    PolicyBundle,
    PolicyBundleRegistry,
    compute_bundle_hash,
)
from cvztte.policy.model import PolicyDecision, RiskTier
from cvztte.policy.opa_client import DEFAULT_QUERY, OPAClient
from cvztte.policy.opa_input import (
    Grant,
    build_authz_input,
    grant_from_delegation,
)

__all__ = [
    "PolicyDecision",
    "RiskTier",
    "OPAClient",
    "DEFAULT_QUERY",
    "Grant",
    "build_authz_input",
    "grant_from_delegation",
    "PolicyBundle",
    "PolicyBundleRegistry",
    "compute_bundle_hash",
]
