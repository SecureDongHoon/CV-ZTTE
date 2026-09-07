"""Deployment profiles: demo / secure-lab / enterprise-reference (spec §53).

Three named profiles select the crypto/runtime posture *and* the Phase-19
resource bounds (§52, §60.32). They never widen a security decision — they only
pick parameters and hardening levels the enterprise operator, not an agent,
controls.

* **demo** — fast, hackathon-friendly, explicitly weaker; clearly labelled.
* **secure-lab** — 128-bit crypto, separate threshold parties, stronger
  isolation; the profile the reference build actually runs.
* **enterprise-reference** — a *configuration skeleton* enumerating the
  infrastructure a production deployment would require (separate hosts, mTLS,
  HSM/KMS/TEE, HA state, SIEM/SOC, signed releases, SBOM/image signing, secure
  clock, DR, external audit). It is **never production-certified** (§53): the
  reference build does not itself provide this infrastructure, and this module
  says so honestly rather than implying otherwise.

``ResourceLimits`` are DoS/memory guards (§52), not cryptographic bindings, so
they live here — off the ``context_hash`` — and are enforced at runtime by the
FHE broker and the :mod:`cvztte.config.backpressure` admission bounds.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field

from cvztte.cac.context import SecurityProfile


class ProfileName(str, enum.Enum):
    DEMO = "demo"
    SECURE_LAB = "secure-lab"
    ENTERPRISE_REFERENCE = "enterprise-reference"


class ResourceLimits(BaseModel):
    """Fail-closed resource bounds for the expensive stages (§52, §60.32)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Reject a ciphertext larger than this many bytes (0 => unbounded). Guards
    #: against oversized-ciphertext memory-exhaustion at the FHE broker.
    max_ciphertext_bytes: int = Field(ge=0, default=0)
    #: Max concurrent in-flight ZK proofs (gnark/EZKL) before backpressure sheds.
    max_inflight_proofs: int = Field(ge=1, default=8)
    #: Max concurrent in-flight FHE broker jobs before backpressure sheds.
    max_inflight_fhe: int = Field(ge=1, default=4)


class InfraRequirement(BaseModel):
    """One enterprise infrastructure control the skeleton enumerates (§53)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    component: str
    requirement: str
    #: Honest self-assessment: the reference build does NOT provide production
    #: infrastructure, so enterprise-reference requirements are unmet here.
    satisfied_by_reference_build: bool = False


class DeploymentProfile(BaseModel):
    """A named posture: crypto profile + resource bounds + hardening claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: ProfileName
    description: str
    #: The CKKS/crypto security profile this deployment uses. enterprise-reference
    #: inherits secure-lab crypto (the skeleton adds infra, not weaker crypto).
    security_profile: SecurityProfile
    resource_limits: ResourceLimits
    requires_mtls: bool = False
    requires_separate_hosts: bool = False
    key_custody: str = "software"  # software | hsm-kms-tee
    #: MUST stay False for enterprise-reference — never claim production-certified.
    production_certified: bool = False
    infra_requirements: tuple[InfraRequirement, ...] = ()

    def model_post_init(self, _ctx) -> None:  # noqa: D401 - pydantic hook
        # Invariant (§53): enterprise-reference is never production-certified.
        if self.name is ProfileName.ENTERPRISE_REFERENCE and self.production_certified:
            raise ValueError("enterprise-reference must never be production_certified (§53)")


_ENTERPRISE_INFRA = (
    InfraRequirement(component="topology", requirement="separate services/hosts per plane"),
    InfraRequirement(component="transport", requirement="mutual TLS between all services"),
    InfraRequirement(component="key-custody", requirement="HSM / KMS / TEE for signing & MAC keys"),
    InfraRequirement(component="state", requirement="highly-available Redis / state store"),
    InfraRequirement(component="observability", requirement="SIEM / SOC integration"),
    InfraRequirement(component="supply-chain", requirement="signed policy/model/circuit releases"),
    InfraRequirement(component="supply-chain", requirement="SBOM + container image signing"),
    InfraRequirement(component="time", requirement="secure/attested clock source"),
    InfraRequirement(component="resilience", requirement="disaster recovery / backups"),
    InfraRequirement(component="assurance", requirement="external cryptographic/security audit"),
)


DEMO = DeploymentProfile(
    name=ProfileName.DEMO,
    description="Fast hackathon-friendly settings — weaker, clearly labelled (§53).",
    security_profile=SecurityProfile.DEMO,
    resource_limits=ResourceLimits(
        max_ciphertext_bytes=32 * 1024 * 1024, max_inflight_proofs=4, max_inflight_fhe=2
    ),
)

SECURE_LAB = DeploymentProfile(
    name=ProfileName.SECURE_LAB,
    description="128-bit crypto, separate threshold parties, stronger isolation (§53).",
    security_profile=SecurityProfile.SECURE_LAB,
    resource_limits=ResourceLimits(
        max_ciphertext_bytes=16 * 1024 * 1024, max_inflight_proofs=8, max_inflight_fhe=4
    ),
    requires_separate_hosts=True,
)

ENTERPRISE_REFERENCE = DeploymentProfile(
    name=ProfileName.ENTERPRISE_REFERENCE,
    description=(
        "Configuration skeleton for a production posture — NOT production-certified; "
        "the reference build does not itself provide this infrastructure (§53)."
    ),
    security_profile=SecurityProfile.SECURE_LAB,
    resource_limits=ResourceLimits(
        max_ciphertext_bytes=16 * 1024 * 1024, max_inflight_proofs=16, max_inflight_fhe=8
    ),
    requires_mtls=True,
    requires_separate_hosts=True,
    key_custody="hsm-kms-tee",
    production_certified=False,
    infra_requirements=_ENTERPRISE_INFRA,
)

_BY_NAME = {p.name: p for p in (DEMO, SECURE_LAB, ENTERPRISE_REFERENCE)}


def get_profile(name: ProfileName | str) -> DeploymentProfile:
    """Resolve a profile by name (enterprise operator selects; agents cannot)."""
    key = ProfileName(name)
    return _BY_NAME[key]
