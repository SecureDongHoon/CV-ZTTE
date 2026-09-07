"""Deployment profiles and Phase-19 resource bounds (spec §52, §53, §60.32).

* :mod:`cvztte.config.profiles` — the demo / secure-lab / enterprise-reference
  deployment profiles and their fail-closed ``ResourceLimits``.
* :mod:`cvztte.config.backpressure` — ``BoundedAdmission``, a fail-closed
  concurrency bound for the saturating prover/FHE stages.
"""

from __future__ import annotations

from cvztte.config.backpressure import BoundedAdmission
from cvztte.config.profiles import (
    DEMO,
    ENTERPRISE_REFERENCE,
    SECURE_LAB,
    DeploymentProfile,
    InfraRequirement,
    ProfileName,
    ResourceLimits,
    get_profile,
)

__all__ = [
    "BoundedAdmission",
    "DeploymentProfile",
    "InfraRequirement",
    "ProfileName",
    "ResourceLimits",
    "get_profile",
    "DEMO",
    "SECURE_LAB",
    "ENTERPRISE_REFERENCE",
]
