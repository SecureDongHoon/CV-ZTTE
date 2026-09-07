"""Agent onboarding, deployment modes, conformance, and shadow reporting.

Spec §33, §60.14, §60.15. See :mod:`cvztte.onboarding.profile` for the
`AgentRuntimeProfile` (the 12 mandatory onboarding fields) and deployment
modes, :mod:`cvztte.onboarding.mode` for admin-only mode control + the
OBSERVE/WARN/ENFORCE/QUARANTINE effect mapping, :mod:`cvztte.onboarding.conformance`
for the pre-activation harness, :mod:`cvztte.onboarding.shadow` for shadow-mode
reporting, and :mod:`cvztte.onboarding.service` for the onboarding orchestrator.
"""

from __future__ import annotations

from cvztte.onboarding.conformance import (
    ConformanceCheck,
    ConformanceHarness,
    ConformanceReport,
)
from cvztte.onboarding.mode import (
    ModeController,
    ModeOutcome,
    apply_mode,
    is_enforcing,
)
from cvztte.onboarding.profile import (
    ActivationState,
    AgentRuntimeProfile,
    ChannelPolicy,
    DeploymentMode,
    SandboxProfile,
)
from cvztte.onboarding.service import OnboardingResult, OnboardingService
from cvztte.onboarding.shadow import ShadowAggregator, ShadowObservation, ShadowReport

__all__ = [
    "ActivationState",
    "AgentRuntimeProfile",
    "ChannelPolicy",
    "DeploymentMode",
    "SandboxProfile",
    "ModeController",
    "ModeOutcome",
    "apply_mode",
    "is_enforcing",
    "ConformanceCheck",
    "ConformanceHarness",
    "ConformanceReport",
    "ShadowAggregator",
    "ShadowObservation",
    "ShadowReport",
    "OnboardingResult",
    "OnboardingService",
]
