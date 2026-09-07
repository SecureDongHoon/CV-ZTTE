"""Agent onboarding orchestration (spec §33, §60.14).

Drives the 9-step onboarding lifecycle (§33): identity → framework/runtime
profile → policy/delegation → risk → sandbox → channel policies → adapter →
enforcement conformance tests → activate.

The service advances an :class:`AgentRuntimeProfile` through its
:class:`ActivationState` and enforces the two fail-closed gates at activation
(§60.14):

1. **mandatory controls present** — every protected channel mediated + deny
   direct, sandbox without unrestricted egress; else ``ACTIVATION_BLOCKED``;
2. **conformance passed** — the live :class:`ConformanceHarness` checks all pass;
   else ``CONFORMANCE_FAILED``.

Activation is admin-only and audited (AuditStage.ADMIN, §60.15). An agent that
fails either gate stays un-``ENFORCED`` — it never silently becomes active.
"""

from __future__ import annotations

from cvztte.audit.log import AuditStage, HashChainedAuditLog
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.onboarding.conformance import ConformanceHarness, ConformanceReport
from cvztte.onboarding.profile import ActivationState, AgentRuntimeProfile


class OnboardingResult:
    """Outcome of an activation attempt: the (possibly advanced) profile + report."""

    def __init__(self, profile: AgentRuntimeProfile, report: ConformanceReport) -> None:
        self.profile = profile
        self.report = report


class OnboardingService:
    """Registers agents and gates activation on controls + conformance (§60.14)."""

    def __init__(self, *, audit_log: HashChainedAuditLog | None = None) -> None:
        self._audit = audit_log

    def register(self, profile: AgentRuntimeProfile) -> AgentRuntimeProfile:
        """Steps 1-7: record the profile. State becomes PROFILED (not yet enforced)."""
        return profile.model_copy(update={"activation_state": ActivationState.PROFILED})

    def run_conformance(self, profile: AgentRuntimeProfile) -> ConformanceReport:
        """Step 8: run live enforcement conformance checks (§60.14)."""
        return ConformanceHarness(profile).run()

    def activate(
        self, profile: AgentRuntimeProfile, *, actor: str, is_admin: bool
    ) -> OnboardingResult:
        """Step 9: admin-only, audited activation gated fail-closed (§60.14).

        Blocks activation unless mandatory controls are present AND conformance
        passes. On success returns the profile advanced to ``ENFORCED``.
        """
        if not is_admin or not actor:
            raise CVZTTEError(
                ErrorCode.MODE_CHANGE_FORBIDDEN, "activation requires an administrator"
            )

        present, missing = profile.mandatory_controls_present()
        if not present:
            self._audit_activation(profile, actor, "BLOCKED", missing=missing)
            raise CVZTTEError(
                ErrorCode.ACTIVATION_BLOCKED,
                "mandatory controls absent",
                detail={"missing": missing},
            )

        report = self.run_conformance(profile)
        if not report.passed:
            self._audit_activation(
                profile, actor, "CONFORMANCE_FAILED", failures=report.failures()
            )
            raise CVZTTEError(
                ErrorCode.CONFORMANCE_FAILED,
                "conformance checks failed",
                detail={"failures": report.failures()},
            )

        activated = profile.model_copy(
            update={"activation_state": ActivationState.ENFORCED}
        )
        self._audit_activation(activated, actor, "ENFORCED")
        return OnboardingResult(profile=activated, report=report)

    # -- internals -----------------------------------------------------------

    def _audit_activation(
        self,
        profile: AgentRuntimeProfile,
        actor: str,
        result: str,
        *,
        missing: list[str] | None = None,
        failures: list[str] | None = None,
    ) -> None:
        if self._audit is None:
            return
        payload: dict = {
            "action": "onboarding_activation",
            "actor": actor,
            "agent_id": profile.agent_id,
            "runtime_id": profile.runtime_id,
            "result": result,
        }
        if missing:
            payload["missing_controls"] = sorted(missing)
        if failures:
            payload["conformance_failures"] = sorted(failures)
        self._audit.append(AuditStage.ADMIN, payload)
