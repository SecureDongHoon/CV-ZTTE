"""Onboarding, deployment modes, conformance, and shadow reporting (spec §33, §60.14, §60.15)."""

from __future__ import annotations

import pytest

from cvztte.audit.log import AuditStage, HashChainedAuditLog
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.onboarding import (
    ActivationState,
    AgentRuntimeProfile,
    ChannelPolicy,
    DeploymentMode,
    ModeController,
    ModeOutcome,
    OnboardingService,
    SandboxProfile,
    ShadowAggregator,
    ShadowObservation,
    apply_mode,
    is_enforcing,
)
from cvztte.onboarding.conformance import ConformanceHarness

POLICY_HASH = "sha256:" + "ab" * 32


def _mediated_channel() -> ChannelPolicy:
    return ChannelPolicy(mediated=True, deny_direct=True)


def _compliant_profile(**overrides) -> AgentRuntimeProfile:
    base = dict(
        agent_id="agt_alice",
        runtime_id="rt_1",
        framework="langgraph",
        delegation_template="tmpl_default",
        policy_hash=POLICY_HASH,
        sandbox=SandboxProfile(
            isolated=True, no_unrestricted_egress=True, filesystem_confined=True
        ),
        tool_policy=_mediated_channel(),
        network_policy=_mediated_channel(),
        filesystem_policy=_mediated_channel(),
        secret_policy=_mediated_channel(),
        output_policy=_mediated_channel(),
        semantic_adapter="langgraph-adapter-01",
    )
    base.update(overrides)
    return AgentRuntimeProfile(**base)


# --------------------------------------------------------------------------
# Deployment-mode effect mapping (§60.15)
# --------------------------------------------------------------------------


def test_observe_produces_would_outcomes_and_never_enforces() -> None:
    # OBSERVE is explicitly NOT security enforcement (§60.15).
    assert apply_mode(DeploymentMode.OBSERVE, True) is ModeOutcome.WOULD_ALLOW
    assert apply_mode(DeploymentMode.OBSERVE, False) is ModeOutcome.WOULD_DENY
    assert is_enforcing(DeploymentMode.OBSERVE) is False


def test_warn_permits_but_flags_denials() -> None:
    assert apply_mode(DeploymentMode.WARN, True) is ModeOutcome.ALLOW
    assert apply_mode(DeploymentMode.WARN, False) is ModeOutcome.WARN_ALLOW
    assert is_enforcing(DeploymentMode.WARN) is False


def test_enforce_blocks_denials() -> None:
    assert apply_mode(DeploymentMode.ENFORCE, True) is ModeOutcome.ALLOW
    assert apply_mode(DeploymentMode.ENFORCE, False) is ModeOutcome.DENY
    assert is_enforcing(DeploymentMode.ENFORCE) is True


def test_quarantine_denies_everything() -> None:
    assert apply_mode(DeploymentMode.QUARANTINE, True) is ModeOutcome.DENY
    assert apply_mode(DeploymentMode.QUARANTINE, False) is ModeOutcome.DENY
    assert is_enforcing(DeploymentMode.QUARANTINE) is True


# --------------------------------------------------------------------------
# Mode changes are admin-only and audited (§60.15)
# --------------------------------------------------------------------------


def test_mode_change_requires_admin() -> None:
    ctrl = ModeController(mode=DeploymentMode.OBSERVE)
    with pytest.raises(CVZTTEError) as exc:
        ctrl.set_mode(DeploymentMode.ENFORCE, actor="mallory", is_admin=False)
    assert exc.value.code == ErrorCode.MODE_CHANGE_FORBIDDEN
    # Mode unchanged after a refused attempt (fail-closed).
    assert ctrl.mode is DeploymentMode.OBSERVE


def test_admin_mode_change_is_audited() -> None:
    log = HashChainedAuditLog()
    ctrl = ModeController(mode=DeploymentMode.OBSERVE, audit_log=log)
    ctrl.set_mode(DeploymentMode.ENFORCE, actor="admin_root", is_admin=True)
    assert ctrl.mode is DeploymentMode.ENFORCE
    assert len(log) == 1
    event = log.events()[0]
    assert event.stage is AuditStage.ADMIN
    assert event.payload["action"] == "mode_change"
    assert event.payload["new_mode"] == "ENFORCE"
    assert log.verify() is True


def test_mode_change_requires_actor() -> None:
    ctrl = ModeController()
    with pytest.raises(CVZTTEError) as exc:
        ctrl.set_mode(DeploymentMode.WARN, actor="", is_admin=True)
    assert exc.value.code == ErrorCode.MODE_CHANGE_FORBIDDEN


# --------------------------------------------------------------------------
# Mandatory controls (§60.14)
# --------------------------------------------------------------------------


def test_compliant_profile_has_all_mandatory_controls() -> None:
    present, missing = _compliant_profile().mandatory_controls_present()
    assert present is True
    assert missing == []


def test_missing_egress_control_is_detected() -> None:
    profile = _compliant_profile(
        sandbox=SandboxProfile(isolated=True, no_unrestricted_egress=False)
    )
    present, missing = profile.mandatory_controls_present()
    assert present is False
    assert "sandbox.no_unrestricted_egress" in missing


def test_unmediated_channel_is_detected() -> None:
    profile = _compliant_profile(network_policy=ChannelPolicy(mediated=False))
    present, missing = profile.mandatory_controls_present()
    assert present is False
    assert "network_policy.mediated" in missing


def test_absent_adapter_does_not_block_controls() -> None:
    # Unknown-framework fallback: no adapter is allowed and must NOT lower enforcement.
    profile = _compliant_profile(semantic_adapter=None)
    present, _ = profile.mandatory_controls_present()
    assert present is True


# --------------------------------------------------------------------------
# Conformance harness (§33, §60.14) — live enforcement, no mocks
# --------------------------------------------------------------------------


def test_conformance_passes_for_compliant_profile() -> None:
    report = ConformanceHarness(_compliant_profile()).run()
    assert report.passed is True, report.failures()
    names = {c.name for c in report.checks}
    assert names == {
        "direct_bypass_blocked",
        "mediated_happy_path",
        "mediated_deny",
        "decision_token_exact_binding",
        "adapter_context",
        "kill_switch",
    }


def test_conformance_kill_switch_check_blocks_inflight() -> None:
    report = ConformanceHarness(_compliant_profile()).run()
    kill = next(c for c in report.checks if c.name == "kill_switch")
    assert kill.passed is True
    # In-flight authority is revoked by the advanced capability epoch.
    assert kill.detail == ErrorCode.DECISION_TOKEN_EPOCH_STALE.value


# --------------------------------------------------------------------------
# Onboarding service: activation gates (§60.14)
# --------------------------------------------------------------------------


def test_activation_requires_admin() -> None:
    svc = OnboardingService()
    with pytest.raises(CVZTTEError) as exc:
        svc.activate(_compliant_profile(), actor="mallory", is_admin=False)
    assert exc.value.code == ErrorCode.MODE_CHANGE_FORBIDDEN


def test_activation_blocked_when_controls_absent() -> None:
    log = HashChainedAuditLog()
    svc = OnboardingService(audit_log=log)
    profile = _compliant_profile(
        sandbox=SandboxProfile(no_unrestricted_egress=False)
    )
    with pytest.raises(CVZTTEError) as exc:
        svc.activate(profile, actor="admin_root", is_admin=True)
    assert exc.value.code == ErrorCode.ACTIVATION_BLOCKED
    # The blocked attempt is audited.
    assert log.events()[-1].payload["result"] == "BLOCKED"


def test_activation_succeeds_for_compliant_profile() -> None:
    log = HashChainedAuditLog()
    svc = OnboardingService(audit_log=log)
    profile = svc.register(_compliant_profile())
    assert profile.activation_state is ActivationState.PROFILED

    result = svc.activate(profile, actor="admin_root", is_admin=True)
    assert result.profile.activation_state is ActivationState.ENFORCED
    assert result.report.passed is True
    assert log.events()[-1].payload["result"] == "ENFORCED"
    assert log.verify() is True


# --------------------------------------------------------------------------
# Shadow-mode reporting (§60.15)
# --------------------------------------------------------------------------


def test_shadow_report_aggregates_observations() -> None:
    agg = ShadowAggregator()
    agg.record(ShadowObservation(
        action_hash="sha256:1", outcome=ModeOutcome.WOULD_ALLOW, adapter_present=True
    ))
    agg.record(ShadowObservation(
        action_hash="sha256:2", outcome=ModeOutcome.WOULD_DENY,
        false_positive_candidate=True, unknown_destination="evil.example.com",
    ))
    agg.record(ShadowObservation(
        action_hash="sha256:3", outcome=ModeOutcome.WOULD_DENY,
        bypass_attempt=True, missing_policy=True,
    ))
    report = agg.report()
    assert report.total == 3
    assert report.would_allow == 1
    assert report.would_deny == 2
    assert report.bypass_attempts == 1
    assert report.missing_policy == 1
    assert report.false_positive_candidates == 1
    assert report.unknown_destinations == ["evil.example.com"]
    assert report.adapter_coverage == pytest.approx(1 / 3)
    # A switch to ENFORCE would newly block both WOULD_DENY actions.
    assert report.enforce_would_block == 2
