"""Containment engine + dynamic capability decay tests (spec §25-§27, §60.18-§60.20).

Covers escalate-only transitions from behavior features, per-state capability
decay monotonicity (§60.19), the "containment never grants authority" invariant
(§26), capability-epoch bumping and the resulting stale-token invalidation
through the real Phase 8 validator, the administrator kill switch (§27), and the
method-gated recovery rules (§60.19).
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from cvztte.adapters.base import AdapterBinding
from cvztte.containment import (
    CapabilityAttributes,
    ContainmentEngine,
    ContainmentState,
    RecoveryMethod,
    ThresholdPolicy,
    effective_capabilities,
)
from cvztte.containment.policy import ContainmentThresholds
from cvztte.decision import (
    DecisionTokenAuthority,
    DecisionTokenValidator,
    EpochSet,
    EpochSource,
    PresentedTokenStore,
)
from cvztte.errors import CVZTTEError, ErrorCode

SUBJECT = "agt_alice|rt_1|ses_1"
AGENT = "agt_alice"
T0 = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)

# A capability profile spanning every decay-relevant attribute.
PROFILE = {
    "read_file": CapabilityAttributes(),
    "write_file": CapabilityAttributes(writes=True),
    "http_get": CapabilityAttributes(external_network=True),
    "read_secret": CapabilityAttributes(secret_access=True),
    "spawn_agent": CapabilityAttributes(new_subagent=True),
    "delete_all": CapabilityAttributes(optional_high_risk=True, writes=True),
    "ping": CapabilityAttributes(diagnostic=True),
}
ALL_CAPS = set(PROFILE)


def _engine(**kw) -> ContainmentEngine:
    return ContainmentEngine(**kw)


# --- escalation --------------------------------------------------------------


def test_evaluate_escalates_from_features() -> None:
    eng = _engine()
    assert eng.state(SUBJECT) is ContainmentState.NORMAL
    tr = eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 3}, now=T0)
    assert tr is not None
    assert tr.old_state is ContainmentState.NORMAL
    assert tr.new_state is ContainmentState.SUSPICIOUS
    assert eng.state(SUBJECT) is ContainmentState.SUSPICIOUS


def test_evaluate_is_escalate_only() -> None:
    eng = _engine()
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"bypass_attempts_5m": 3}, now=T0)
    assert eng.state(SUBJECT) is ContainmentState.QUARANTINED
    # Clean features must NOT lower the state.
    tr = eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={}, now=T0)
    assert tr is None
    assert eng.state(SUBJECT) is ContainmentState.QUARANTINED


def test_quarantine_signal_flag_forces_quarantine() -> None:
    eng = _engine()
    tr = eng.evaluate(
        subject=SUBJECT, agent_id=AGENT,
        features={"secret_exfiltration_attempt": True}, now=T0,
    )
    assert tr.new_state is ContainmentState.QUARANTINED


def test_thresholds_are_config_controlled() -> None:
    # A stricter policy escalates on a single denial; the default would not.
    strict = ThresholdPolicy(ContainmentThresholds(suspicious_denials_60s=1))
    eng = _engine(policy=strict)
    tr = eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 1}, now=T0)
    assert tr is not None and tr.new_state is ContainmentState.SUSPICIOUS


# --- capability decay --------------------------------------------------------


def test_capability_decay_is_monotone_per_state() -> None:
    def caps(state: ContainmentState) -> frozenset[str]:
        return effective_capabilities(
            delegated=ALL_CAPS, enterprise_policy=ALL_CAPS,
            runtime_profile=ALL_CAPS, state=state, profile=PROFILE,
        )

    normal = caps(ContainmentState.NORMAL)
    suspicious = caps(ContainmentState.SUSPICIOUS)
    restricted = caps(ContainmentState.RESTRICTED)
    quarantined = caps(ContainmentState.QUARANTINED)
    terminated = caps(ContainmentState.TERMINATED)

    # Each escalation is a subset of the previous (authority only shrinks, §60.19).
    assert suspicious <= normal
    assert restricted <= suspicious
    assert quarantined <= restricted
    assert terminated <= quarantined

    assert normal == ALL_CAPS
    assert "delete_all" not in suspicious  # optional high-risk dropped
    assert restricted == {"read_file", "ping"}  # read-only, no net/secret/subagent
    assert quarantined == {"ping"}  # diagnostic only
    assert terminated == frozenset()  # no runtime authority


def test_decay_never_grants_authority() -> None:
    # A capability not delegated can never appear at any containment state.
    delegated = {"read_file"}
    for state in ContainmentState:
        caps = effective_capabilities(
            delegated=delegated, enterprise_policy=ALL_CAPS,
            runtime_profile=ALL_CAPS, state=state, profile=PROFILE,
        )
        assert caps <= delegated


def test_engine_effective_capabilities_tracks_state() -> None:
    eng = _engine()
    args = dict(delegated=ALL_CAPS, enterprise_policy=ALL_CAPS,
                runtime_profile=ALL_CAPS, profile=PROFILE)
    assert eng.effective_capabilities(SUBJECT, **args) == ALL_CAPS
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_5m": 8}, now=T0)
    assert eng.state(SUBJECT) is ContainmentState.RESTRICTED
    assert eng.effective_capabilities(SUBJECT, **args) == {"read_file", "ping"}


# --- capability epoch --------------------------------------------------------


def test_transition_bumps_capability_epoch() -> None:
    source = EpochSource(EpochSet())
    eng = _engine(epoch_source=source)
    before = source.current().capability_epoch
    tr = eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 3}, now=T0)
    assert source.current().capability_epoch == before + 1
    assert tr.capability_epoch == before + 1


def test_no_transition_does_not_bump_epoch() -> None:
    source = EpochSource(EpochSet())
    eng = _engine(epoch_source=source)
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={}, now=T0)  # no change
    assert source.current().capability_epoch == 0


def test_containment_invalidates_in_flight_token() -> None:
    # A token minted under the current capability epoch must stop validating
    # once containment escalates and bumps the epoch (§27).
    KEY = b"k" * 32
    binding = AdapterBinding(agent_id=AGENT, runtime_id="rt_1", session_id="ses_1")
    source = EpochSource(EpochSet())
    eng = _engine(epoch_source=source)

    authority = DecisionTokenAuthority(KEY)
    store = PresentedTokenStore()
    validator = DecisionTokenValidator(mac_key=KEY, epoch_source=source, store=store)

    from cvztte.action.model import ActionType, AgentAction

    action = AgentAction(action_type=ActionType.FILE_READ, target="a.txt", operation="read")
    signed = authority.issue(
        action=action, binding=binding, audience="file-broker-01",
        policy_hash="sha256:" + "de" * 32, epochs=source.current(),
    )
    store.present(signed)

    # Valid before containment.
    decision = validator.authorize(
        action=action, action_hash=action.action_hash(),
        binding=binding, audience="file-broker-01",
    )
    assert decision.effect.value == "ALLOW"

    # Containment escalation bumps the capability epoch -> token now stale.
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"bypass_attempts_5m": 3}, now=T0)
    store.present(signed)  # re-present the same (now single-use-consumed) token
    with pytest.raises(CVZTTEError) as exc:
        validator.authorize(
            action=action, action_hash=action.action_hash(),
            binding=binding, audience="file-broker-01",
        )
    assert exc.value.code == ErrorCode.DECISION_TOKEN_EPOCH_STALE


# --- kill switch -------------------------------------------------------------


def test_kill_switch_forces_quarantine() -> None:
    eng = _engine()
    tr = eng.kill_switch(
        subject=SUBJECT, agent_id=AGENT,
        target_state=ContainmentState.QUARANTINED, reason_codes=["operator"], now=T0,
    )
    assert tr.new_state is ContainmentState.QUARANTINED
    assert "KILL_SWITCH" in tr.reason_codes
    assert eng.blocks_new_consequential_tokens(SUBJECT) is True


def test_kill_switch_can_terminate() -> None:
    eng = _engine()
    tr = eng.kill_switch(
        subject=SUBJECT, agent_id=AGENT,
        target_state=ContainmentState.TERMINATED, reason_codes=["sandbox-escape"], now=T0,
    )
    assert tr.new_state is ContainmentState.TERMINATED


def test_kill_switch_rejects_non_terminal_target() -> None:
    eng = _engine()
    with pytest.raises(CVZTTEError) as exc:
        eng.kill_switch(
            subject=SUBJECT, agent_id=AGENT,
            target_state=ContainmentState.SUSPICIOUS, reason_codes=["x"], now=T0,
        )
    assert exc.value.code == ErrorCode.CONTAINMENT_QUARANTINED


def test_kill_switch_does_not_de_escalate() -> None:
    eng = _engine()
    eng.kill_switch(
        subject=SUBJECT, agent_id=AGENT,
        target_state=ContainmentState.TERMINATED, reason_codes=["x"], now=T0,
    )
    # A weaker kill target keeps the more severe state.
    tr = eng.kill_switch(
        subject=SUBJECT, agent_id=AGENT,
        target_state=ContainmentState.QUARANTINED, reason_codes=["y"], now=T0,
    )
    assert tr.new_state is ContainmentState.TERMINATED


# --- recovery ----------------------------------------------------------------


def test_recover_suspicious_requires_cooldown() -> None:
    eng = _engine(suspicious_cooldown_seconds=300)
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 3}, now=T0)
    # Too soon: cooldown not elapsed.
    with pytest.raises(CVZTTEError) as exc:
        eng.recover(subject=SUBJECT, agent_id=AGENT,
                    method=RecoveryMethod.COOLDOWN_CLEAN, now=T0 + timedelta(seconds=10))
    assert exc.value.code == ErrorCode.RECOVERY_APPROVAL_REQUIRED
    # After cooldown: recovers to NORMAL.
    tr = eng.recover(subject=SUBJECT, agent_id=AGENT,
                     method=RecoveryMethod.COOLDOWN_CLEAN, now=T0 + timedelta(seconds=400))
    assert tr.new_state is ContainmentState.NORMAL
    assert eng.state(SUBJECT) is ContainmentState.NORMAL


def test_restricted_cannot_recover_by_cooldown() -> None:
    eng = _engine()
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_5m": 8}, now=T0)
    assert eng.state(SUBJECT) is ContainmentState.RESTRICTED
    with pytest.raises(CVZTTEError) as exc:
        eng.recover(subject=SUBJECT, agent_id=AGENT,
                    method=RecoveryMethod.COOLDOWN_CLEAN, now=T0 + timedelta(hours=1))
    assert exc.value.code == ErrorCode.RECOVERY_APPROVAL_REQUIRED
    # A fresh authenticated session is sufficient for RESTRICTED.
    tr = eng.recover(subject=SUBJECT, agent_id=AGENT,
                     method=RecoveryMethod.FRESH_SESSION, now=T0 + timedelta(minutes=1))
    assert tr.new_state is ContainmentState.NORMAL


def test_quarantined_requires_admin_with_approver() -> None:
    eng = _engine()
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"bypass_attempts_5m": 3}, now=T0)
    assert eng.state(SUBJECT) is ContainmentState.QUARANTINED
    # Fresh session is not enough for QUARANTINED.
    with pytest.raises(CVZTTEError):
        eng.recover(subject=SUBJECT, agent_id=AGENT, method=RecoveryMethod.FRESH_SESSION, now=T0)
    # Admin approval without a named approver is refused.
    with pytest.raises(CVZTTEError):
        eng.recover(subject=SUBJECT, agent_id=AGENT, method=RecoveryMethod.ADMIN_APPROVAL, now=T0)
    tr = eng.recover(subject=SUBJECT, agent_id=AGENT,
                     method=RecoveryMethod.ADMIN_APPROVAL, approver="sec-admin", now=T0)
    assert tr.new_state is ContainmentState.NORMAL
    assert "APPROVER:sec-admin" in tr.reason_codes


def test_terminated_only_recovers_by_reonboard() -> None:
    eng = _engine()
    eng.kill_switch(subject=SUBJECT, agent_id=AGENT,
                    target_state=ContainmentState.TERMINATED, reason_codes=["x"], now=T0)
    for method in (RecoveryMethod.COOLDOWN_CLEAN, RecoveryMethod.FRESH_SESSION,
                   RecoveryMethod.ADMIN_APPROVAL):
        with pytest.raises(CVZTTEError) as exc:
            eng.recover(subject=SUBJECT, agent_id=AGENT, method=method,
                        approver="sec-admin", now=T0)
        assert exc.value.code == ErrorCode.RECOVERY_APPROVAL_REQUIRED
    tr = eng.recover(subject=SUBJECT, agent_id=AGENT, method=RecoveryMethod.REONBOARD, now=T0)
    assert tr.new_state is ContainmentState.NORMAL


def test_recover_normal_subject_is_error() -> None:
    eng = _engine()
    with pytest.raises(CVZTTEError) as exc:
        eng.recover(subject=SUBJECT, agent_id=AGENT, method=RecoveryMethod.ADMIN_APPROVAL,
                    approver="a", now=T0)
    assert exc.value.code == ErrorCode.RECOVERY_APPROVAL_REQUIRED


# --- transition records (§60.20) --------------------------------------------


def test_transition_record_fields() -> None:
    eng = _engine()
    eng.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 3},
                 runtime_id="rt_1", now=T0)
    records = eng.transitions(SUBJECT)
    assert len(records) == 1
    r = records[0]
    assert r.subject == SUBJECT
    assert r.agent_id == AGENT
    assert r.runtime_id == "rt_1"
    assert r.old_state is ContainmentState.NORMAL
    assert r.new_state is ContainmentState.SUSPICIOUS
    assert r.reason_codes  # non-empty
    assert r.evidence_hash.startswith("sha256:")
    assert r.capability_epoch >= 1
    assert r.at  # ISO timestamp


def test_evidence_hash_is_deterministic_and_content_bound() -> None:
    e1 = _engine()
    e2 = _engine()
    r1 = e1.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 3}, now=T0)
    r2 = e2.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 3}, now=T0)
    assert r1.evidence_hash == r2.evidence_hash
    e3 = _engine()
    r3 = e3.evaluate(subject=SUBJECT, agent_id=AGENT, features={"denials_60s": 99}, now=T0)
    assert r3.evidence_hash != r1.evidence_hash


# --- concurrency -------------------------------------------------------------


def test_concurrent_escalation_is_race_safe() -> None:
    source = EpochSource(EpochSet())
    eng = _engine(epoch_source=source)
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        barrier.wait()
        eng.evaluate(subject=f"s{i}", agent_id=f"a{i}",
                     features={"bypass_attempts_5m": 3}, now=T0)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 8 distinct subjects each escalated once -> 8 epoch bumps, no lost updates.
    assert source.current().capability_epoch == 8
    for i in range(8):
        assert eng.state(f"s{i}") is ContainmentState.QUARANTINED
