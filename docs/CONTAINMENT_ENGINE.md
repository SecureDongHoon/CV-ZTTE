# Containment Engine

Spec references: §4.13–§4.15 (escalation reduces authority; monotonic decay;
audited recovery), §60.6 (behavior features). Code: `cvztte/containment/`
(`engine.py`, `policy.py`, `model.py`). See also `docs/CONTAINMENT.md`,
`docs/BEHAVIOR_ENGINE.md`, `docs/DYNAMIC_CAPABILITY_DECAY.md`,
`docs/KILL_SWITCH.md`.

## State machine

`ContainmentState` (`cvztte/decision/model.py:32-40`) is an escalate-only ladder:

```
NORMAL → SUSPICIOUS → RESTRICTED → QUARANTINED → TERMINATED
```

`STATE_ORDER` (`model.py:27-33`) defines severity. `ContainmentEngine.evaluate`
computes `target = more_severe(current, warranted)` and returns `None` when the
target is not strictly more severe than the current state
(`engine.py:245-248`) — **features never de-escalate**. Only explicit, audited
recovery moves a subject back down.

## Subject keying

The containment subject is `f"{agent_id}|{runtime_id}|{session_id}"`
(`containment_subject`, `cvztte/control_plane/plane.py:70-72`). A new session is a
new subject — but this does **not** grant a bypass, because (a) RESTRICTED+
ceilings block `new_subagent` capabilities and (b) every transition bumps a
**global** capability epoch that invalidates all in-flight tokens (see
Quarantine propagation). Finer per-subject epoch keying is a documented
production follow-up (`engine.py:12-18`).

## Evasion evidence → transitions (thresholds are policy, not hardcoded)

`ThresholdPolicy.assess(features)` (`policy.py:53-77`) reads the behavior-engine
feature keys `denials_60s`, `bypass_attempts_5m`, `denials_5m`,
`secret_probe_count`, and a set of boolean `quarantine_signal_flags`. Thresholds
are defaults on the **frozen** `ContainmentThresholds` dataclass
(`policy.py:21-39`), injected into the engine — the engine only *applies* them:

| Transition | Trigger (default) |
|---|---|
| NORMAL → SUSPICIOUS | `denials_60s ≥ 3` or `bypass_attempts_5m ≥ 1` |
| → RESTRICTED | `denials_5m ≥ 8` or `bypass_attempts_5m ≥ 2` |
| → QUARANTINED | `bypass_attempts_5m ≥ 3` or `secret_probe_count ≥ 3` |
| → QUARANTINED (forced) | any of `quarantine_signal_flags` set: `sensitive_read_to_egress_sequence`, `secret_exfiltration_attempt` |

`assess()` never returns `TERMINATED` — that is reserved for the kill switch
(`policy.py:8-11`). Because thresholds live in the injected dataclass, an operator
tunes containment via configuration, not code edits (invariant: thresholds are
config/policy-controlled).

## Method signatures (`cvztte/containment/engine.py`)

- `evaluate(*, subject, agent_id, features, runtime_id=None, reason_codes=None, now=None) -> ContainmentTransition | None` (`engine.py:227`)
- `state(subject) -> ContainmentState` (`engine.py:141`)
- `recover(*, subject, agent_id, method, approver=None, runtime_id=None, now=None) -> ContainmentTransition` (`engine.py:299`)
- `kill_switch(*, subject, agent_id, target_state, reason_codes, runtime_id=None, now=None) -> ContainmentTransition` (`engine.py:260`)
- `__init__(*, policy=None, epoch_source=None, suspicious_cooldown_seconds=300.0)` (`engine.py:104`)

## Quarantine propagation (the shared epoch)

Every transition is committed through `_commit_transition`, which calls
`_bump_capability_epoch()` (`engine.py:174-180, 210`): under a lock it reads the
shared `EpochSource`, increments `capability_epoch`, and sets it back. The
`DecisionTokenValidator` shares that same `EpochSource`, so at validation step 6
`token.epochs != EpochSource.current()` raises `DECISION_TOKEN_EPOCH_STALE`
(`cvztte/decision/validator.py:157-161`). Brokers/proxies therefore enforce
quarantine transitively: they call the validator, and a bumped epoch makes every
previously minted token stale — demonstrated end to end in the conformance
kill-switch check (`cvztte/onboarding/conformance.py:210-229`), where after
`kill_switch(...)` the file broker rejects the action and nothing is written.

The mint path itself also blocks contained subjects:
`blocks_new_consequential_tokens()` is True for QUARANTINED/TERMINATED
(`model.py:119-121`), gated in `ControlPlane.evaluate` (`plane.py:230-235`) and
re-checked at approve/mint time (`plane.py:341-346`).

## Recovery (never self-service)

`RecoveryMethod` (`engine.py:47-57`): `COOLDOWN_CLEAN`, `FRESH_SESSION`,
`ADMIN_APPROVAL`, `REONBOARD`, gated per state by `_RECOVERY_ALLOWED`
(`engine.py:63-83`): SUSPICIOUS accepts all four; RESTRICTED excludes
`COOLDOWN_CLEAN`; QUARANTINED accepts only `ADMIN_APPROVAL`/`REONBOARD`;
TERMINATED accepts only `REONBOARD`. `recover()` raises
`RECOVERY_APPROVAL_REQUIRED` for an insufficient method, requires cooldown elapse
for `COOLDOWN_CLEAN`, requires a named `approver` for `ADMIN_APPROVAL` and for
QUARANTINED+, and commits an audited transition with an evidence hash
(`engine.py:299-359`). An agent cannot self-recover: recovery is exposed only via
`AdminPlane.reset_containment`, which calls `self._authz.require(principal)` and
sets the admin principal as approver (`cvztte/control_plane/planes.py:153-162`);
the HTTP route requires an admin header (`http_api.py:143-159`).
