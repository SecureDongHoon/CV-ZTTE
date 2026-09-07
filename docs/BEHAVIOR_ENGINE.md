# Stateful Behavior Engine (Phase 9)

Single-action authorization is insufficient (spec §24): an agent can look
individually compliant while a *sequence* reveals probing, an exfiltration ramp,
destination switching after denial, or unusual fanout. The Behavior Engine keeps
per-scope rolling state so that sequence is visible to risk scoring, the
containment state machine (Phase 10), and high-risk Judge/proof flows.

## Scope (`cvztte/behavior/model.py`)

State is partitioned by `BehaviorScope` = `(agent_id, session_id, runtime_id,
delegation_id?)` (spec §24). Scopes are fully isolated.

## Event kinds — no double counting (§60.6)

`BehaviorEventKind` distinguishes `PROPOSED`, `DENIED`, `BYPASS_ATTEMPTED`,
`EXECUTED`, `FAILED`. This distinction is a security requirement: a cooperative
*proposal* and its eventual *execution* must not be counted as two independent
attacks. Therefore:

- **Windowed "did" features** (`actions_last_10s/60s/5m`, `sensitive_reads_last_5m`)
  count `EXECUTED` events only.
- **"Attempted/blocked" features** count `DENIED` (`policy_denials`),
  `BYPASS_ATTEMPTED` (`bypass_attempts`), and privilege-escalation *attempts*
  regardless of outcome.
- Byte/resource/destination/destructive/fanout effects are attributed to
  `EXECUTED` only.

## Features (§60.6 minimum, all present)

`actions_last_60s`, `sensitive_reads_last_5m`, `bytes_read`, `bytes_written`,
`external_bytes`, `unique_resources`, `secret_access_count`, `policy_denials`,
`privilege_escalation_attempts`, `new_external_destination`,
`destructive_action_count`, `agent_message_fanout` — plus `actions_last_10s`,
`actions_last_5m`, and `bypass_attempts`. Rolling windows are 10s / 60s / 5m.

## Canonical snapshot + hash

`BehaviorSnapshot` is versioned and hashable via `Domain.BEHAVIOR_STATE`. The
hash **excludes** the wall-clock `computed_at`, so identical behavioral content
hashes identically and a verifier can check equality when the snapshot is bound
into a high-risk Judge decision or ZK proof (spec §24). The hash changes when the
content changes (e.g. events aging out of a window).

## Race-safe transitions

Each scope has its own reentrant lock. `record()` and `snapshot()` are atomic.
`BehaviorEngine.transition(scope)` exposes the scope lock as a context manager so
a caller can perform the `snapshot -> evaluate -> reserve/execute -> event-append`
sequence (§60.6) without another writer interleaving. A concurrency test drives
many threads to confirm counters are consistent.

## Consumers (later phases)

Phase 10 (containment/capability decay) correlates these features against
OPA/config thresholds to drive `NORMAL -> SUSPICIOUS -> RESTRICTED -> QUARANTINED
-> TERMINATED` and bumps the capability epoch. The snapshot hash binds behavior
into the Judge (Phase 11) and EZKL (Phase 12) high-risk paths.

## Tests

`tests/unit/test_behavior.py`: windowing; proposal/execution not double-counted;
denial/bypass/attempt counters; cumulative effect features; destination dedup;
snapshot-hash stability + content sensitivity; scope isolation; concurrent-record
race safety; transition lock.
