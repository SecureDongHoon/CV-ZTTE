# Containment & Dynamic Capability Decay (Phase 10)

Detecting a compromised or evasive agent is not enough — the control plane must
*change the agent's effective authority* in response, and do so in a way that can
only ever remove authority, never grant it (spec §25–§27, §60.18–§60.20). Phase
10 implements the first-class containment state machine and the capability decay
it drives.

## State machine (`cvztte/containment/`)

Ordered ladder, higher = less authority (§25):

```
NORMAL  ->  SUSPICIOUS  ->  RESTRICTED  ->  QUARANTINED  ->  TERMINATED
```

- **`model.py`** — `ContainmentState` (reused from the Decision Token model so a
  token records the state it was authorized under), `STATE_ORDER`/`severity()`/
  `more_severe()`, the `CapabilityAttributes` classification, the per-state
  capability *ceiling* (`_ceiling_allows`), `effective_capabilities(...)`, and
  the auditable `ContainmentTransition` record.
- **`policy.py`** — `ContainmentThresholds` (a frozen, **config-controlled**
  dataclass; the engine never hardcodes thresholds, §60.18) and `ThresholdPolicy`,
  which maps a behavior/evasion feature map to the highest warranted state. It
  **never** returns `TERMINATED` — termination is reserved for a sandbox-escape
  signal or an explicit administrator kill.
- **`engine.py`** — `ContainmentEngine`, the per-subject state machine.

## Escalation is escalate-only (§60.18)

`evaluate(subject, agent_id, features, ...)` assesses the warranted state from
the configured policy and moves the subject to `more_severe(current, warranted)`.
Clean features never lower a state — de-escalation is exclusively via `recover`.
Each escalation records a `ContainmentTransition` and advances the capability
epoch.

## Dynamic capability decay (§60.19)

Effective capability is the intersection, tightened by the containment ceiling:

```
effective = delegated ∩ enterprise_policy ∩ runtime_profile ∩ ceiling(state)
```

Because the ceiling is applied to an already-intersected set, containment can
only remove capabilities (§26). Reference ceilings:

| State       | Ceiling                                                        |
|-------------|----------------------------------------------------------------|
| NORMAL      | everything the intersection allows                             |
| SUSPICIOUS  | drop optional high-risk capabilities                           |
| RESTRICTED  | read-only: no writes, external network, secret access, subagents |
| QUARANTINED | diagnostic/status only                                         |
| TERMINATED  | no runtime authority                                           |

The ceilings are monotone: each state's allowed set is a subset of the state
below it (test-enforced).

## Capability epoch (§27)

Every transition (escalation, kill, recovery) atomically increments the
`capability_epoch` on a shared `EpochSource`. The Phase 8 Decision Token
validator rejects any token whose epochs no longer match (step 6), so escalation
immediately invalidates in-flight execution capabilities. **This reference bumps
a single global capability epoch**, so one subject's transition over-invalidates
tokens for all subjects — coarse but strictly fail-closed (it can only revoke
early, never extend authority). A production build would key epochs per
subject/capability class.

## Kill switch (§27)

`kill_switch(subject, target_state, ...)` forces `QUARANTINED` or `TERMINATED`
(any other target is rejected, fail-closed). It is escalate-only: a weaker target
never de-escalates an already-more-contained subject.

## Recovery is explicit, method-gated, audited (§60.19/§60.20)

`recover(subject, method, approver=...)` de-escalates to `NORMAL` only when the
method is sufficient for the current state; otherwise it raises
`RECOVERY_APPROVAL_REQUIRED` and leaves the state unchanged. No trivial
time-based full restoration above SUSPICIOUS.

| Current state | Accepted recovery methods                                   |
|---------------|-------------------------------------------------------------|
| SUSPICIOUS    | cooldown + clean evidence, fresh session, admin, re-onboard |
| RESTRICTED    | fresh authenticated session/delegation, admin, re-onboard   |
| QUARANTINED   | admin approval (named approver), re-onboard                 |
| TERMINATED    | re-onboarding on a new runtime only — no in-place recovery  |

## Transition record (§60.20)

Each `ContainmentTransition` carries `subject`, `agent_id`, `runtime_id`,
`old_state`, `new_state`, `reason_codes`, a deterministic `evidence_hash`
(`commit(Domain.CONTAINMENT_TRANSITION, …)` — time-independent, verifier-
checkable), the resulting `capability_epoch`, and the timestamp.

## Fail-closed summary

- Assessment never lowers protection; missing/clean features cannot de-escalate.
- Insufficient recovery method → `RECOVERY_APPROVAL_REQUIRED`, no state change.
- Containment can only remove authority; nothing here grants a capability the
  subject did not already hold.
- Every transition advances the capability epoch, revoking outstanding tokens.
