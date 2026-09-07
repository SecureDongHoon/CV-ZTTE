# Agent Onboarding, Conformance & Deployment Modes

Spec references: §33, §60.14, §60.15, §60.16.

This document describes how an agent runtime is onboarded, how the platform
verifies that enforcement actually works for it before it goes live, and how the
four deployment modes turn a security decision into an actual outcome.

Module: `cvztte/onboarding/`.

---

## 1. `AgentRuntimeProfile` — the 12 mandatory fields (§60.14)

`cvztte/onboarding/profile.py` defines the enterprise declaration an agent is
onboarded with. Every field in §60.14 is present:

| # | Field | Meaning |
|---|-------|---------|
| 1 | `agent_id`, `runtime_id` | Agent + runtime identity |
| 2 | `framework` | Framework / runtime type |
| 3 | `delegation_template`, `policy_hash` | Delegation / policy template |
| 4 | `max_risk_level` | Risk profile (0–4) |
| 5 | `sandbox` | Sandbox profile (isolation, egress, fs confinement) |
| 6 | `tool_policy` | Tool / MCP channel policy |
| 7 | `network_policy` | Network channel policy |
| 8 | `filesystem_policy` | Filesystem channel policy |
| 9 | `secret_policy` | Secret channel policy |
| 10 | `output_policy` | Output channel policy |
| 11 | `semantic_adapter` | Installed adapter (or `None`) |
| 12 | `activation_state` | Lifecycle state |

Each channel is a `ChannelPolicy` with `mediated` (a broker/gateway mediates it)
and `deny_direct` (un-mediated access is refused in the reference deployment).

### Mandatory controls (fail-closed)

`mandatory_controls_present()` returns `(present, missing)`. Controls are present
only when **every** protected channel is `mediated` and `deny_direct`, and the
sandbox has `no_unrestricted_egress`. An **absent semantic adapter is allowed** —
it is the unknown-framework fallback (boundary-only context, §33) and does **not**
lower enforcement. Missing sandbox egress control or an un-mediated channel does.

---

## 2. Onboarding lifecycle (§33, 9 steps)

`ActivationState`: `REGISTERED → PROFILED → CONFORMANCE_PASSED → ENFORCED`
(plus `QUARANTINED`, `DISABLED`).

`OnboardingService` (`service.py`) drives the 9 spec steps:

1–7. `register(profile)` records identity, framework, policy/delegation, risk,
sandbox, channel policies, adapter → state becomes `PROFILED`.
8. `run_conformance(profile)` runs the live conformance harness.
9. `activate(profile, actor, is_admin)` — **admin-only, audited** — gates on two
fail-closed conditions:
   - mandatory controls present, else `ACTIVATION_BLOCKED`;
   - conformance passes, else `CONFORMANCE_FAILED`.

Only on success does the profile advance to `ENFORCED`. **An agent that fails
either gate never silently becomes active.**

---

## 3. Conformance harness (§33, §60.14)

`ConformanceHarness` (`conformance.py`) wires a **real** `FileBroker` over a
throwaway workspace to the real Decision Token authority/validator/epoch source
and the real containment engine — no mocks on the acceptance path — and runs:

| Check | Verifies |
|-------|----------|
| `direct_bypass_blocked` | An un-tokened request is denied |
| `mediated_happy_path` | An approved, exact-bound token executes |
| `mediated_deny` | A DENY token does not execute |
| `decision_token_exact_binding` | A token for action A cannot execute action B (§4.11) |
| `adapter_context` | A declared adapter is recorded (absent = allowed fallback) |
| `kill_switch` | An admin kill advances the capability epoch and rejects in-flight tokens |

The harness never weakens a control to make a check pass. Any failed mandatory
check blocks activation.

---

## 4. Deployment modes (§33, §60.15)

`DeploymentMode` and the `apply_mode(mode, base_allow) → ModeOutcome` mapping
(`mode.py`) turn a security verdict into an actual outcome:

| Mode | base ALLOW | base DENY | Enforces? |
|------|-----------|-----------|-----------|
| `OBSERVE` | `WOULD_ALLOW` | `WOULD_DENY` | **No** (not security enforcement) |
| `WARN` | `ALLOW` | `WARN_ALLOW` (permitted, flagged) | No |
| `ENFORCE` | `ALLOW` | `DENY` | Yes |
| `QUARANTINE` | `DENY` | `DENY` | Yes |

`OBSERVE` is explicitly **not** security enforcement: it only reports and never
blocks or executes. `is_enforcing()` is true only for `ENFORCE`/`QUARANTINE`.

### Mode changes are admin-only and audited

`ModeController.set_mode(new, actor, is_admin)` refuses a non-admin caller
fail-closed (`MODE_CHANGE_FORBIDDEN`) and appends an `AuditStage.ADMIN` event to
the hash-chained audit log for every accepted change.

Recommended rollout (§60.15): `OBSERVE → WARN → hard-rule enforcement →
high-risk enforcement → broader enforcement`. See [SHADOW_MODE.md](SHADOW_MODE.md).

---

## 5. Kill switch scope (§60.16)

The containment engine's kill switch (Phase 10) forces `QUARANTINED`/`TERMINATED`
and atomically advances the capability epoch, which invalidates every in-flight
Decision Token minted under the older epoch. The conformance `kill_switch` check
demonstrates this end to end: after a kill, the presented token is rejected as
`DECISION_TOKEN_EPOCH_STALE` and the effect does not occur.
