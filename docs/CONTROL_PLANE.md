# Control Plane (Phase 17 — Full Integration)

*Spec references: §17, §54, §60.29. Companion controls: §11 (freshness), §13
(policy), §26–§28 (containment & approval), §35–§47 (CAC), §60.24 (lineage),
§60.26 (release gate), §60.30 (error taxonomy).*

The Control Plane is the integration seam that ties the phase-by-phase CV-ZTTE
library into **one fail-closed authorization pipeline** and exposes it through
two separated surfaces — an **agent plane** and an **admin plane** (§60.29). It
introduces no new cryptography or policy; it *composes* the already-tested
primitives in a fixed order and refuses to let any security error become an
implicit ALLOW (§4.20).

## Components

| Module | Responsibility |
| --- | --- |
| `plane.py` — `ControlPlane` | The orchestrator. Runs the evaluate → mint pipeline, parks approvals, and drives containment admin. |
| `planes.py` — `AgentPlane` / `AdminPlane` | The §60.29 plane separation. An agent holds only an `AgentPlane`; admin operations live on a distinct object gated by `AdminAuthorizer`. |
| `approval.py` — `ApprovalStore` | Stateful, TTL-bounded approval workflow (PENDING → GRANTED/DENIED). Replaces the earlier boolean gate. |
| `replay.py` — `ReplayGuardProtocol` / `InMemoryReplayGuard` | Freshness seam (§11): single-use nonces + monotonic sequence. Redis guard in production. |
| `cac_service.py` — `CACService` | The CAC surface: encrypt / compute / decrypt-request / result, wiring in the permission guard, lineage, query governance and the release gate. |
| `http_api.py` — `ControlPlaneAPI` / `make_server` | Dependency-free stdlib HTTP router mapping §60.29 routes onto the planes, with fail-closed `CVZTTEError` → HTTP status mapping. |

## The evaluate pipeline (`ControlPlane.evaluate`)

Every consequential action runs the same ordered gauntlet. **Any step may only
subtract authority; none can add it.** A failure at any step raises a
`CVZTTEError` — never a silent ALLOW.

1. **Identity / integrity / freshness** — `verify_request` checks the ML-DSA
   signature, the action-hash binding, expiry, and the optional policy-hash pin.
2. **Replay / sequence** — an atomic `check_and_commit`: a reused nonce is
   `NONCE_REPLAY`; a non-monotonic per-session sequence is `SEQUENCE_INVALID`.
3. **Session** — the session must be active and bound to the same agent/runtime.
4. **Containment** — a RESTRICTED / QUARANTINED / TERMINATED subject cannot mint
   a new consequential token (§26). Containment can only remove authority.
5. **Policy / risk** — OPA authorizes and supplies the risk tier. Risk **is**
   `PolicyDecision.risk_level`; there is no separate risk engine. A hard DENY is
   final (§13).
6. **Approval** — if policy sets `require_human_approval` *or* the risk tier is
   at/above `require_approval_from_tier` (default L4), the decision is parked
   `PENDING_APPROVAL` and **no executable token is minted** until an admin grants
   it (§28). Approval never overrides containment — containment is re-checked at
   mint time inside `approve()`.
7. **Mint + present** — the sole `DecisionTokenAuthority` mints a short-lived,
   single-use, execution-bound token under the **current epoch snapshot**
   (`containment.current_epochs()`) and presents it at the enforcement audience.

`evaluate_execute` runs the same pipeline and then, only on ALLOW, hands the
token to an `EnforcementBroker` that **independently re-observes** the operation
and re-validates the token — so a token minted for action A cannot execute
action B (§4.11).

## Why the shared EpochSource matters

`ContainmentEngine`, `DecisionTokenAuthority`, and the token validator share one
`EpochSource`. On any containment escalation the global `capability_epoch`
increments atomically, which **invalidates every outstanding token** bound to
the older epoch. The Control Plane mints under `containment.current_epochs()`, so
a token minted a microsecond before a quarantine is dead the instant the
quarantine lands. This wiring is the linchpin of the "containment can only remove
authority" invariant and must not be broken.

## Plane separation (§60.29)

The admin and agent planes **MUST be separated**. We realize this as *object
capability*, not a request flag:

- An agent is handed an `AgentPlane`. It literally has no method for agent
  registration, key rotation/revocation, policy activation, FHE-registry
  activation, containment kill-switch/reset, or approval grant/deny.
- Those operations live only on `AdminPlane`, and **every one** of its methods
  calls `AdminAuthorizer.require(principal)` first, failing closed with
  `ENFORCEMENT_DENIED` for a non-admin principal.

Over HTTP the same split holds: admin routes require the `X-CVZTTE-Admin`
principal header (still gated by `AdminAuthorizer`); a missing/invalid principal
is `ENFORCEMENT_DENIED`. The reference server authenticates the admin principal
by header for demonstration — production terminates TLS and authenticates the
admin plane with real credentials on a separate listener.

## CAC surface (`CACService`)

`CACService` composes the Phase 14–16 CAC primitives into the CAC endpoints and
wires in the three cross-cutting Phase 17 controls, fail-closed at each step:

- **Permission guard at the current containment state** (§42, §47): every op is
  gated by `READ_PLAINTEXT` / `COMPUTE_ON_CIPHERTEXT` / `DECRYPT_RESULT` *after*
  containment decay, and **compute never implies decrypt**.
- **Data lineage** (§60.24): every ciphertext, result, decrypt request, and
  release is recorded — **hashes/IDs only, never plaintext** — so a released
  value is fully traceable to its inputs.
- **Confidential Query Governance** (§45) **+ release gate** (§60.26) at decrypt
  time: inference-leakage limits, result-substitution detection, and an
  approval requirement for restricted classifications. If approval is required
  and not present, the decrypt request is parked `PENDING_APPROVAL` and **no
  plaintext is produced**.

The service performs no identity/policy/token authorization itself — the
`ControlPlane` runs that pipeline first (§35, §40). It never persists a secret
key or plaintext beyond the released, governed result value.

## HTTP routes (§60.29)

| Method & path | Plane | Handler |
| --- | --- | --- |
| `GET  /health/live` | — | liveness |
| `GET  /health/ready` | — | dependency readiness (503 if not wired) |
| `POST /v3/sessions` | agent | open a session for a registered agent |
| `POST /v3/actions/evaluate` | agent | run the pipeline; ALLOW / DENY / PENDING_APPROVAL |
| `POST /v3/actions/evaluate-execute` | agent | evaluate then mediate (requires a configured broker) |
| `GET  /v3/decisions/{id}` | agent | fetch a prior decision (public view) |
| `GET  /v3/agents/{subject}/containment` | agent | containment state + transitions |
| `POST /v3/approvals/{decision_id}` | **admin** | grant a parked approval and mint |
| `POST /v3/agents/{subject}/quarantine` | **admin** | kill switch (§27) |
| `POST /v3/agents/{subject}/containment/reset` | **admin** | method-gated recovery (§27, §60.19) |

CAC endpoints (`/v3/cac/encrypt`, `/compute`, `/decrypt-requests`,
`/decrypt-requests/{id}/approve`, `/v3/cac/results/{id}`) are served by
`CACService` and require a configured FHE broker (native OpenFHE); without one
they fail closed with `SECURITY_DEPENDENCY_UNAVAILABLE`.

### Error mapping (fail-closed)

`CVZTTEError` → HTTP status is stable (`http_api.status_for`): schema/hash
errors → 400, oversized body → 413, unknown agent/key/session → 404,
dependency-unavailable → 503, **everything else (deny/containment/token/policy)
→ 403**. An unknown route is `404 SCHEMA_INVALID`, a malformed body is `400
SCHEMA_INVALID`, and any unexpected exception is a generic `500` with no detail —
internals, secrets, plaintext, and key material are never leaked to the client.

## What the Control Plane deliberately does **not** do

- It does not weaken any security property to "make integration work."
- It does not let an agent choose the VK / model / circuit / policy / provider /
  crypto parameters — those are registry- and admin-controlled.
- It does not treat OBSERVE mode as enforcement, and mode changes remain
  admin-only and audited.
- It does not claim FHE is authorization, nor that the query governor is
  differential privacy unless real DP noise/accounting is configured (§45).
