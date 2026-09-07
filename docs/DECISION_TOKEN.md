# Decision Token v3 (Phase 8)

The Decision Token is a short-lived, single-use **execution capability**
(spec §31, §60.11). After the control plane runs its checks (ML-DSA / OPA /
gnark / behavior / Judge / EZKL) and reaches a decision, the **Decision Token
Authority** mints a token that binds *one* canonical action to *one*
agent/runtime/session, *one* enforcement audience, and a snapshot of the current
epochs. An enforcement point executes the action only after independently
validating that token and re-checking the exact match.

## Modules (`cvztte/decision/`)

| Module | Role |
| --- | --- |
| `model.py` | `DecisionToken` (all §60.11 fields), `SignedDecisionToken` (token + MAC), `EpochSet`, `TokenChecks`, `ContainmentState`, `TokenDecision` |
| `mac.py` | Gateway-only keyed MAC (HMAC-SHA256, domain-separated via `Domain.DECISION_TOKEN`), constant-time verify |
| `authority.py` | `DecisionTokenAuthority` — the **only** minter and **only** holder of the MAC key |
| `replay.py` | `TokenUseTracker` / `InMemoryTokenUseTracker` — single-use / max-uses tracking |
| `validator.py` | `DecisionTokenValidator` (the real `enforcement.common.DecisionValidator`), `EpochSource`, `PresentedTokenStore` |

## Token fields (§60.11)

`token_version=3`, `decision_id`, `request_id`, `agent_id`, `runtime_id`,
`session_id`, `action_hash`, `action_type`, `target_constraint`,
`operation_constraint`, `payload_hash`, `policy_hash`, `risk_level`,
`containment_state`, `decision`, `issued_at`, `not_before`, `expires_at`,
`max_uses` (default 1), `nonce` (128-bit), `audience`, the five epochs
(`agent_revocation` / `runtime_revocation` / `policy` / `capability` / `risk`),
and `checks`. Defaults are single-use and a very short TTL (30 s).

## Gateway-only MAC key

Authenticity is a keyed MAC over the token's RFC 8785 canonical bytes, computed
with a key held **only** by the authority and the enforcement-side validator
(spec §31). The key never enters an agent context, an LLM prompt, a log, or an
audit record. `DecisionTokenAuthority` rejects a key shorter than 32 bytes.
Domain separation (`Domain.DECISION_TOKEN`) means a token MAC can never be
reinterpreted for another object class (§4.11 family).

## Validation flow (enforcement side, §16 steps 4-6)

The broker observes the action, recomputes the ActionHash, and calls the
validator. Because the Phase 7 `DecisionValidator` protocol passes only
`(action, action_hash, binding, audience)`, the presented token is retrieved
from a `PresentedTokenStore` keyed by `(audience, action_hash)` — modeling the
agent presenting, at the enforcement point, the exact token it was issued. The
store is **not** a mint. The validator then enforces, failing closed (§4.20) at
each step with a specific error code:

1. token present — else `DECISION_TOKEN_INVALID` (this is the bypass-attempt
   path: reaching a broker with no matching token is denied);
2. MAC valid (constant time) — else `DECISION_TOKEN_INVALID`;
3. `token_version == 3`, action-hash and action-type bind — else
   `FINAL_ACTION_BINDING_FAILED` / `DECISION_TOKEN_INVALID`;
4. agent/runtime/session bind to the observed request — else
   `DECISION_TOKEN_INVALID`;
5. audience matches — else `DECISION_TOKEN_AUDIENCE_MISMATCH`;
6. `not_before <= now < expires_at` — else `DECISION_TOKEN_EXPIRED`;
7. epochs equal the current epochs — else `DECISION_TOKEN_EPOCH_STALE`;
8. exact target/operation/payload constraints — else
   `FINAL_ACTION_BINDING_FAILED`;
9. record one use (≤ `max_uses`) — else `DECISION_TOKEN_REPLAY`.

Only then is an `AuthorizedDecision` returned; the broker still re-checks the
exact-match constraints as defense in depth, and executes only on `ALLOW`.

## Epochs (§27)

`EpochSource` holds the current epochs. Bumping an epoch (revocation, policy
change, capability decay, risk change — driven by Phase 10) advances the value
and **invalidates every in-flight token** minted under the older epoch, which
then fails with `DECISION_TOKEN_EPOCH_STALE`. This is how containment/capability
changes take effect immediately without recalling tokens.

## Invariants exercised by tests

`tests/integration/test_decision_token.py` runs the real validator through a
real `FileBroker`: happy-path execute + audit; single-use replay rejection;
expiry; stale-epoch; MAC tamper; **cross-action** (a token for action A cannot
execute action B, §4.11); binding mismatch; DENY not executed; no-token bypass;
audience mismatch. Replay is tracked, and no failure path ever executes the
effect.
