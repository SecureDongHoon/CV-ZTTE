# Confidential Query Governance

*Spec references: §45, §60.27. Phase 16.*

## What this is (and is not)

Fully Homomorphic Encryption keeps data encrypted **during computation**. It does
**not** prevent an authorized recipient from learning individual facts by combining
the *plaintext outputs* they are permitted to receive. Confidential Query Governance
addresses that residual **inference-leakage** risk on the permitted plaintext side
of the boundary — after the CAC decrypt/release gates (§42) have already been
satisfied.

> **This is NOT differential privacy.** No DP noise is added and no privacy budget
> (ε/δ) is accounted for. Calling it DP would be an overclaim the spec forbids
> (§45). A DP mechanism is provided as a *pluggable extension point* only — see
> [Differential-privacy extension point](#differential-privacy-extension-point).

Governance is **advisory over releases, fail-closed on denial**, and orthogonal to
authorization: it can never *grant* a decrypt that CAC denied; it can only further
restrict, transform, or gate a release that CAC already permitted.

## Threat model

An agent (or a colluding set of queries under one accounting scope) issues a
sequence of *individually authorized* aggregate queries whose **combination**
discloses an individual value. Canonical patterns:

- **Differencing** — `SUM(dept)` and `SUM(dept \ {alice})` differ by exactly
  Alice's salary.
- **Small aggregation groups** — a "group average" over a group of size 1 or 2 is
  effectively an individual value.
- **Repeated overlapping subsets** — many highly-overlapping aggregates triangulate
  a single record.
- **High decrypt frequency** — brute-force enumeration under a single scope.
- **Excess precision** — an unrounded mean leaks more than a coarse bucket.

## Accounting scope

Everything is accounted **per scope** = `(agent_id, dataset_id, session_id, purpose)`
(`QueryScope`). History (timestamps + subset id-sets) is kept per scope and consulted
on every evaluation. Subsets are recorded as **record identifiers, never plaintext
values** — consistent with the lineage store (see [DATA_LINEAGE](DATA_LINEAGE.md)).

## Controls (policy-driven, never hardcoded — §4)

`QueryGovernancePolicy` knobs, each defaulting to the *safe* (more restrictive or
no-op) setting:

| Knob | Effect | Denial / action code |
| --- | --- | --- |
| `min_group_size` (k) | Deny aggregate over a group smaller than k | `FHE_QUERY_PATTERN_RISK` (DENY) |
| `deny_individual_value` | Deny any `INDIVIDUAL` release outright | `FHE_QUERY_PATTERN_RISK` (DENY) |
| `max_decrypts_per_window` + `window_seconds` | Rate-limit releases per scope per rolling window | `FHE_PRIVACY_BUDGET_EXCEEDED` (DENY) |
| `differencing_min_symmetric_difference` | Deny a subset whose symmetric difference vs a prior subset is in `[1, threshold)` | `FHE_QUERY_PATTERN_RISK` (DENY) |
| `max_overlap_ratio` | Deny a subset whose overlap coefficient vs a prior subset exceeds the limit | `FHE_QUERY_PATTERN_RISK` (DENY) |
| `require_approval_below_group_size` | Gate small-group releases behind human approval (§48) | `APPROVAL_REQUIRED` (REQUIRE_APPROVAL) |
| `round_decimals` | Round/minimize released values | — (TRANSFORM) |

### Decision semantics — most-restrictive-wins, fail-closed

`QueryGovernor.evaluate()` is **read-only** and returns a `GovernanceDecision`
(`ALLOW` / `DENY` / `TRANSFORM` / `REQUIRE_APPROVAL`). Checks are applied in
severity order and the **first** that fires wins, so a query that triggers both a
group-size denial and an approval gate is **denied** (the more restrictive
outcome). Any denial carries a stable `ErrorCode`; a `DENY` never degrades to an
implicit allow (§4.20).

`governed_release()` evaluates and then records the query **only if it was not
denied**, so denied attempts do not consume budget or pollute the differencing
history. `minimize(values, decision)` applies a `TRANSFORM` decision's rounding to
the released values.

## Differential-privacy extension point

`cvztte.confidential_query.dp` defines the `NoiseMechanism` protocol. The default
`NoDP` is the identity: it adds no noise and does no accounting, and reports
`accounts_privacy = False`. `QueryGovernor.is_differential_privacy()` returns
`True` **only** when a mechanism with `accounts_privacy = True` — i.e. real
calibrated noise *and* an ε/δ accountant — is plugged in. Until such a mechanism is
implemented, the governor truthfully reports that it is not providing DP.

## What this does not claim

- It is **not** authorization — CAC decides who may decrypt (§42).
- It is **not** a confidentiality guarantee about the FHE computation itself — that
  is the ciphertext/context/key custody model (Phases 14–15).
- It is **not** differential privacy (§45), until a real DP mechanism is installed.
