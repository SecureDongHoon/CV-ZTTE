# Shadow-Mode Reporting

Spec reference: §60.15.

Shadow mode is how an agent is rolled toward enforcement without risk. While it
runs in `OBSERVE` (or `WARN`), the platform records what enforcement **would**
have done without blocking anything — `OBSERVE` is explicitly not security
enforcement — and aggregates it into a report that tells operators what a switch
to `ENFORCE` would break.

Module: `cvztte/onboarding/shadow.py`.

## Observations

Each observed action becomes a `ShadowObservation`:

- `action_hash` — the canonical action;
- `outcome` — the `ModeOutcome` enforcement would have produced
  (`WOULD_ALLOW` / `WOULD_DENY` under OBSERVE; `WARN_ALLOW` under WARN);
- `bypass_attempt` — the action tried to reach a resource directly (un-mediated);
- `missing_policy` — no enterprise policy matched the action;
- `unknown_destination` — an external destination not on any allowlist;
- `adapter_present` — a semantic adapter supplied context;
- `false_positive_candidate` — an operator flagged a `WOULD_DENY` as a likely
  false positive.

## Report (§60.15)

`ShadowAggregator.report()` produces a `ShadowReport` covering the fields the
spec asks for:

- **false-positive review candidates** — `false_positive_candidates`;
- **missing policy** — `missing_policy`;
- **normal-behavior baseline** — `would_allow` vs. total;
- **unknown destinations** — `unknown_destinations` (sorted, de-duplicated);
- **adapter coverage** — `adapter_coverage` (fraction with adapter context);
- **bypass attempts** — `bypass_attempts`.

`enforce_would_block` = `would_deny + warn_allow` is the count of observed
actions a switch to `ENFORCE` would newly block — the key rollout signal.

## Rollout

The recommended progression (§60.15):

```
OBSERVE -> WARN -> high-confidence hard-rule enforcement
        -> high-risk enforcement -> broader enforcement
```

The aggregator is a **reporting aid only**: it never authorizes and never
relaxes a control.
