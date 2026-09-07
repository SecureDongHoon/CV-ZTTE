# Dynamic Capability Decay

Spec references: §4.13–§4.14 (escalation reduces authority; decay is monotonic
within an active episode), §47 (CAC permissions decayed by containment). Code:
`cvztte/containment/model.py`, `cvztte/cac/permissions.py`. See also
`docs/CONTAINMENT_ENGINE.md`, `docs/CONTAINMENT.md`.

## The intersection rule

Effective authority is never widened by any single grant — it is the
**intersection** of four independent sources, so the least-privileged one wins:

```
effective = delegated ∩ enterprise_policy ∩ runtime_profile ∩ containment_ceiling
```

The containment ceiling is the only term that changes at runtime as behavior
degrades; because it is intersected (never unioned), a higher containment state
can only *remove* capabilities. There is no code path in which a more severe
containment state yields more authority (invariant §4.13).

## CAC ceilings (`cvztte/cac/permissions.py`)

`CACPermission` is a three-way split — `READ_PLAINTEXT`, `COMPUTE_ON_CIPHERTEXT`,
`DECRYPT_RESULT` (`permissions.py:24-27`). The per-state ceiling
`_CONTAINMENT_CEILING` (`permissions.py:44-52`):

| State | CAC ceiling |
|---|---|
| NORMAL | all three |
| SUSPICIOUS | compute only (no decrypt, no read-plaintext) |
| RESTRICTED | compute only |
| QUARANTINED | none |
| TERMINATED | none |

`effective_cac_permissions(granted, state) = granted & ceiling_for(state)`, with a
fail-closed default of the empty set for unknown states (`permissions.py:55-64`).
This is where "compute never implies decrypt" (§42) survives escalation: even a
subject *granted* `DECRYPT_RESULT` loses it at SUSPICIOUS and above.

## Monotonicity within an episode

Because containment state is escalate-only during an active episode
(`ContainmentEngine.evaluate` returns `None` unless the target is strictly more
severe — `engine.py:245-248`) and the ceiling table is monotonically
non-increasing in severity, effective capability can only shrink until an
explicit, audited recovery lowers the state (`recover()`,
`docs/CONTAINMENT_ENGINE.md`). Decay does not silently reverse on its own.

## Epoch coupling

A capability change is only meaningful if already-minted authority is revoked.
Every containment transition bumps the shared `capability_epoch`
(`engine.py:174-180`), so any Decision Token minted under the old (looser)
ceiling is rejected with `DECISION_TOKEN_EPOCH_STALE` at validation
(`cvztte/decision/validator.py:157-161`). Decay of the *ceiling* and revocation
of *outstanding tokens* therefore happen atomically together.
