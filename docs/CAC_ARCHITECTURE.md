# CAC — Confidential Agent Collaboration (Architecture)

Spec references: §35–§47.

CAC lets approved agents compute over sensitive data **without** the plaintext
being disclosed to compute-only agents. It is built on real OpenFHE CKKS and is
subject to the *entire* normal CV-ZTTE pipeline — identity, policy,
authorization, behavior, containment, Decision Token, audit (§35). FHE is **not**
authorization; it only removes the need to expose plaintext to a compute agent.

Module: `cvztte/cac/` (Python control plane) + `services/fhe-broker/` (native C++
broker). This document covers the Phase 14 foundations; threshold decryption
(§41) is Phase 15.

---

## Permission model (§35, §42, §47)

Three **separate** capabilities — critically, compute authority does **not**
imply decrypt (§42):

| Permission | Meaning |
|------------|---------|
| `READ_PLAINTEXT` | May see the underlying plaintext |
| `COMPUTE_ON_CIPHERTEXT` | May run approved programs over ciphertext |
| `DECRYPT_RESULT` | May obtain plaintext of an approved result |

Reference role grants (`REFERENCE_ROLE_GRANTS`): data owner = all; analytics
agent = compute only; security supervisor = decrypt approved results;
unauthorized = none.

**Containment ceilings (§47)** decay CAC capability by state:

| State | Allowed CAC |
|-------|-------------|
| NORMAL | compute + decrypt + read (per policy) |
| SUSPICIOUS | compute only |
| RESTRICTED | compute only (pre-approved datasets/programs) |
| QUARANTINED | none |
| TERMINATED | none |

`effective_cac_permissions(granted, state) = granted ∩ ceiling(state)` — the
ceiling can only **remove** capability. The `cvztte.cac.guard` functions
(`require_compute` / `require_decrypt` / `require_read_plaintext`) apply this
fail-closed before the broker is ever invoked.

---

## Registries

- **Context registry** (`context.py`, §37) — CKKS crypto parameters are
  registry-controlled; an agent cannot supply them. Each context is pinned by a
  domain-separated `context_hash`; `require_active()` rejects an unknown,
  retired, or substituted context.
- **Program registry** (`program.py`, §39) — only allowlisted programs run:
  `SUM_V1`, `AVERAGE_V1`, `WEIGHTED_SCORE_V1`. No arbitrary agent-uploaded
  computation. `require()` also rejects a program whose depth exceeds the
  context's multiplicative depth.

## Envelopes (§38)

- **Ciphertext envelope** — dataset/ciphertext/context id, context hash, key
  epoch, schema, classification, owner, **hash over the serialized ciphertext
  bytes**, creation time, and the allowed-program set (+ its hash).
- **Result envelope** — the above plus lineage: parent ciphertext ids, program
  id/version, result ciphertext hash, lineage id.

`assert_no_substitution()` and the broker's input verification reject
context / key-epoch / ciphertext substitution fail-closed, and refuse a program
not in a ciphertext's allowed set.

---

## Compute flow (§40)

```
Agent -> FHE_COMPUTE -> CV-ZTTE
 ML-DSA -> OPA -> gnark -> containment/risk -> optional Judge/EZKL
 -> Decision Token -> FHE Broker -> OpenFHE Evaluate -> encrypted result
```

The `FHEBrokerClient` sits at the last hop. It performs **no** authorization —
the control plane runs the full pipeline first (Phase 17 wires this end to end).
The client shells out to the native broker (list argv, never `shell=True`),
pins every ciphertext by content hash, wraps it in an envelope, and fails closed
on any broker error (`FHE_COMPUTE_FAILED` / `FHE_COMPUTE_TIMEOUT`).

The compute agent receives a **ciphertext/result reference, not secret key
shares** (§40).

## Role separation (§43)

- ML-DSA: who signed? · OPA: enterprise policy? · gnark: capability/delegation
  predicate? · Behavior/Containment: abnormal/evasive? · Judge: should this
  proceed in context? · EZKL: prove the Judge computation? · **OpenFHE: compute
  without plaintext disclosure?**

We do **not** claim FHE is authorization, nor that gnark/EZKL prove the OpenFHE
evaluation. See [FHE_SECURITY_MODEL.md](FHE_SECURITY_MODEL.md).
