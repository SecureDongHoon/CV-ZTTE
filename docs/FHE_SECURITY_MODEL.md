# FHE / CAC Security Model

Spec references: §35, §36, §41, §42, §43, §45, §47.

This document states honestly what the CAC subsystem does and does **not**
guarantee. Where the reference is weaker than a production deployment, it says so
explicitly.

## What FHE gives us

- **Compute without plaintext disclosure.** An analytics agent can run an
  approved program (`SUM_V1`, `AVERAGE_V1`, `WEIGHTED_SCORE_V1`) over CKKS
  ciphertext and obtain an encrypted result without ever seeing the plaintext.

## What FHE does NOT give us (§43)

FHE is **not** authorization. We do **not** claim:

- FHE is authorization;
- gnark proves the OpenFHE evaluation;
- EZKL proves the OpenFHE evaluation;
- a ZKP proves business-policy correctness.

Authorization is done by the normal CV-ZTTE pipeline (ML-DSA → OPA → gnark →
behavior/containment → optional Judge/EZKL → Decision Token). CAC operations are
just AgentActions subject to all of it (§35).

## Permission separation (§42)

`READ_PLAINTEXT`, `COMPUTE_ON_CIPHERTEXT`, and `DECRYPT_RESULT` are distinct.
**Compute authority does not imply decrypt authority.** Decryption is a separate
high-risk action; plaintext release additionally evaluates classification,
recipient, purpose, aggregation/minimization, and audit (§42). Containment
ceilings decay these capabilities (§47): RESTRICTED forbids decrypt;
QUARANTINED/TERMINATED forbid all CAC.

## Key custody — Phase 14 vs. Phase 15

**Phase 14 single-key.** The native broker holds the CKKS secret key in the
context directory and performs `decrypt` directly. This demonstrates the
compute-without-disclosure property and the permission model, but a single
component can decrypt. This path remains only for contexts that legitimately use
a single key.

**Phase 15 adds genuine OpenFHE multiparty decryption**, where no single service
holds a reconstructed full secret key (§41). Reference participants: Data Owner
Authority, Security/Privacy Authority, CV-ZTTE Decryption Authority, run as
separate processes. The protocol is **N-of-N — all configured participants are
required**; we deliberately do **not** call it "2-of-3" because the selected
OpenFHE workflow does not support recovery from a proper subset. Dropping a party
makes decryption fail cryptographically. **Secret shares never enter LLM context,
logs, or audit** (§41), and no service persists the combined secret key. Full
protocol details, the release policy, and what is deferred (Output Proxy/DLP →
Phase 17; query governance → Phase 16) are in
[THRESHOLD_FHE.md](THRESHOLD_FHE.md).

## Parameters and security level (§37)

Contexts request OpenFHE's `HEStd_128_classic` security level. A `demo` profile
may use weaker parameters and MUST be labelled as such; a `secure-lab` profile
uses 128-bit settings. Agents cannot supply crypto parameters — they come from
the registry and are pinned by `context_hash`.

## Substitution resistance (§38)

Every ciphertext is pinned by a domain-separated hash over its serialized bytes
and bound (in its envelope) to a context id, context hash, and key epoch. The
broker rejects, fail-closed:

- a ciphertext whose bytes no longer match its envelope (`FHE_CIPHERTEXT_INVALID`);
- an input bound to a different context/hash (`FHE_CONTEXT_MISMATCH`);
- an input under a different key epoch (`FHE_KEY_EPOCH_MISMATCH`);
- a program not in the ciphertext's allowed set (`FHE_PROGRAM_DENIED`).

## Inference risk (§45) — not differential privacy

FHE does not prevent inference from *permitted plaintext outputs*. The result of
`AVERAGE_V1` on a tiny group still leaks. Confidential Query Governance (Phase
16) tracks decrypt count, query frequency, overlapping subsets, result
precision, and differencing patterns, and can rate-limit, require minimum group
size, round/minimize, or deny individual-value release. **We do not call this
differential privacy** — no DP noise/accounting is implemented; a DP extension
point is provided.

## Resource exhaustion (§46)

Depth limits and a broker timeout are enforced now; batch size, queues, quotas,
and rate limits are control-plane / query-governance responsibilities. Repeated
abusive expensive requests feed Behavior/Containment and can trigger capability
decay.
