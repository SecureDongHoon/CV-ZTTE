# Architecture

Spec references: §5 (high-level architecture), §4 (invariants). This document is
the map; each subsystem has its own doc (linked inline).

## One sentence

An untrusted agent proposes a **canonical action**; the CV-ZTTE **control plane**
identifies, authorizes, proves, and behavior/containment-checks it and — only if
every check passes — mints a short-lived, execution-bound **Decision Token**; the
**Enforcement Fabric** independently re-observes the real action, requires an
exact token match, executes it, and writes an authenticated **Execution Receipt**.
The action understood, authorized, proven, and executed is the *same* action (§4).

## Planes

```
        UNTRUSTED AGENT WORLD  (LLM, planner, SDK, sub-agents, RAG — all untrusted)
                 |  proposes
                 v
        Semantic Adapters  →  Canonical AgentAction   (adapters only sense/propose)
                 |
   ==============================  CONTROL PLANE  ==============================
     Strict parser/canonicalization → ML-DSA identity → session/replay/delegation
     → OPA hard policy → gnark ZK authorization → behavior engine → containment
     → dynamic capability decay → risk-adaptive enforcement → Safety Judge → EZKL
     → approval/quarantine → CAC confidentiality → confidential-query governance
     → Decision Token authority → audit / SIEM / kill switch
                 |  Decision Token (short-lived, scoped, execution-bound)
   =============================  ENFORCEMENT FABRIC  =========================
     MCP gateway | API/DB | egress proxy | file broker | process broker
     | secret broker | output proxy | agent-message broker | CAC/FHE broker
                 |  observe actual action → recompute hash → exact token match
                 v
        PROTECTED DATA PLANE  →  Execution Receipt (hash-chained, ML-DSA checkpoints)
```

The **agent plane** and **admin plane** are separated as object capabilities
(Phase 17): an agent literally holds no admin method, and every admin operation
is gated by an allowlist authorizer over a required admin principal (§60.29).

## The pipeline, stage by stage

| Stage | Module | Doc | Fails closed to |
|---|---|---|---|
| Canonicalization | `cvztte/canonical/`, `cvztte/action/` | `ACTION_MODEL.md` | `SCHEMA_INVALID` / parse reject |
| Identity (ML-DSA-65) | `cvztte/identity/` | (review §1) | `MLDSA_INVALID` / `KEY_REVOKED` |
| Session / replay / delegation | `cvztte/session/`, `cvztte/replay/`, `cvztte/delegation/` | — | `NONCE_REPLAY` / `SEQUENCE_INVALID` |
| OPA policy + risk tiers | `cvztte/policy/`, `policy/rego/` | `POLICY_MODEL.md` | `OPA_DENY` / `OPA_UNAVAILABLE` |
| gnark ZK authorization | `services/zk-authz/`, `cvztte/zkauthz/` | `GNARK_BINDING.md` | `GNARK_PROOF_INVALID` |
| Behavior engine | `cvztte/behavior/` | `BEHAVIOR_ENGINE.md` | (feeds containment) |
| Containment + capability decay | `cvztte/containment/` (engine, policy, model) | `CONTAINMENT_ENGINE.md`, `DYNAMIC_CAPABILITY_DECAY.md` | `CONTAINMENT_*` |
| Safety Judge | `cvztte/judge/` | `SAFETY_JUDGE.md` | `JUDGE_UNSAFE` / `JUDGE_FAILED` |
| EZKL ZKML proof | `cvztte/ezkl/` | `EZKL_BINDING.md` | `EZKL_PROOF_INVALID` |
| Approval / quarantine / kill | `cvztte/control_plane/`, `cvztte/containment/` | `KILL_SWITCH.md` | `APPROVAL_REQUIRED` / `CONTAINMENT_QUARANTINED` |
| Decision Token | `cvztte/decision/` | `DECISION_TOKEN.md` | `DECISION_TOKEN_*` |
| Enforcement Fabric | `enforcement/` | `ENFORCEMENT_FABRIC.md` | `*_DENIED` |
| Execution Receipt / audit | `cvztte/audit/` | `EXECUTION_RECEIPTS.md` | `AUDIT_CHAIN_BROKEN` |
| CAC / OpenFHE / threshold | `cvztte/cac/`, `services/fhe-broker/`, `services/fhe-key-authority-*/` | `CAC_ARCHITECTURE.md`, `OPENFHE_INTEGRATION.md`, `FHE_SECURITY_MODEL.md`, `THRESHOLD_FHE.md` | `FHE_*` |
| Confidential-query governance / lineage | `cvztte/confidential_query/`, `cvztte/lineage/` | `CONFIDENTIAL_QUERY_GOVERNANCE.md`, `DATA_LINEAGE.md` | `FHE_QUERY_PATTERN_RISK` |

Every stage may only **subtract** authority. No stage can turn a security error
into an ALLOW (§4.20). The full error taxonomy is `cvztte/errors.py`.

## Shared epoch source (the containment ↔ token link)

`ContainmentEngine`, `DecisionTokenAuthority`, and `DecisionTokenValidator` share
**one** `EpochSource` (`cvztte/decision/validator.py`). A containment escalation
atomically bumps `capability_epoch`; the validator then rejects every
already-minted token with `DECISION_TOKEN_EPOCH_STALE`. That single shared object
is why "quarantine now" instantly invalidates in-flight authority — see
`docs/CONTAINMENT_ENGINE.md` and `docs/KILL_SWITCH.md`.

## Native services

- **gnark ZK-authz** (Go, `services/zk-authz/`) — Groth16/BN254 authorization proofs.
- **OpenFHE FHE broker** (C++, `services/fhe-broker/`) — real CKKS encrypt/evaluate/decrypt.
- **Threshold key authorities** (`services/fhe-key-authority-{a,b,c}/`) — genuine
  N-of-N multiparty key ceremony and partial decryption as separate processes.

The Python control plane shells out to these over narrow list-argv boundaries
(never `shell=True`, §60.12) and fails closed if a binary is missing
(`SECURITY_DEPENDENCY_UNAVAILABLE`).

## Deployment & performance

Deployment profiles (demo / secure-lab / enterprise-reference) and the fail-closed
resource bounds / backpressure are in `docs/DEPLOYMENT.md` and
`docs/PERFORMANCE.md`. The reference build runs `secure-lab`; enterprise-reference
is a configuration skeleton and is never production-certified (§53).
