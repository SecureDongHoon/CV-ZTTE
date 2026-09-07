# CV-ZTTE v3 — Implementation Plan

Maps the 20 implementation phases of `CODEX_TASK_v3.md` §54 to concrete
modules, services, and tests in this repository. Each phase ends with
**tests → docs → a logical Git commit** (spec §0 rule 12).

Status legend: ☐ not started · ◐ in progress · ☑ done

---

## Environment & language split

| Concern | Language / Tool | Location |
|---|---|---|
| Control Plane, adapters, brokers, Judge training, orchestration | Python 3.10 (venv) | `cvztte/`, `enforcement/`, `apps/`, `services/decrypt-coordinator` |
| ML-DSA identity | OpenSSL 3.5.8 (native, source-built) via CLI/EVP signer helper | `cvztte/identity/` |
| ZK authorization | Go 1.27.1 + gnark v0.16.3 / gnark-crypto v0.21.0 | `services/zk-authz/` |
| ZKML proof of Judge | EZKL (Python) + ONNX | `cvztte/ezkl/`, `artifacts/judge/` |
| Confidential compute (FHE) | OpenFHE v1.5.1 (C++), narrow native broker | `services/fhe-broker/`, `services/fhe-key-authority-*` |
| Replay / freshness / behavior state | Redis 8.10.1 (source-built) | `cvztte/replay/`, `cvztte/behavior/` |
| Policy | OPA v1.20.2 (static binary) + Rego | `policy/rego/`, `cvztte/policy/` |
| Isolation / egress / threshold parties | Docker/compose (target) or process-level fallback | `docker-compose.yml`, `enforcement/`, `services/` |

Details and pinned versions: `docs/ENVIRONMENT.md`.

---

## Phase 0 — Environment / feasibility  ◐
- Inventory host, pin versions, build user-local toolchain (no sudo).
- Real smoke tests: ML-DSA (OpenSSL), OPA eval, gnark prove/verify, EZKL
  prove/verify, OpenFHE enc/eval/dec + threshold, Redis atomic, container/network.
- Deliverables: `docs/ENVIRONMENT.md`, this plan, `smoke/` scripts, commit.

## Phase 1 — Core canonical models
- `cvztte/action/` — `AgentAction` (versioned, all required action types §6).
- `cvztte/context/` — `AgentContext`, provenance, semantic quality enum.
- `cvztte/canonical/` — RFC 8785/JCS canonicalization, strict parser
  (reject dup keys, NaN/Inf, bad UTF-8, unknown fields, deep nesting, oversize),
  domain-separated SHA-256 `H(domain, bytes)=SHA256(UTF8(domain)||0x00||bytes)`.
- Tests: `tests/unit/test_canonical.py`, `test_action_model.py`. Docs: `ACTION_MODEL.md`.

## Phase 2 — Identity (ML-DSA)
- `cvztte/identity/provider.py` — provider abstraction (generate/import/sign/verify/metadata).
- `cvztte/identity/openssl_signer.py` — isolated signer helper (subprocess to OpenSSL 3.5 EVP),
  private key never in-process with LLM/log/audit.
- Key registry: active/prepared/retired/revoked, not-before/after, rotation, emergency revoke.
- Tests: sign/verify, mutation rejection, revoked key. Optional liboqs fallback disabled+reported.

## Phase 3 — Sessions / delegation / replay
- `cvztte/delegation/` — Policy Authority, structured delegation, no self-authorization.
- `cvztte/replay/` — Redis atomic nonce+sequence Lua script; Redis-down ⇒ no protected ALLOW.
- `SignedActionRequest` assembly/verification (§10). Tests: replay, rollback, expiry, concurrent dup.

## Phase 4 — OPA / risk
- `policy/rego/` — capability/resource/classification/limits/risk-floor rules;
  decision output with `allow, reason_code, risk_level, require_*`.
- `cvztte/policy/` — OPA client, bundle hash pinning, risk tiers L0–L4. Docs: `POLICY_MODEL.md`.

## Phase 5 — gnark authorization
- `services/zk-authz/` (cmd/circuit/credential/prover/verifier/registry/tests).
- Trusted issuer-anchored credential; public inputs bind action/policy/agent/circuit-version/capability.
- Poseidon↔SHA-256 bridge documented+tested. Groth16 vs PLONK benchmark. Docs: `GNARK_BINDING.md`.

## Phase 6 — Adapters
- `cvztte/adapters/` — MCP, LangGraph, LangChain, Generic SDK, Coding, Agent-message; browser stub.
- Normalize action/context/runtime; adapters propose only. Docs: `FRAMEWORK_ADAPTERS.md`.

## Phase 7 — Enforcement Fabric
- `enforcement/` — MCP gateway, egress proxy, file/process/secret/output/message brokers.
- Common flow: observe→canonicalize→recompute hash→validate token→exact match→execute→receipt.
- Docker/netns isolation (or documented process-level fallback). Docs: `ENFORCEMENT_FABRIC.md`.

## Phase 8 — Decision Token / receipts
- `cvztte/decision/` — Decision Token v3 (all §60.11 fields, epochs, audience, single-use, TTL).
- Gateway-only MAC/sign key. `cvztte/audit/` Execution Receipt. Docs: `DECISION_TOKEN.md`, `EXECUTION_RECEIPTS.md`.

## Phase 9 — Behavior engine
- `cvztte/behavior/` — rolling windows (10s/60s/5m), features §60.6, proposed/denied/bypass/executed/failed
  event distinction, canonical snapshot+hash, race-safe transitions. Docs: `BEHAVIOR_ENGINE.md`.

## Phase 10 — Containment / capability decay
- `cvztte/containment/` — state machine NORMAL→…→TERMINATED, config/OPA thresholds, evidence records.
- `cvztte/capability_decay/` — effective = intersection(...); ceilings; capability_epoch increment atomic.
- Kill switch (agent/runtime/session/delegation/group). Docs: `CONTAINMENT_ENGINE.md`, `DYNAMIC_CAPABILITY_DECAY.md`, `KILL_SWITCH.md`.

## Phase 11 — Safety Judge
- `cvztte/judge/` — deterministic feature extractor; MLP N→32→16→3 (UNSAFE/REVIEW/SAFE);
  train on synthetic+adversarial; margin guard. PyTorch→ONNX.

## Phase 12 — EZKL
- `cvztte/ezkl/` — ONNX→settings→SRS→circuit→setup→witness→proof→verify; artifact manifest+hash pinning;
  public-input binding to gateway-derived features; parity + quantization guard. Docs: `EZKL_BINDING.md`.

## Phase 13 — Onboarding / modes
- `cvztte/onboarding/` — `AgentRuntimeProfile`, conformance tests, OBSERVE/WARN/ENFORCE/QUARANTINE.
- Docs: `AGENT_ONBOARDING.md`, `SHADOW_MODE.md`.

## Phase 14 — OpenFHE / CAC foundations
- `services/fhe-broker/` (C++), context/program/ciphertext registries, real CKKS. `cvztte/cac/`.
- Docs: `CAC_ARCHITECTURE.md`, `OPENFHE_INTEGRATION.md`, `FHE_SECURITY_MODEL.md`.

## Phase 15 — Threshold FHE / decrypt
- `services/fhe-key-authority-{a,b,c}`, `services/decrypt-coordinator` (separate processes/containers).
- Genuine OpenFHE multiparty semantics; no persisted full key; release policy. Docs: `THRESHOLD_FHE.md`.

## Phase 16 — Confidential query governance / lineage
- `cvztte/confidential_query/`, `cvztte/lineage/`. Docs: `CONFIDENTIAL_QUERY_GOVERNANCE.md`, `DATA_LINEAGE.md`.

## Phase 17 — Full integration ✅
- Wire containment + CAC + risk + approval + brokers through the Control Plane API (§60.29).
- `cvztte/control_plane/` — `ControlPlane` orchestrator (evaluate → mint pipeline, fail-closed at every
  step), agent/admin **plane separation** (`AgentPlane`/`AdminPlane` gated by `AdminAuthorizer`),
  stateful TTL-bounded `ApprovalStore`, freshness `ReplayGuard` seam, `CACService`, and a stdlib
  `http_api` router mapping the §60.29 routes with `CVZTTEError`→HTTP status. Shared `EpochSource` keeps
  containment escalation invalidating outstanding tokens. Docs: `CONTROL_PLANE.md`.

## Phase 18 — Adversarial / failure suite ✅
- `tests/adversarial/` — reusable `lab.py` harness wires the integrated stack (real ML-DSA identity,
  DecisionTokenAuthority/validator over a shared `EpochSource`, ContainmentEngine, brokers) behind the
  Phase 17 ControlPlane. Six family modules cover §51 and the §60.31 cases through the real path; every
  DENY asserts protected side-effect count = 0 and unauthorized-plaintext-release count = 0 via
  `SideEffectLedger`. `tests/e2e/test_full_path.py` exercises one complete real ALLOW path (mint →
  independent broker re-validation → execute → hash-chained audit verifies) and a DENY/quarantine path.
- The full 150-case coverage map (including the native gnark/EZKL/OpenFHE/threshold cases carried by the
  guarded integration tests) is `docs/ADVERSARIAL_SUITE.md`.

## Phase 19 — Performance / hardening ✅
- `tests/performance/` benchmarks the §60.32 inventory with real components and observed medians
  (`bench.py` + a session recorder that prints a summary table): CPU/canonicalization, native ML-DSA
  sign/verify, Judge inference, Decision Token issuance, containment + capability-epoch propagation,
  behavior snapshot, egress/output/MCP proxies, backpressure, the full ALLOW path (L2), and
  quarantine/stale-token propagation always-on; OpenFHE context/key setup, encrypt, SUM, AVERAGE,
  decrypt, ciphertext size, and gnark prove/verify guarded on the compiled binaries (`-m slow`).
  Bounds are generous regression signals — no fabricated enterprise throughput (§52).
- The §52 coding-agent claim is demonstrated with the real token authority: sandbox-local work
  (N local hashes + one boundary crossing) beats central per-file mediation, asserted in the suite.
- `cvztte/config/backpressure.py::BoundedAdmission` — a fail-closed concurrency bound for the
  saturating prover/FHE stages: over-capacity admissions are shed with
  `SECURITY_DEPENDENCY_UNAVAILABLE` (→ DENY), never buffered unboundedly.
- `cvztte/config/profiles.py` — the demo / secure-lab / enterprise-reference deployment profiles
  with frozen `ResourceLimits`; enterprise-reference is a configuration skeleton whose constructor
  forbids `production_certified=True` (§53).
- The FHE broker now enforces `ResourceLimits.max_ciphertext_bytes` (`FHE_CIPHERTEXT_TOO_LARGE`),
  closing §60.31 #146 against the real OpenFHE broker.
- Docs: `PERFORMANCE.md`, `DEPLOYMENT.md`.

## Phase 20 — Documentation / security review / demo ✅
- Demos A–I (§58), `docs/FINAL_SECURITY_REVIEW.md` (all §56/§60.35 questions), `docs/FINAL_COMPLETION_REPORT.md`, `docs/DEMO.md`.
- Done: authored the full descriptive doc set — `ARCHITECTURE.md`, `THREAT_MODEL.md`
  (§1/§2/§3/§4 all 21 invariants + §59 challenge), `ACTION_MODEL.md`, and the §55
  subsystem docs `CONTAINMENT_ENGINE.md` / `DYNAMIC_CAPABILITY_DECAY.md` /
  `KILL_SWITCH.md`. `docs/DEMO.md` maps every §58 demo (A–I) to a real test in the
  integrated stack (no mock walkthroughs). `docs/FINAL_SECURITY_REVIEW.md` answers
  all 30 §56 questions and the §60.35 coverage list from actual code with
  `path:line` citations — including honest production gaps (§29: FIPS, key custody,
  local EZKL SRS, single-key FHE legacy path, mTLS/hosts, cases #61/#62) and the
  first external-audit priorities (§30). `docs/FINAL_COMPLETION_REPORT.md` maps
  every §57 Definition-of-Done item to code and a passing test; suite at completion:
  **364 passed, 23 deselected** (`-m "not slow"`), native OpenFHE/gnark benchmarks
  run separately. Facts gathered by read-only Explore agents with citations; no
  facts fabricated.

---

## Cross-cutting invariants tracked continuously
The 21 enduring invariants (§4) and error taxonomy (§60.30) are enforced from Phase 1 onward and
re-verified in Phase 18. No security-subsystem error may produce an implicit ALLOW (§4.20, fail-closed).
