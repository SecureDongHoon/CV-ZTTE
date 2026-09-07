# CV-ZTTE v3

**Cryptographically Verifiable Zero-Trust Agentic Security Control Plane and
Enforcement Fabric** — reference implementation.

> Semantic Interception for understanding. Mandatory Mediation for security.
> The action we understand, authorize, prove, and execute must be the same action.
> READ != COMPUTE != DECRYPT.

This is a framework-agnostic security control plane for autonomous AI agents. It
assumes the agent may be prompt-injected, malicious, or fully compromised, and
ensures every consequential action is identified, signed (post-quantum ML-DSA),
authorized (OPA + gnark ZK), behavior/containment-checked, proof-bound (EZKL
ZKML), mediated at the real execution boundary, and audited — while enabling
policy-governed confidential computation over encrypted data (OpenFHE).

See `CV-ZTTE_Spec_v3.md` / `CODEX_TASK_v3.md` for the authoritative specification.

## Quick start

```bash
source env.sh              # user-local toolchain + venv (see docs/ENVIRONMENT.md)
bash smoke/run_all.sh      # Phase 0 feasibility gate (6 foundations)
python -m pytest tests/    # unit/integration tests
```

## Status

Phased build per `docs/IMPLEMENTATION_PLAN.md`. Complete: Phase 0
(environment/feasibility), Phase 1 (canonical models), Phase 2 (ML-DSA identity:
native-OpenSSL signer isolation, key registry, rotation/revocation), Phase 3
(SignedActionRequest, sessions, structured delegation, Redis atomic replay/
freshness), Phase 4 (OPA/Rego authoritative policy, risk tiers L0–L4, bundle
hash pinning), Phase 5 (gnark ZK authorization: Groth16/BN254 circuit with
Poseidon2 credential binding, SHA-256→field bridge, versioned/pinned artifact
registry, fail-closed Python client — client cannot select the VK), Phase 6
(framework adapters: MCP/LangGraph/LangChain/Generic/Coding/Agent-message +
experimental browser stub — normalize to canonical actions and propose only,
BOUNDARY_ONLY fallback when absent/bypassed), Phase 7 (Enforcement Fabric:
file/egress/secret/output/process/message brokers + MCP gateway on a common
observe→recompute-hash→authorize→exact-match→execute→receipt flow, fail-closed;
traversal/symlink defense, use-without-disclosure, DLP, no-shell command
allowlist, anti-authority-laundering, credential hiding), Phase 8 (Decision
Token v3: all §60.11 fields, gateway-only MAC, epochs, audience, single-use/TTL,
the real DecisionValidator with cross-action §4.11 binding; hash-chained
Execution Receipt audit log with ML-DSA-signed checkpoints), Phase 9 (stateful
Behavior Engine: per-scope 10s/60s/5m rolling windows, §60.6 features,
proposed/denied/bypass/executed/failed distinction so proposals and executions
are not double-counted, canonical time-independent snapshot hash, race-safe
transitions), Phase 10 (containment state machine NORMAL→SUSPICIOUS→RESTRICTED→
QUARANTINED→TERMINATED with dynamic capability decay = intersection(delegated,
enterprise_policy, runtime_profile, containment_ceiling); escalate-only
assessment from behavior features with config-controlled thresholds; atomic
capability-epoch bump on every transition that invalidates in-flight Decision
Tokens; administrator kill switch; explicit method-gated audited recovery;
containment can only remove authority, never grant it), Phase 11 (Safety Judge:
deterministic bounded-feature extractor, compact N→32→16→3 MLP trained on
synthetic+adversarial scenarios, PyTorch→ONNX export with a pinned manifest and
startup drift rejection, fail-closed margin guard that resolves quantization-
boundary ambiguity toward the more restrictive verdict — UNSAFE/REVIEW/SAFE),
Phase 12 (EZKL ZKML: real ONNX→settings→SRS→circuit→setup→witness→proof→verify
pipeline proving the approved Judge; hash-pinned artifact manifest with startup
drift rejection; §30 proof binding — public-input equality to gateway-derived
feature field elements, SAFE predicate on proven logits, and a quantization
guard that rejects a quantized verdict disagreeing with the float Judge), Phase
13 (agent onboarding + deployment modes: 12-field AgentRuntimeProfile with
fail-closed mandatory-controls check, admin-only audited mode control with the
OBSERVE/WARN/ENFORCE/QUARANTINE effect mapping — OBSERVE produces WOULD_ALLOW/
WOULD_DENY and is explicitly not enforcement, a live conformance harness wiring a
real FileBroker + token authority/validator + containment engine to verify
bypass-blocked/happy/deny/exact-binding/adapter/kill-switch before ENFORCED,
onboarding service that blocks activation when controls are absent or conformance
fails, and shadow-mode reporting), Phase 14 (CAC / OpenFHE foundations: a narrow
native C++ fhe_broker over real OpenFHE 1.5.1 CKKS — genuine context/key setup,
encrypt, allowlisted evaluate SUM/AVERAGE/WEIGHTED_SCORE, decrypt, no toy crypto;
registry-controlled contexts and programs an agent cannot supply; ciphertext/
result envelopes pinned by hashes over serialized bytes with context/key-epoch/
ciphertext substitution rejection; the READ_PLAINTEXT/COMPUTE_ON_CIPHERTEXT/
DECRYPT_RESULT permission split where compute never implies decrypt, decayed by
containment ceilings; a fail-closed Python client shelling out with list argv,
no shell=True — single-key custody now, threshold decryption in Phase 15),
Phase 15 (threshold/multiparty FHE: a genuine OpenFHE N-of-N interactive
protocol — every configured party required to decrypt, deliberately NOT labelled
2-of-3 — across three key authorities run as separate processes; a key ceremony
that installs only joint public + eval-sum keys and leaves each secret share in
its own directory with no full secret key ever persisted; a decrypt coordinator
that holds no share and applies a fail-closed release gate before fusing partials
— DECRYPT_RESULT after containment decay, result-hash substitution rejection, and
human approval for CONFIDENTIAL/SECRET — dropping a party fails decryption
cryptographically), and Phase 16 (Confidential Query Governance — fail-closed,
policy-driven inference-leakage controls on permitted plaintext outputs: minimum
aggregation group size, individual-value denial, decrypt rate limiting,
differencing/overlap-pattern denial, small-group approval, and result rounding,
most-restrictive-wins and explicitly NOT differential privacy with only a
pluggable DP extension point; plus a tamper-evident data-lineage DAG that traces
every released result back through decrypt request → result → program → ciphertext
→ dataset, storing hashes/IDs and never plaintext), and Phase 17 (full integration
through the Control Plane API — one fail-closed pipeline that runs identity/
integrity/freshness → session → containment → policy/risk → human approval → mint,
where any step may only subtract authority and none can turn a security error into
an ALLOW; a stateful TTL-bounded approval workflow that parks high-risk decisions
PENDING and mints nothing until an admin grants; agent and admin planes kept
separated as object capability — an agent literally holds no admin method, and
every admin operation is gated by an allowlist authorizer, over HTTP by a required
admin principal; a shared EpochSource so a containment escalation invalidates every
outstanding token; and a dependency-free stdlib HTTP router mapping the §60.29
routes with a stable CVZTTEError→status mapping that never leaks internals), and
Phase 18 (the mandatory adversarial/failure suite — a reusable `tests/adversarial/lab.py`
harness drives real attacks through the integrated stack behind the Phase 17 control
plane, covering the §51 families and the §60.31 case inventory, and every DENY asserts
both protected side-effect count = 0 and unauthorized-plaintext-release count = 0; one
complete real ALLOW/DENY end-to-end path lives in `tests/e2e/`, and the full 150-case
coverage map is `docs/ADVERSARIAL_SUITE.md`), and Phase 19 (performance / hardening —
`tests/performance/` benchmarks the §60.32 inventory with real components and observed
medians, never fabricated throughput: native ML-DSA/OpenFHE/gnark alongside the token,
containment, Judge, and enforcement paths, plus the §52 coding-agent demonstration that
sandbox-local work beats central per-file mediation; a fail-closed `BoundedAdmission`
sheds over-capacity prover/FHE load to `SECURITY_DEPENDENCY_UNAVAILABLE` rather than
buffering unboundedly; the demo / secure-lab / enterprise-reference deployment profiles,
where enterprise-reference is a configuration skeleton that can never be marked
production-certified; and a fail-closed FHE ciphertext-size bound
(`FHE_CIPHERTEXT_TOO_LARGE`) — see `docs/PERFORMANCE.md` and `docs/DEPLOYMENT.md`), and
Phase 20 (documentation / security review / demonstrations — the full descriptive doc set
(`ARCHITECTURE`, `THREAT_MODEL` with all 21 invariants and the §59 acceptance challenge,
`ACTION_MODEL`, and the §55 `CONTAINMENT_ENGINE`/`DYNAMIC_CAPABILITY_DECAY`/`KILL_SWITCH`
docs); `docs/DEMO.md` mapping every §58 demonstration A–I to a real test in the integrated
stack; `docs/FINAL_SECURITY_REVIEW.md` answering all 30 §56 questions and the §60.35 coverage
list from actual code with file:line citations, stating production gaps and first external-audit
priorities honestly; and `docs/FINAL_COMPLETION_REPORT.md` mapping every §57 Definition-of-Done
item to code and a passing test — full suite 364 passed, 23 deselected). This completes the
20-phase build. See the plan for progress.

## Layout

- `cvztte/` — Python control-plane library (action, context, canonical, identity, policy, …)
- `services/` — Go gnark ZK-authz, C++ OpenFHE broker, threshold key authorities
- `enforcement/` — mandatory-mediation brokers/proxies (Enforcement Fabric)
- `policy/rego/` — OPA policy bundles
- `smoke/` — Phase 0 feasibility smoke tests
- `docs/` — architecture, threat model, security review, and per-subsystem docs

**Not production-certified.** See `docs/ENVIRONMENT.md` for the NIST-standardized
vs FIPS-validated distinction and the reference build's limitations.
