# Final Security Review

Spec references: §56 (30 mandatory review questions, answered from actual code),
§60.35 (required coverage), §2 (non-claims), §3 (TCB). Per §56/§60.35 an
unanswered question is a release blocker; every question below is answered with
`path:line` citations to the implementation. Where a property is only partially
achieved, that is stated plainly, not hidden.

Companion docs: `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`,
`docs/ADVERSARIAL_SUITE.md`, and the per-subsystem docs linked inline.

---

## 1. Exact ML-DSA signed bytes / provider

The signed message is domain-separated canonical bytes:
`signing_input() = Domain.REQUEST.value.encode() + b"\x00" + canonicalize(canonical_dict())`
(`cvztte/request/model.py:52-56`, separator `:25`), with
`Domain.REQUEST = "cvztte.request.v3"` (`cvztte/canonical/domains.py:14`).
`canonical_dict()` is the RFC 8785 JCS serialization
(`cvztte/canonical/jcs.py`) of all signature-covered fields — protocol_version,
agent_id, key_id, runtime_id, session_id, delegation_id, policy_hash, action,
action_hash, timestamp, expires_at, sequence, nonce, request_id
(`cvztte/request/model.py:33-46`, `extra="forbid"` `:31`). The builder signs
exactly `signing_input()` (`request/builder.py:91-93`) and the verifier recomputes
it (`request/verify.py:75-77`). Provider is native OpenSSL, not liboqs:
`name = "openssl-native"` (`cvztte/identity/openssl_signer.py:57`),
backend `"openssl-default-provider"` (`:224`), algorithm
`ML_DSA_65 = "ML-DSA-65"` (`cvztte/identity/provider.py:41,45`), availability
checked at construction (`openssl_signer.py:92-103`), algorithm downgrade
rejected with `MLDSA_INVALID` (`:170-174`). Requires OpenSSL 3.5+.

## 2. Key isolation / revocation

Every crypto operation is delegated to the `openssl` CLI subprocess
(`openssl_signer.py:77-90`); key files are `0600` inside a `0700` keystore
(`:71,108,141`); the private key never returns to Python — callers hold only an
opaque `PrivateKeyHandle` with a redacted `__repr__` (`provider.py:85-98`), and
the registry "never handles private key bytes" (`registry.py:14-17,263-270`); the
LLM/SDK never sees it (`request/builder.py:6-8`). This satisfies invariant §4
(agent private keys never enter LLM context/log/audit/proof).
`KeyState = PREPARED/ACTIVE/RETIRED/REVOKED` (`registry.py:34-38`); `rotate()`
auto-retires the prior active key (`:201-211,180-188`); `revoke()` is irreversible
(`:213-219`) and `revoke_agent()` is a full-agent kill switch (`:221-232`).
Verify-time: REVOKED→`KEY_REVOKED`, PREPARED/out-of-window/unknown→`KEY_UNKNOWN`,
bad signature→`MLDSA_INVALID` (`registry.py:272-295,237-241`).

## 3. Atomic replay / freshness

Replay defense is a single Redis Lua `EVAL` (registered script), so the
check-and-commit is atomic (`cvztte/replay/redis_freshness.py:19,34,60`;
`cvztte/replay/replay_atomic.lua`). The script does nonce single-use
(`SISMEMBER`/`SADD` → `NONCE_REPLAY`), sequence monotonicity
(`seq <= last` → `SEQUENCE_INVALID`), and nonce `EXPIRE` TTL. Defaults:
TTL 300 s, nonce ≥ 128 bits (`redis_freshness.py:22-23`; short nonce →
`SCHEMA_INVALID` `:56-57`). Nonces are `secrets.token_hex(16)` (128-bit CSPRNG,
`request/builder.py:88`) and sequence is monotonic per (agent, session)
(`:36-48`). **Fail-closed:** Redis unavailable or any unknown Lua result →
`SECURITY_DEPENDENCY_UNAVAILABLE` (`redis_freshness.py:35-40,64-69,78-83`), never
an implicit allow. Sessions add `SESSION_UNKNOWN`/`SESSION_EXPIRED`
(`cvztte/session/model.py:76-98`); expired request →`REQUEST_EXPIRED` with 30 s
skew (`request/verify.py:20,83-86`).

## 4. Policy Authority / self-authorization prevention

Only trusted issuers mint delegations: `AuthorityKind =
SECURITY_ADMIN/AUTHORIZED_USER/ORCHESTRATOR_IAM` (`cvztte/delegation/model.py:42-47`).
`issue_root` rejects an untrusted issuer and rejects
`authority_id == subject_agent_id` self-delegation → `DELEGATION_INVALID`
(`:109-118`). `issue_child` forbids widening: capabilities must be a subset,
resource scopes a subset, clearance ≤ parent, expiry ≤ parent
(`:161-182`), and depth is bounded (`child_depth > parent.max_chain_depth` →
`DELEGATION_INVALID`, default 4, `:106,157-160`). Revocation propagates to all
descendants and `validate_for_agent` fails on any revoked/expired ancestor with a
cycle guard (`:213-266`). This is invariant §4 (agent cannot self-authorize or
widen delegation) enforced structurally.

## 5. OPA decision semantics

`default allow := false`; `allow if count(violation) == 0`
(`policy/rego/cvztte/authz.rego:140-142`) — default-deny, hard-DENY is final. The
Rego bundle is pinned by a domain-separated hash
`commit(Domain.POLICY, {version, sorted per-file sha256 manifest})`
(`cvztte/policy/bundle.py:21-34`); a mismatch raises `POLICY_HASH_MISMATCH`
(`bundle.py:71-79`, also `request/verify.py:59-60`) so the client cannot swap the
policy (invariant §4.7). Risk tiers L0–L4 are a deterministic `max()` over
declared candidates (writes/network→3, shell/secret/decrypt→4, …)
(`authz.rego:149-169`). **Fail-closed:** hard deny →`OPA_DENY`; missing
binary/bundle, eval error/timeout, nonzero exit, or an undefined/unparseable
decision →`OPA_UNAVAILABLE` (`cvztte/policy/opa_client.py:27-98`). See
`docs/POLICY_MODEL.md`.

## 6. gnark exact statement / public / private inputs / issuer anchoring

Groth16/BN254, `CircuitVersion = 3` (`services/zk-authz/circuit/authz.go:13`;
registry `registry.go:25-26`). **Public inputs** (fixed order,
`authz.go:26-39`): AgentHi/Lo, CredentialCommitment, RequiredCapability,
RequiredClearance, CurrentEpoch, ActionHi/Lo, PolicyHi/Lo, ScopeHi/Lo, CircuitVer,
SessionBinding. **Private witness** (`:42-45`): Capability, Clearance,
ExpiryEpoch, Salt. The circuit (`Define`, `:48-86`) recomputes a Poseidon2
commitment over agent/capability/clearance/expiry/scope/policy/salt and asserts it
equals the public `CredentialCommitment` (`:54-65`), then asserts
`Capability == RequiredCapability`, `RequiredClearance ≤ Clearance`,
`CurrentEpoch ≤ ExpiryEpoch`, and the SessionBinding equality (`:68-84`).
**Issuer anchoring:** the commitment binds a `Salt` known only to the trusted
issuer, issued off-circuit (`services/zk-authz/credential/credential.go:47-60`)
with native Poseidon2 matching the in-circuit hasher. The SHA-256→field bridge
(32-byte digest → two 128-bit big-endian limbs) is bit-identical between Go and
Python (`services/zk-authz/bridge/bridge.go:18-25`,
`cvztte/zkauthz/bridge.py:18-28`).

## 7. Action-proof binding (§4.11)

`ActionHi/ActionLo` are public inputs folded into
`SessionBinding = Poseidon2(CredentialCommitment, ActionHi, ActionLo, CurrentEpoch,
CircuitVer)`, asserted in-circuit (`authz.go:79-84`; off-circuit
`credential.go:58-60`). Because these are Groth16 public inputs, a proof made for
action A cannot verify when the verifier supplies action B's public inputs — the
"proof for one action cannot verify for another (§4.11)" comment is at
`authz.go:76-78`.

## 8. Adapter bypass behavior

Adapters only sense/propose: `FrameworkAdapter.propose()` returns an inert
`ActionProposal` carrying no authorization artifacts and always sets
`provenance.boundary_observed=False` (`cvztte/adapters/base.py:78-90,131-143`);
"an adapter never authorizes, signs, mints a token, or executes" (`base.py:5-8`).
When an adapter is absent or bypassed, `boundary_only_context()` yields
`SemanticContextQuality.BOUNDARY_ONLY` and high-risk actions default to
DENY/ESCALATE (`cvztte/adapters/registry.py:68-87`); unknown tool kinds degrade to
PARTIAL rather than guessing (`frameworks.py:94-103`). Mandatory mediation still
applies because the broker builds this context itself — invariant §4.2/§4.3
(adapters are sensors, not trust boundaries; missing context never lowers
protection). See `docs/FRAMEWORK_ADAPTERS.md`.

## 9. Mandatory mediation per resource

`EnforcementBroker.mediate()` (`enforcement/common.py:176-220`) runs one flow for
every broker: observe → canonicalize → **independently recompute action_hash**
(`:180`, "never trust a supplied hash") → validate Decision Token (fail-closed,
DENIED receipt on error `:183-192`) → `_assert_exact_match` on
action_hash/target/operation/payload_hash (mismatch → `FINAL_ACTION_BINDING_FAILED`
`:194-195,224-248`) → execute only on match → emit `ExecutionReceipt`. Each
resource has a dedicated broker with its own audience and deny code: file
(`FILE_PATH_ESCAPE`/`FILE_ACCESS_DENIED`), egress (`EGRESS_DENIED`), secret
(`SECRET_DISCLOSURE_FORBIDDEN`/`SECRET_UNKNOWN`), output (`OUTPUT_DENIED`), process
(`PROCESS_COMMAND_DENIED`, argv-only `shell=False` `process_broker.py:109`),
message (`MESSAGE_DENIED`), MCP gateway (`MCP_BYPASS_DENIED`, credential injected
internally with a leak check). Protected endpoints/credentials are held internally
with no accessor. See `docs/ENFORCEMENT_FABRIC.md`.

## 10. Decision Token exact constraints / epochs / audience

The token body (`cvztte/decision/model.py:73-100`, `extra="forbid"`) carries all
§60.11 fields: version, decision_id, request_id, agent/runtime/session ids,
action_hash, action_type, target/operation constraints, payload_hash, policy_hash,
risk_level, containment_state, decision, issued_at, not_before, expires_at,
max_uses (default 1), nonce, audience, epochs, checks. The **5 epochs** are
agent_revocation, runtime_revocation, policy, capability, risk (`EpochSet`,
`:43-57`). Authenticated by an HMAC-SHA256 **MAC** (not a signature) over
`Domain.DECISION_TOKEN || 0x00 || canonical_bytes` with a **gateway-only** key
(`cvztte/decision/mac.py:22-40`, custody note `:1-12`). `DecisionTokenValidator.
authorize` runs 8 ordered fail-closed steps (`validator.py:105-193`): (1) MAC →
`DECISION_TOKEN_INVALID`; (2) version/action-type → `DECISION_TOKEN_INVALID`,
action_hash → `FINAL_ACTION_BINDING_FAILED`; (3) agent/runtime/session binding →
`DECISION_TOKEN_INVALID`; (4) audience → `DECISION_TOKEN_AUDIENCE_MISMATCH`;
(5) TTL → `DECISION_TOKEN_EXPIRED`; (6) epoch freshness vs the shared
`EpochSource` → `DECISION_TOKEN_EPOCH_STALE`; (7) exact target/operation/payload →
`FINAL_ACTION_BINDING_FAILED`; (8) single-use consume → `DECISION_TOKEN_REPLAY`.
See `docs/DECISION_TOKEN.md`.

## 11. Actual action observation / TOCTOU

`mediate()` re-observes the real operation and recomputes `action_hash()` itself
before authorization and before execution (`common.py:176-195`);
`_assert_exact_match` re-validates the token against the freshly observed action
(`:224-248`) — "defense in depth for §4.11: a token for Action A cannot execute
Action B" (`:9-11`). Filesystem TOCTOU specifically: `FileBroker._open_nofollow`
opens the leaf `O_NOFOLLOW` and re-verifies containment on the opened descriptor
via `/proc/self/fd/{fd}`, closing the check-to-use window; a symlinked leaf raises
`FILE_PATH_ESCAPE` (`enforcement/file_broker.py:86-111`).

## 12. Execution Receipt trust

The audit log is hash-chained: each event carries `prev_hash`, `event_hash()`
commits the body under `Domain.AUDIT_EVENT`, `append()` links to the prior event
or genesis, and `verify()` re-walks seq/prev_hash continuity
(`cvztte/audit/log.py:36,59-132`). Checkpoints are ML-DSA-signed over
`{covers_through_seq, head_hash}` with a dedicated key and refuse a broken chain
(`AUDIT_CHAIN_BROKEN`, `:134-178`). Stages distinguish PROPOSED/AUTHORIZED/
TOKEN_ISSUED/ACTUAL_ACTION_OBSERVED/EXECUTED/DENIED/FAILED/RECEIPT/ADMIN — an
ALLOW does not imply execution; only EXECUTED/RECEIPT attests effect (`:14-16`).
See `docs/EXECUTION_RECEIPTS.md`.

## 13. Behavior snapshot consistency

Rolling windows are 10 s/60 s/5 m (`cvztte/behavior/model.py:31-33`). Event kinds
PROPOSED/DENIED/BYPASS_ATTEMPTED/EXECUTED/FAILED are distinct, and windowed "did"
features count EXECUTED only, so proposals and executions are not double-counted
(`engine.py:117-137,151-154`, `:10-12`). The snapshot hash commits under
`Domain.BEHAVIOR_STATE` and pops `computed_at`, so identical behavioral content
hashes identically regardless of wall-clock time (`model.py:105-111`). See
`docs/BEHAVIOR_ENGINE.md`.

## 14. Evasion evidence / containment transitions

`ThresholdPolicy.assess` reads behavior features (`denials_60s`,
`bypass_attempts_5m`, `denials_5m`, `secret_probe_count`, quarantine flags) against
a frozen, injected `ContainmentThresholds` dataclass — thresholds are
config/policy-controlled, not hardcoded (`cvztte/containment/policy.py:21-77`).
Transitions are escalate-only and `assess()` never issues TERMINATED (reserved for
the kill switch). Full table and state machine in `docs/CONTAINMENT_ENGINE.md`.

## 15. Capability-decay monotonicity / recovery

Effective authority = `delegated ∩ enterprise_policy ∩ runtime_profile ∩
containment_ceiling`; the ceiling only tightens with severity and is intersected,
never unioned, so escalation can only remove capability
(`cvztte/cac/permissions.py:44-64`). Recovery is explicit, method-gated, audited,
and never self-service (`RecoveryMethod`, `engine.py:47-83,299-359`; admin-only via
`AdminPlane.reset_containment`). See `docs/DYNAMIC_CAPABILITY_DECAY.md`.

## 16. Quarantine propagation

Every transition bumps the shared `capability_epoch` atomically
(`containment/engine.py:174-180`); the `DecisionTokenValidator` shares that
`EpochSource`, so all in-flight tokens become stale
(`DECISION_TOKEN_EPOCH_STALE`, `decision/validator.py:157-161`). Mint is also
blocked for QUARANTINED/TERMINATED subjects (`model.py:119-121`,
`plane.py:230-235,341-346`). Verified end to end in
`conformance.py:210-229`. See `docs/KILL_SWITCH.md`.

## 17. Judge semantics

Deterministic 25-feature extractor, all bounded to [0,1], pinned by
`feature_extractor_hash()` under `Domain.MODEL` with `FEATURE_VERSION=1`
(`cvztte/judge/features.py:33-179`). MLP N→32→16→3 (`model.py:19-50`), verdicts
UNSAFE/REVIEW/SAFE with index 0 most restrictive. ONNX inference is pinned to a
verified manifest with startup drift rejection and single-thread determinism
(`judge.py:60-83`). **Fail-closed margin guard:** if the top-two probability margin
< threshold the verdict collapses to the more restrictive of the two
(`judge.py:102-125`); any inference error → `JUDGE_FAILED`. See
`docs/SAFETY_JUDGE.md`.

## 18. EZKL exact statement / public inputs / SAFE predicate / quantization

Proves the Judge MLP over the deterministic feature vector; input/output public,
params fixed by hash (`cvztte/ezkl/prover.py:132-137`). Verification: (1)
cryptographic validity against pinned VK/SRS/settings else `EZKL_PROOF_INVALID`;
(2) `input_felts == float_to_felt(features)` else `EZKL_PUBLIC_INPUT_MISMATCH`
(binds proof to gateway-derived features); (3) SAFE predicate = argmax of decoded
output logits is SAFE; (4) **quantization guard** — the proven quantized verdict
must equal the trusted float ONNX verdict, else `EZKL_QUANTIZATION_GUARD`
(`verifier.py:61-121`). Artifact drift → `EZKL_ARTIFACT_UNAPPROVED`. **Caveat:** the
EZKL SRS is generated locally (`gen_srs`) — a deterministic reference setup, not a
trusted ceremony (`prover.py:12-16`); this is a production gap (§29). See
`docs/EZKL_BINDING.md`.

## 19. FHE scheme / parameters / context integrity

CKKS, the only end-to-end scheme, on OpenFHE pinned to 1.5.1
(`services/fhe-broker/CMakeLists.txt:1`; `cvztte/cac/context.py:26-29,60-61`).
Crypto params (ring_dimension, multiplicative_depth, scaling_mod_size, batch_size,
key_epoch, threshold) are registry-controlled — agents reference a `context_id`
and cannot mint a context (`context.py:54-91`, §37). The context is pinned by
`context_hash()` under `Domain.FHE_CONTEXT` (`:71-87`); `require_active()` fails
closed on non-ACTIVE (`FHE_CONTEXT_UNAPPROVED`) or hash mismatch
(`FHE_CONTEXT_MISMATCH`) (`:110-121`). Two profiles: `demo` (may be weaker, must be
labelled) and `secure-lab` (128-bit); the native broker sets `HEStd_128_classic`
(`fhe_broker.cpp:112,290`). See `docs/OPENFHE_INTEGRATION.md`,
`docs/FHE_SECURITY_MODEL.md`.

## 20. Where plaintext can exist

Exactly three narrow points: (1) encryption input to `FHEBrokerClient.encrypt`
(`cvztte/cac/broker.py:157-177`); (2) the single-key Phase-14 `decrypt` output
(`:255-270`); (3) threshold fusion output via `MultipartyDecryptFusion`
(`coordinator.py:141-185`). Evaluate operates entirely on ciphertext
(`EvalSum`/`EvalMult`, `fhe_broker.cpp:195-211`) — no computation decrypts first.
Ciphertexts/results are serialized to `.bin` on disk; serialized keys never enter
agent context, logs, or audit (`broker.py:20`, `authority.py:9-17`). Result
lineage stores hashes/IDs, never plaintext (§60.24, `docs/DATA_LINEAGE.md`).

## 21–22. Threshold share holders / semantics / can one party decrypt

Genuine OpenFHE **N-of-N interactive** protocol, deliberately NOT labelled
2-of-3: the coordinator collects one partial from *every* party and fuses
(`coordinator.py:141-185`); `authority.py:16` — "Every party is required to
decrypt (N-of-N). One missing party cannot decrypt." Three key authorities run as
separate processes (DATA_OWNER / SECURITY_PRIVACY / CVZTTE_DECRYPTION,
`services/fhe-key-authority-{a,b,c}/main.py:20`). Each party's secret share stays
in its own `share_dir` (`fhe_broker.cpp:321-323,352-354`); the coordinator holds no
share (`coordinator.py:6-7`). No single party can decrypt on the threshold path;
dropping a party fails closed with `FHE_THRESHOLD_INSUFFICIENT`
(`coordinator.py:151-156`). This satisfies invariant §4.18. **Caveat:** the
single-key Phase-14 `decrypt` path does load a full `key-sec.bin` and one party
decrypts directly (`broker.py:255-270`; `fhe_broker.cpp:128`) — a documented legacy
custody model, not the threshold model. See `docs/THRESHOLD_FHE.md`.

**Whether any full key is reconstructed/persisted:** No, on the threshold path —
`mp-install-public` writes only the joint public key + joint eval-sum keys; the
joint secret `s = s_a+s_b+s_c` exists only implicitly and is never persisted
(`fhe_broker.cpp:299,363-384`). **Evaluation-key protection:** the eval-sum key is
public evaluation material; the eval-mult (relin) key is optional/absent in
threshold contexts since allowlisted programs never multiply ct×ct
(`fhe_broker.cpp:178-187`).

## 23. FHE program allowlisting

Programs are a closed enum `SUM_V1/AVERAGE_V1/WEIGHTED_SCORE_V1`
(`cvztte/cac/program.py:23-28`), each with a manifest pinned by `program_hash()`
under `Domain.FHE_PROGRAM` (`:52-100`). Unknown → `FHE_PROGRAM_UNKNOWN`; depth over
context → `FHE_PROGRAM_DENIED` (`:117-132`); the C++ broker independently rejects
unknown programs (`fhe_broker.cpp:207-208`). Additionally each ciphertext envelope
carries `allowed_programs`/`allowed_program_set_hash`, and `_verify_inputs` rejects
a program outside the ciphertext's allowed set (`FHE_PROGRAM_DENIED`) or a tampered
set hash (`FHE_CIPHERTEXT_INVALID`) (`broker.py:308-316`). No arbitrary
agent-uploaded computation exists (invariant §4.19).

## 24. READ / COMPUTE / DECRYPT enforcement

`CACPermission` is three separate capabilities READ_PLAINTEXT /
COMPUTE_ON_CIPHERTEXT / DECRYPT_RESULT (`cvztte/cac/permissions.py:24-27`).
`require_decrypt` checks `DECRYPT_RESULT` specifically — compute alone never
satisfies it (`guard.py:37-49`, §42). Reference grants: analytics agent gets
compute only, security supervisor gets decrypt only (`permissions.py:33-38`).
Guards raise `FHE_COMPUTE_DENIED` / `FHE_DECRYPT_DENIED`. Containment ceilings
decay these per §47 (see Q15). This is invariant §4.16/§4.17.

## 25. Confidential-query inference leakage

`QueryGovernor.evaluate` is most-restrictive-wins and fail-closed
(`cvztte/confidential_query/governance.py:33-131`): individual-value denial + min
group size (`FHE_QUERY_PATTERN_RISK`), decrypt rate limit
(`FHE_PRIVACY_BUDGET_EXCEEDED`), differencing denial, repeated-overlap denial,
small-group human approval (`APPROVAL_REQUIRED`), and result rounding/minimization.
It is **explicitly NOT differential privacy**: the default mechanism is `NoDP`,
adds no noise, does no accounting, and `is_differential_privacy()` is True only if
a real noise+accounting mechanism is plugged in (`dp.py:1-42`,
`governance.py:41,48-50`) — §45 honored. Thresholds are config-controlled
(`models.py:88-113`). See `docs/CONFIDENTIAL_QUERY_GOVERNANCE.md`.

## 26. Output release

`enforcement/output_proxy.py` is DLP over final USER_OUTPUT: DENY on
synthetic-credential patterns and SECRET classification, REDACT on PII sample and
CONFIDENTIAL, else ALLOW (`:32-97`, deny → `OUTPUT_DENIED`). A released FHE
aggregate is authorized *before release* by `ThresholdReleasePolicy.authorize`,
invoked first inside `DecryptCoordinator.decrypt` before any partials are
collected (`release.py:57-79`, `coordinator.py:158-159`): it requires
`DECRYPT_RESULT` after containment decay, recomputes the result hash under
`Domain.FHE_RESULT` and rejects substitution (`FHE_RESULT_RELEASE_DENIED`), and
requires human approval for CONFIDENTIAL/SECRET (`APPROVAL_REQUIRED`). **Caveat:**
directly chaining the output-proxy DLP to the threshold release gate is a
documented Phase-17 deferral (`release.py:14-17`).

**Ciphertext/context/key-epoch binding + result substitution:** envelopes bind
context_id/context_hash/key_epoch/ciphertext_hash and allowed_program_set_hash;
`assert_no_substitution` rejects context mismatch (`FHE_CONTEXT_MISMATCH`) and
key-epoch mismatch (`FHE_KEY_EPOCH_MISMATCH`) (`cvztte/cac/envelope.py:24-101`);
`_verify_inputs` recomputes the ciphertext byte hash (`FHE_CIPHERTEXT_INVALID`)
(`broker.py:279-316`); release re-checks the result hash (`release.py:65-71`).

## 27. Failure behavior of every dependency

Fail-closed throughout (§4.20): Redis → `SECURITY_DEPENDENCY_UNAVAILABLE`
(Q3); OPA missing/erroring → `OPA_UNAVAILABLE` (Q5); missing gnark/OpenFHE
binaries → `SECURITY_DEPENDENCY_UNAVAILABLE`; broker/prover/FHE over-capacity →
`BoundedAdmission` sheds to `SECURITY_DEPENDENCY_UNAVAILABLE`
(`docs/PERFORMANCE.md`); FHE partial-decrypt subprocess failure →
`FHE_COMPUTE_FAILED` (`authority.py:151-156`); dropped threshold party →
`FHE_THRESHOLD_INSUFFICIENT`. Tests: `tests/adversarial/test_failure_injection.py`
(`test_case58_opa_unavailable_fails_closed`,
`test_case102_broker_dependency_failure_no_side_effect`). No mandatory
security-subsystem error maps to an implicit ALLOW.

## 28. Remaining TCB

Trusted (§3.2): the CV-ZTTE control plane; Policy Authority; identity/key
registry; approved policy-bundle, gnark, Judge/EZKL, and OpenFHE
context/program/key registries; the Decision Token authority and its gateway-only
MAC key; the Enforcement Fabric; the N threshold authorities (per configured trust
model); container/network isolation; and trusted time/state (Redis). A compromise
of any of these is outside the model. `shell=True` is never used (§60.12); the
control plane shells to native services only over list-argv boundaries.

## 29. Production gaps

- **Not FIPS-validated.** NIST-standardized ML-DSA via OpenSSL 3.5, not a
  FIPS-validated cryptographic module.
- **Key custody.** Private keys are `0600` files, not HSM/KMS/TEE-backed; the
  Decision Token MAC key and FHE keys likewise lack hardware custody.
- **EZKL SRS is a local reference setup**, not a trusted-ceremony/perpetual-powers
  SRS (Q18).
- **Single-key FHE legacy path** persists a full secret key (Q21) — production
  should use only the threshold path.
- **Transport.** mTLS / separate hosts are configuration in the
  enterprise-reference profile, not enforced by the reference build; the profile
  is structurally never production-certified (`cvztte/config/profiles.py`, §53).
- **No independent audit yet** (see Q30).
- **Two adversarial cases (#61/#62) remain mechanism-limited**, documented in
  `docs/ADVERSARIAL_SUITE.md`, not silently passed.
- **QueryGovernor is not differential privacy** (Q25) — no formal leakage bound.

## 30. First external-audit priorities

1. The Decision Token MAC key custody and the gateway trust boundary (single point
   whose compromise forges authorization).
2. gnark credential-issuance / salt custody and the SHA-256→field bridge
   (`ActionHi/ActionLo` derivation at call sites — one bridge caller was not fully
   traced in review and should be audited, Q7 caveat).
3. The EZKL SRS/setup trust model and the quantization guard's soundness (Q18).
4. Threshold FHE key ceremony and the claim that no full secret is ever
   reconstructable, plus eval-key exposure (Q21–22).
5. Fail-closed completeness: prove no security-subsystem error path reaches an
   implicit ALLOW across all brokers (§4.20).
6. Enforcement Fabric bypass resistance and TOCTOU under a real OS/container
   (Q11), and admin/agent plane isolation (§60.29).

---

## What neither ZKP proves (§2, §43)

gnark proves the encoded **authorization predicate** against a trusted credential;
EZKL proves the approved **Judge computation** for proof-bound inputs. **Neither
proves that the OpenFHE evaluation was performed correctly**, and FHE is **not**
an authorization mechanism. FHE does not hide timing, access patterns, ciphertext
size, or program identity. These non-claims are stated in `docs/THREAT_MODEL.md`
and enforced by keeping the three subsystems' commitments domain-separated and
independent.
