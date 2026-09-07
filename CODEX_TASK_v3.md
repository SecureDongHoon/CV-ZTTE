# CV-ZTTE Specification v3

## Standalone Master Specification for an Enterprise-Oriented, Cryptographically Verifiable Zero-Trust Agentic Security Control Plane

**Document status:** Authoritative standalone master specification\
**Purpose:** Rebuild CV-ZTTE from an empty repository without requiring
v1/v2/v2.1/v2.2 documents\
**Audience:** Codex coding agent, security engineers, cryptography
reviewers, AI platform engineers, enterprise architects\
**Target:** Executable end-to-end reference implementation whose
architecture is credible as the foundation of an enterprise AI-Agent
runtime security gateway\
**Core stack:** OpenSSL ML-DSA, OPA/Rego, gnark, PyTorch/ONNX/EZKL,
OpenFHE/Threshold FHE, Redis, PostgreSQL, container/runtime isolation,
protocol/network/filesystem/process/output/message brokers\
**Primary philosophy:** **Do not attempt to make the AI Agent
trustworthy. Make every consequential Agent action observable,
least-privileged, authorized, cryptographically bound, verifiable,
enforceable, and auditable.**\
**Privacy philosophy:** **Grant only the minimum action authority and
minimum plaintext visibility required for the task.**\
**Runtime architecture:** **Semantic Interception for understanding.
Mandatory Mediation for security.**

------------------------------------------------------------------------

# 0. Normative language and Codex rules

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative.

This specification supersedes all historical CV-ZTTE design documents
for a fresh implementation. Do not search for or depend on older CV-ZTTE
specifications unless explicitly asked by the user.

Before substantial implementation:

1.  Read this entire document.
2.  Inspect the host environment.
3.  Resolve current compatible versions from actual installed
    tooling/current official documentation.
4.  Pin exact versions/commits.
5.  Create `docs/ENVIRONMENT.md`.
6.  Create `docs/IMPLEMENTATION_PLAN.md` mapping the phases in this
    document to concrete modules/tests.
7.  Run real feasibility smoke tests for:
    -   OpenSSL ML-DSA;
    -   OPA;
    -   gnark proof generation/verification;
    -   EZKL proof generation/verification;
    -   OpenFHE encryption/evaluation/decryption and supported
        multiparty/threshold workflow;
    -   Redis atomic operations;
    -   container/network isolation.
8.  Never silently weaken a security property because a library API is
    inconvenient.
9.  If an API/version differs from examples, adapt to the current API
    while preserving the security property and document the deviation in
    `docs/IMPLEMENTATION_NOTES.md`.
10. Real acceptance paths MUST NOT replace cryptography with mocks.
11. All mandatory security subsystem failures MUST fail closed unless a
    policy explicitly selects a safer action such as
    QUARANTINE/ESCALATE.
12. Each implementation phase ends with tests, documentation, and a
    logical Git commit.
13. Do not declare completion until all Definition-of-Done and
    adversarial requirements have evidence in
    `docs/FINAL_COMPLETION_REPORT.md`.

------------------------------------------------------------------------

# 1. Mission

CV-ZTTE is a **framework-agnostic Agentic Security Control Plane and
Enforcement Fabric** for autonomous and semi-autonomous AI Agents.

It assumes the Agent may be: - prompt-injected; - malicious; -
hallucinating; - compromised through retrieved content; - persistently
searching for bypasses; - using legitimate identity credentials while
exceeding delegated authority.

CV-ZTTE controls **consequential actions** rather than trusting internal
reasoning.

It MUST support: - MCP/tool calls; - APIs/DB; - network egress; -
filesystem; - processes/shell/code execution; - secret access; - user
output; - Agent-to-Agent communication; - sub-Agent delegation; -
confidential computation.

The reference implementation must demonstrate that an Agent can be
legitimate and fully compromised while unauthorized real-world side
effects remain blocked.

------------------------------------------------------------------------

# 2. What CV-ZTTE does not claim

Do not claim that CV-ZTTE: - makes LLM reasoning trustworthy; - prevents
all prompt injection; - formally verifies business-policy correctness; -
proves a Safety Judge is semantically perfect; - makes the whole system
quantum-safe merely because ML-DSA is used; - makes a host safe after
kernel/hypervisor compromise; - makes FHE hide timing, access patterns,
ciphertext size, program identity, or all metadata; - makes ZKP
integration correct merely because gnark/EZKL themselves verify; - is
production-certified without independent review.

Correct claims: - ML-DSA authenticates signed Agent requests under
registered keys. - OPA enforces deterministic enterprise policy. - gnark
proves explicitly encoded authorization predicates anchored to trusted
credentials. - the Behavior/Containment subsystem detects and responds
to stateful evasion. - EZKL proves the approved mathematical Judge
computation for proof-bound inputs. - OpenFHE permits approved
computation over ciphertext without exposing source plaintext to
compute-only Agents. - Enforcement Fabric prevents cooperative-SDK
bypass within the declared runtime threat model.

------------------------------------------------------------------------

# 3. Trust model

## 3.1 Untrusted

Treat as potentially malicious: - user input; - retrieved/RAG content; -
LLM; - planner; - Agent-generated arguments; - Agent memory content; -
Agent framework; - sub-Agent; - another Agent; - network client; -
captured request/token/proof; - ciphertext reference supplied by
Agent; - adapter-provided optional semantic metadata unless
bound/validated.

## 3.2 Trusted/controlled security plane

Reference TCB: - CV-ZTTE Control Plane; - Policy Authority; -
identity/key registry; - approved policy bundle registry; - gnark
verifier registry; - Judge/EZKL artifact registry; - OpenFHE
context/program/key registry; - Decision Token authority; - Enforcement
Fabric; - threshold-decryption authorities according to configured trust
model; - container/network isolation primitives; - trusted time/state
services.

Production must reduce/segregate this TCB through HSM/KMS/TEE, mTLS,
separate hosts, signed releases, and independent audit.

------------------------------------------------------------------------

# 4. Enduring invariants

The primary invariant is:

> **THE SAME CANONICAL ACTION MUST BE IDENTIFIED, SIGNED, AUTHORIZED,
> POLICY-COMPLIANT, BEHAVIOR-CHECKED, PROOF-BOUND, AND EXECUTED.**

Additional invariants:

1.  No protected effect without mandatory mediation.
2.  Framework adapters are semantic sensors, not trust boundaries.
3.  Missing semantic context never lowers protection.
4.  Agent private ML-DSA keys never enter LLM context/log/audit/proof.
5.  Agent cannot self-authorize or widen delegation.
6.  Hard-policy DENY cannot be overridden by ML/ZKP.
7.  Client cannot choose weaker model/circuit/VK/policy/provider.
8.  Replay/stale/sequence-regressed requests fail.
9.  Decision Token is short-lived, scoped, and execution-bound.
10. Enforcement point independently observes/recomputes actual action.
11. Action A authorization/proof/token cannot execute Action B.
12. Execution requires an authenticated Execution Receipt.
13. Risk escalation can only reduce authority or add controls.
14. Capability decay is monotonic within an active escalation episode.
15. Recovery/de-escalation is explicit and audited.
16. `READ != COMPUTE != DECRYPT`.
17. FHE compute authority never implies plaintext or decryption
    authority.
18. Threshold mode must not leave a single unauthorized principal able
    to decrypt.
19. FHE programs/contexts/parameters are registry-approved, never
    Agent-selected arbitrary crypto.
20. No security subsystem error produces implicit ALLOW.
21. Audit records must not contain secrets/plaintext unnecessarily.

------------------------------------------------------------------------

# 5. High-level architecture

``` text
                      USER / ORCHESTRATOR / ADMIN
                                 |
                                 v
                       UNTRUSTED AGENT WORLD
      MCP | LangGraph | LangChain | Coding | Browser | Custom | Multi-Agent
                                 |
                +----------------+----------------+
                |                                 |
        Semantic Adapters                  Hostile/direct path
                |                                 |
                v                                 v
        Rich AgentContext                Sandbox / runtime boundary
                |                                 |
                +----------------+----------------+
                                 |
                         Canonical AgentAction
                                 |
====================================================================
                       CV-ZTTE CONTROL PLANE
====================================================================
 Strict Parser / Canonicalization
 OpenSSL ML-DSA Identity
 Session / Replay / Delegation
 OPA / Hard Policy
 gnark ZK Authorization
 Stateful Behavior Engine
 Evasion / Containment Engine
 Dynamic Capability Decay
 Risk-Adaptive Enforcement
 Safety Judge
 EZKL ZKML
 Approval / Quarantine
 CAC Confidentiality Policy
 Confidential Query Governance
 Decision Token Authority
 Audit / SIEM / Kill Switch
                                 |
                          Decision Token
====================================================================
                       ENFORCEMENT FABRIC
====================================================================
 MCP Gateway | API/DB | Egress Proxy | File Broker | Process Broker
 Secret Broker | Output Proxy | Agent Message Broker | CAC/FHE Broker
                                 |
                         Actual Action Observe
                                 |
                           Exact token match
                                 |
                                 v
                         PROTECTED DATA PLANE
                                 |
                         Execution Receipt
```

------------------------------------------------------------------------

# 6. Generalized AgentAction

Use one versioned canonical model for consequential operations.

Required action types:

``` text
TOOL_CALL
MCP_CALL
API_REQUEST
DB_OPERATION
FILE_READ
FILE_WRITE
FILE_DELETE
PROCESS_EXEC
SHELL_EXEC
CODE_EXECUTION
NETWORK_REQUEST
USER_OUTPUT
AGENT_MESSAGE
MEMORY_READ
MEMORY_WRITE
SECRET_ACCESS
CLOUD_CONTROL_ACTION
EXTERNAL_MESSAGE
FHE_ENCRYPT
FHE_COMPUTE
FHE_DECRYPT_REQUEST
FHE_PARTIAL_DECRYPT
FHE_COMBINE_DECRYPT
FHE_KEY_ROTATE
FHE_CONTEXT_CREATE
```

Optional extension: `FHE_REENCRYPT`.

Example:

``` json
{
  "action_version": 1,
  "action_type": "DB_OPERATION",
  "target": "prod-security-db",
  "operation": "select",
  "resource": "security_events",
  "arguments": {"columns":["id","severity"],"limit":50},
  "data_classification": "INTERNAL"
}
```

Sensitive payloads should use immutable references + hashes rather than
duplicate plaintext.

------------------------------------------------------------------------

# 7. Canonical AgentContext and provenance

Use:

``` json
{
  "context_version": 1,
  "agent_id": "agt_...",
  "runtime_id": "runtime_...",
  "session_id": "ses_...",
  "delegation_id": "dlg_...",
  "framework": "langgraph",
  "adapter_id": "langgraph-v1",
  "workflow_id": "wf_...",
  "node_id": "tool-node",
  "intent_hash": "sha256:...",
  "purpose_code": "SECURITY_ANALYSIS",
  "data_classification": "INTERNAL",
  "semantic_context_quality": "RICH"
}
```

Quality: - `RICH` - `PARTIAL` - `BOUNDARY_ONLY` - `UNKNOWN`

Provenance must identify whether the action was observed by adapter, MCP
gateway, egress proxy, file/process/output/message/FHE broker, and
whether actual boundary observation occurred.

For high-risk effects, boundary-observed action is authoritative.

------------------------------------------------------------------------

# 8. Strict parsing, canonicalization, commitments

Reject: - duplicate JSON keys; - NaN/Infinity; - invalid UTF-8; -
unknown fields unless versioned extension allows them; - excessive
nesting; - oversized payloads; - malformed Unicode/path ambiguity.

Use RFC 8785/JCS-compatible canonicalization for JSON security objects.

Domain-separated SHA-256:

``` text
H(domain, bytes) = SHA256(UTF8(domain) || 0x00 || bytes)
```

Domains include: `ACTION`, `REQUEST`, `POLICY`, `DELEGATION`, `SESSION`,
`AUDIT`, `BEHAVIOR_STATE`, `MODEL`, `CIRCUIT`, `FHE_CONTEXT`,
`FHE_CIPHERTEXT`, `FHE_PROGRAM`, `EXECUTION_RECEIPT`.

Gateway independently recomputes ActionHash.

------------------------------------------------------------------------

# 9. OpenSSL ML-DSA Agent identity

Primary provider: **OpenSSL 3.5+ native ML-DSA via provider/EVP APIs**.

Default: `ML-DSA-65`.

Implement provider abstraction: - generate/import keys; - sign; -
verify; - provider metadata.

Do not use liboqs as primary. Optional development fallback may exist
but must be disabled by default and visibly reported.

Do not equate NIST FIPS 204 standardization with FIPS module validation.

Key lifecycle: - Agent identity != key identity; -
active/prepared/retired/revoked; - not-before/not-after; - rotation; -
emergency revocation.

Private key: - isolated signer/helper; - restricted storage in PoC; -
HSM/KMS/TEE extension point; - never exposed to LLM.

------------------------------------------------------------------------

# 10. SignedActionRequest

Signature-covered fields:

``` json
{
  "protocol_version":"3.0",
  "agent_id":"agt_...",
  "key_id":"key_...",
  "runtime_id":"runtime_...",
  "session_id":"ses_...",
  "delegation_id":"dlg_...",
  "policy_hash":"sha256:...",
  "action":{},
  "action_hash":"sha256:...",
  "timestamp":"...",
  "expires_at":"...",
  "sequence":17,
  "nonce":"...",
  "request_id":"req_..."
}
```

Use exact canonical bytes and approved domain/context.

Agent SDK maintains sequence/CSPRNG nonce but cannot authorize.

------------------------------------------------------------------------

# 11. Session, replay, freshness

Use: - timestamp; - short expiry; - \>=128-bit nonce; - monotonic
sequence; - session/runtime/delegation IDs.

Redis atomic operation must combine nonce insertion and sequence
validation/update to avoid races.

Redis unavailable -\> no protected ALLOW.

------------------------------------------------------------------------

# 12. Policy Authority and structured delegation

Agent must never self-authorize.

Trusted Policy Authority: - security administrator; - authorized user; -
orchestrator/IAM service.

Natural language may be UX input only:

``` text
Natural language
 -> policy compiler
 -> structured policy
 -> strict validation/static checks
 -> human/admin approval
 -> authoritative policy bundle
```

Active policy is deterministic, versioned, hash-pinned, and auditable.

------------------------------------------------------------------------

# 13. OPA/Rego hard policy

OPA is authoritative for deterministic rules: - capabilities; -
tools/operations; - resource/path/domain scope; - classification; -
row/byte limits; - time/environment; - sandbox profile; - secret/output
restrictions; - risk floor; - required security controls.

Output example:

``` json
{
  "allow": true,
  "risk_level": 3,
  "require_gnark": true,
  "require_behavior": true,
  "require_ezkl": true,
  "require_human_approval": false
}
```

Hard DENY is final.

Policy bundle version/hash is registry-controlled.

------------------------------------------------------------------------

# 14. gnark ZK Authorization

Purpose:

> Prove possession of trusted delegated authorization attributes for the
> exact action while minimizing disclosure.

gnark does not replace OPA.

Use a pinned reviewed stable gnark release. Benchmark Groth16 vs PLONK
on actual circuit and document selection.

Credential MUST be anchored to trusted issuer. Never let Agent invent
private witness attributes.

Conceptual statement:

``` text
There exists trusted issuer-authorized credential C such that:
 C binds to authenticated Agent
 AND valid delegation/policy
 AND not expired
 AND required capability exists
 AND resource scope covers action
 AND clearance satisfies requirement
 AND action commitment matches public action
 AND policy/delegation commitment matches approved commitment
```

If using Poseidon/field-friendly commitments in-circuit while
application uses SHA-256, define and test a deterministic bridge. Never
claim SHA-256 is constrained unless it is.

Version circuit source/compiled constraints/proving
system/curve/PK/VK/schema.

Client cannot select VK.

------------------------------------------------------------------------

# 15. Framework Adapter Layer

Adapters provide semantic visibility, not security authority.

Implement: - MCP Adapter; - LangGraph Adapter; - LangChain Adapter; -
Generic SDK; - Coding Agent runtime profile; - Agent Message adapter; -
browser extension point.

Adapter interface normalizes action/context/runtime identity.

If adapter is absent or bypassed, mandatory mediation still applies with
`BOUNDARY_ONLY` context and stricter risk policy.

------------------------------------------------------------------------

# 16. Mandatory Mediation / Enforcement Fabric

Common enforcement point behavior:

1.  observe actual operation;
2.  construct canonical AgentAction;
3.  recompute ActionHash;
4.  validate Decision Token signature/MAC;
5.  validate token nonce/use/TTL/audience/Agent/runtime/epochs;
6.  compare exact target/operation/payload constraints;
7.  execute only on match;
8.  emit Execution Receipt.

Implement: - MCP Gateway; - Network Egress Proxy; - File Broker; -
Process Broker; - Secret Broker; - Output Proxy; - Agent Message
Broker; - CAC/FHE Compute Broker.

------------------------------------------------------------------------

# 17. MCP Gateway

Agent receives gateway endpoint, not protected MCP endpoint.

Gateway: - terminates Agent-side MCP; - maps protected servers; - hides
credentials; - normalizes calls; - obtains/validates decision; -
forwards exact tool/args; - sanitizes result if policy requires; - emits
receipt.

Direct protected MCP access must fail in reference deployment.

------------------------------------------------------------------------

# 18. Network Egress Proxy

Agent runtime has no unrestricted egress in ENFORCE mode.

Use explicit proxy/sidecar/egress gateway + network policy.

Normalize: - scheme; - destination host/IP; - port; - method; - path
class; - payload hash/size; - classification if available.

Do not claim HTTPS content inspection unless TLS is actually terminated
under controlled policy.

Direct socket bypass must fail in reference deployment.

------------------------------------------------------------------------

# 19. Filesystem / File Broker

Split: - sandbox-local workspace: bounded local capability; -
sensitive/protected paths: brokered.

Protect `/secrets`, production config, host/shared sensitive areas.

File Broker binds canonical path/operation/content hash/version and
defends traversal, symlink escape, mount escape, path races.

------------------------------------------------------------------------

# 20. Process Broker / Coding Agent sandbox

Coding Agents require performance-aware sandboxing.

Machine-readable profile defines: - workspace read/write; - allowed
internal registries; - process allow/deny; - network policy; - secret
policy.

Use non-root, dropped capabilities, namespaces/container, resource
limits, seccomp/AppArmor where practical.

Do not centrally prove every local file syscall. Boundary crossings are
mediated.

Never use unrestricted `shell=True`.

------------------------------------------------------------------------

# 21. Secret Broker

Prefer use-without-disclosure.

Agent requests logical operation/secret handle. Broker/executor
retrieves secret and injects it into controlled downstream operation.

Demo must show approved DB operation without secret appearing in: -
Agent context; - response; - logs; - audit.

Direct raw secret read denied.

------------------------------------------------------------------------

# 22. Output Proxy

Protected final output is `USER_OUTPUT`.

Use ephemeral content ref + hash.

Policy/DLP-like controls: - synthetic credential detection; - PII
sample; - confidential classification.

Decisions: - ALLOW; - REDACT; - DENY.

Output release itself is consequential and audited.

------------------------------------------------------------------------

# 23. Agent Message Broker and sub-Agent delegation

Protected Agent-to-Agent communication uses broker.

Check: - sender/receiver; - purpose; - classification; - delegation; -
authority propagation.

Sub-Agent: - child capabilities subset of parent; - expiry \<= parent; -
scope cannot widen; - bounded chain depth; - revocation propagation.

Prevent authority laundering.

------------------------------------------------------------------------

# 24. Stateful Behavior Engine

Single-action security is insufficient.

Maintain per Agent/session/runtime/delegation/resource/destination
state.

Features: - actions/denials over windows; - sensitive reads; - bytes; -
external destinations; - secret accesses; - privilege attempts; -
destructive actions; - message fanout; - output classification
changes; - sequence motifs; - bypass events.

Snapshot behavior state and hash it for high-risk Judge/proof binding.

Avoid race conditions with atomic/transactional state transitions.

------------------------------------------------------------------------

# 25. Evasion / Containment Escalation Engine

First-class state machine:

``` text
NORMAL -> SUSPICIOUS -> RESTRICTED -> QUARANTINED -> TERMINATED
```

Correlate: - repeated denials; - destination/tool/protocol switching
after denial; - direct mediation bypass; - secret probing; - token/proof
misuse; - capability forgery; - sub-Agent laundering; - unusual
fanout; - security-control probing; - exfiltration sequence.

Thresholds/policies are configurable via OPA/config, not buried in code.

Containment is not merely a severity label; it changes effective
authority.

------------------------------------------------------------------------

# 26. Dynamic Capability Decay

Compute:

``` text
effective_capabilities =
intersection(
 delegated_capabilities,
 enterprise_policy,
 runtime_profile,
 containment_capability_ceiling
)
```

Example: - NORMAL: normal delegated capability; - SUSPICIOUS: remove
risky optional capability; - RESTRICTED: read-only/no external/no
secret/no new sub-Agent; - QUARANTINED: diagnostic only; - TERMINATED:
none.

Containment cannot grant authority.

------------------------------------------------------------------------

# 27. Capability/revocation epochs and recovery

Maintain: - agent_revocation_epoch; - runtime_revocation_epoch; -
policy_epoch; - capability_epoch; - risk_epoch.

Decision Token carries them. Enforcement points reject stale epochs.

On containment transition, increment capability epoch atomically.

Recovery: - no trivial time-based full restoration; - policy-controlled
cooldown + evidence, admin approval, fresh session/delegation, or
re-onboarding; - RESTRICTED/QUARANTINED recovery stricter than
SUSPICIOUS.

Kill switch supports agent/runtime/session/delegation/group and can
force QUARANTINE/TERMINATED.

------------------------------------------------------------------------

# 28. Risk-Adaptive Enforcement

Baseline every protected action: - strict parse; - ML-DSA; -
replay/session/delegation; - OPA; - audit; - containment check.

Suggested tiers: - L0 observational/public; - L1 internal low risk; - L2
sensitive read + behavior; - L3 write/external/high-value + gnark +
behavior + Judge/EZKL; - L4
secret/shell/destructive/financial/privileged/decrypt + strongest
controls + approval.

Risk may add controls, never remove mandatory baseline.

------------------------------------------------------------------------

# 29. Safety Judge

Purpose:

> Even if authorized, is this action safe in current context/history?

Use deterministic features from: - canonical action; - policy result; -
resource/data risk; - behavior snapshot; - containment state; -
intent/delegation; - destination attributes.

No LLM-only security judgment.

Small PyTorch model suitable for ZKML.

Preferred output: - UNSAFE; - REVIEW; - SAFE.

Use confidence margin; ambiguous -\> REVIEW/DENY.

Train on synthetic/adversarial scenarios, including exfiltration and
evasion. Do not overclaim detection quality.

------------------------------------------------------------------------

# 30. EZKL ZKML

Pipeline:
`PyTorch -> ONNX -> settings/calibration -> SRS -> circuit -> setup -> witness -> proof -> verify`.

Pin version/artifacts.

EZKL proves the approved mathematical Judge computation for proof-bound
inputs. It does not prove semantic correctness or OpenFHE computation.

Test PyTorch/ONNX/EZKL parity and quantization.

Proof binding: - public proof-bound feature/instance representation; -
Gateway independently derives expected features from exact
action/policy/behavior/containment snapshot; - verifier checks equality
and SAFE predicate; - model/circuit/VK registry pinned.

Metadata next to proof is not cryptographic binding.

------------------------------------------------------------------------

# 31. Decision Token v3

Token is a short-lived execution capability.

Include: - decision ID; - Agent/runtime/session; - ActionHash/type; -
target/operation/payload constraints; - policy hash; - risk; -
containment state; - revocation/policy/capability/risk epochs; -
issued/not-before/expiry; - max uses; - nonce; - enforcement audience; -
checks performed.

Gateway-only signing/MAC key.

Default single-use, short TTL.

Enforcement point independently observes action and validates exact
match.

------------------------------------------------------------------------

# 32. Execution Receipt

Enforcement point returns authenticated receipt:

``` json
{
  "receipt_version":1,
  "decision_id":"dec_...",
  "action_hash":"sha256:...",
  "enforcement_point_id":"...",
  "executed_at":"...",
  "result_status":"SUCCESS",
  "result_hash":"sha256:...",
  "token_nonce":"..."
}
```

Audit lifecycle:
`PROPOSED -> AUTHORIZED -> TOKEN_ISSUED -> ACTUAL_ACTION_OBSERVED -> EXECUTED -> RECEIPT`.

Control Plane must not assume execution merely because ALLOW was issued.

------------------------------------------------------------------------

# 33. Deployment modes and onboarding

Modes: - OBSERVE; - WARN; - ENFORCE; - QUARANTINE.

OBSERVE is not security enforcement.

Onboarding: 1. identity; 2. framework/runtime profile; 3.
policy/delegation; 4. risk; 5. sandbox; 6.
MCP/network/file/process/secret/output/message policies; 7. adapter; 8.
enforcement conformance tests; 9. activate.

Conformance test must verify direct bypass blocking, mediated happy/deny
paths, token binding, adapter context, kill switch.

Unknown framework fallback: - sandbox; - deny direct protected egress; -
brokers/gateways; - boundary-only context; - semantic adapter later.

------------------------------------------------------------------------

# 34. Audit / SIEM / observability

Audit: - identity/key; - session/delegation; - policy; -
action/provenance; - risk/containment; -
OPA/gnark/behavior/Judge/EZKL; - Decision Token; - enforcement point; -
receipt; - FHE lineage where applicable.

Hash-chain events. Periodically ML-DSA-sign checkpoints with dedicated
audit identity if feasible.

Never log secret/plaintext/key share.

Metrics include decision counts, denials, bypasses, containment
transitions, proof latency, FHE latency, kill-switch propagation.

------------------------------------------------------------------------

# 35. CAC --- Confidential Agent Collaboration

CAC allows approved computation on sensitive data without plaintext
disclosure to compute-only Agents.

The permission model MUST distinguish:

``` text
READ PLAINTEXT
COMPUTE ON CIPHERTEXT
DECRYPT RESULT
```

Example: - Data Owner: read/compute/decrypt; - Analytics Agent: compute
only; - Security Supervisor: approved decrypt; - unauthorized Agent:
none.

CAC remains subject to normal CV-ZTTE
identity/policy/authorization/behavior/containment/token/audit.

------------------------------------------------------------------------

# 36. OpenFHE integration

Primary FHE library: **OpenFHE**.

Codex must resolve/pin current stable version and real APIs.

Prefer a narrow native C++ FHE broker/service.

Smoke test: - context/key setup; - encrypt; - evaluate; - decrypt; -
supported multiparty/threshold workflow.

No toy crypto.

Scheme selection: - CKKS for approximate real analytics; - BFV/BGV for
exact integer arithmetic; - FHEW/TFHE/scheme switching only when
justified.

Initial E2E scenario uses CKKS.

------------------------------------------------------------------------

# 37. FHE Context Registry

Registry-controlled context:

``` json
{
  "context_id":"ckks-employee-risk-v1",
  "scheme":"CKKS",
  "openfhe_version":"...",
  "security_profile":"secure-lab",
  "ring_dimension":0,
  "multiplicative_depth":0,
  "scaling_parameters":{},
  "batch_size":0,
  "key_epoch":3,
  "threshold":{"enabled":true,"participants":3,"required_semantics":"documented"},
  "context_hash":"sha256:...",
  "status":"ACTIVE"
}
```

Use OpenFHE-supported security settings. If demo parameters are weaker,
label clearly and provide secure-lab profile.

Agent cannot supply crypto parameters.

------------------------------------------------------------------------

# 38. Ciphertext and result envelopes

Ciphertext envelope includes: - dataset ID; - ciphertext ID; - context
ID; - key epoch; - schema; - classification; - owner; - ciphertext
hash; - creation time; - allowed-program-set hash.

Result envelope additionally includes: - parent ciphertext IDs; -
program ID/version; - result ciphertext hash; - lineage ID.

Reject context/key epoch/ciphertext substitution.

------------------------------------------------------------------------

# 39. FHE Program Registry

Allowlisted programs only, e.g.: - SUM_V1; - AVERAGE_V1; -
WEIGHTED_SCORE_V1; - THRESHOLD_COUNT_V1 if supported safely.

Manifest: - input schema; - scheme; - depth; - shapes; - implementation
hash; - leakage notes; - benchmark; - policy classification.

No arbitrary Agent-uploaded computation by default.

------------------------------------------------------------------------

# 40. FHE Compute Broker

Flow:

``` text
Agent -> FHE_COMPUTE -> CV-ZTTE
 ML-DSA -> OPA -> gnark -> containment/risk -> optional Judge/EZKL
 -> Decision Token -> FHE Broker -> OpenFHE Evaluate -> encrypted result
```

Broker validates exact: - dataset; - ciphertext; - context; - key
epoch; - program; - token audience/action; - containment/capability
epoch.

Compute Agent gets ciphertext/result reference, not secret key shares.

------------------------------------------------------------------------

# 41. Threshold / multiparty FHE

Implement genuine OpenFHE-supported multiparty/threshold decryption.

Reference participants: - Data Owner Authority; - Security/Privacy
Authority; - CV-ZTTE Decryption Authority.

Prefer separate processes/containers.

Important: document actual OpenFHE protocol semantics. Do not label it
generic `2-of-3` unless the actual selected workflow supports that
threshold. If all configured parties are required, say so.

No service should persist a reconstructed full secret key.

Secret shares never enter LLM/log/audit.

------------------------------------------------------------------------

# 42. Decryption workflow

Decryption is separate high-risk action.

``` text
Encrypted Result
 -> FHE_DECRYPT_REQUEST
 -> ML-DSA/OPA/gnark
 -> containment/risk
 -> approval if required
 -> Decision Token
 -> partial decrypt participants
 -> combine
 -> Output Proxy / release policy
 -> authorized consumer
```

Compute authority does not imply decrypt.

Plaintext release evaluates classification, recipient, purpose,
aggregation/minimization, and audit.

------------------------------------------------------------------------

# 43. gnark / EZKL / FHE role separation

-   ML-DSA: who signed?
-   OPA: enterprise policy?
-   gnark: prove trusted capability/delegation predicate?
-   Behavior/Containment: is Agent acting abnormally/persistently
    evasive?
-   Judge: should this authorized action proceed in context?
-   EZKL: prove Judge computation?
-   OpenFHE: compute without plaintext disclosure?

Do not claim: - FHE is authorization; - gnark proves OpenFHE
evaluation; - EZKL proves OpenFHE evaluation; - ZKP proves
business-policy correctness.

------------------------------------------------------------------------

# 44. Agent-to-Agent confidential messaging

Preferred: - ciphertext stored in CAC; - Agent Message Broker carries
`ciphertext_ref` + purpose, not large raw crypto/plaintext; - receiving
Agent requests FHE Compute Broker.

Policy checks recipient, dataset, purpose, compute capability,
containment.

Optional PRE extension only if justified; re-encryption itself is
controlled AgentAction.

------------------------------------------------------------------------

# 45. Confidential Query Governance

FHE does not prevent inference from permitted plaintext outputs.

Track per Agent/dataset/session/purpose: - decrypt count; - query
frequency; - overlapping subsets; - result precision; - aggregation
size; - differencing patterns.

Policy can: - rate-limit; - require minimum group size; -
round/minimize; - deny individual-value release; - require approval; -
restrict repeated overlapping queries.

Do not call this differential privacy unless actual DP noise/accounting
is implemented.

Provide DP extension point.

------------------------------------------------------------------------

# 46. FHE resource-exhaustion controls

Limit: - ciphertext size; - batch/vector size; - depth; - allowed
programs; - queue; - CPU/memory; - timeout; - per-Agent/dataset quota; -
rate.

Repeated abusive expensive requests feed Behavior/Containment and can
trigger capability decay.

------------------------------------------------------------------------

# 47. Containment + CAC integration

Containment ceilings apply to FHE:

-   NORMAL: delegated FHE compute/decrypt according to policy;
-   SUSPICIOUS: lower-risk approved compute only;
-   RESTRICTED: pre-approved datasets/programs, no decrypt;
-   QUARANTINED: no compute/decrypt;
-   TERMINATED: none.

Capability epoch invalidates stale CAC tokens.

------------------------------------------------------------------------

# 48. Human / multi-party approval

L4 actions may require approval: - destructive DB; - production
deployment; - credential export; - financial; - privilege change; -
sensitive FHE decrypt.

Approval binds exact ActionHash and expires.

Support one-admin PoC; extension for two-person/threshold approval.

------------------------------------------------------------------------

# 49. Repository structure

Recommended:

``` text
cv-ztte/
├── CV-ZTTE_Codex_Implementation_Spec_v3.md
├── CODEX_TASK_v3.md
├── README.md
├── Makefile
├── docker-compose.yml
├── pyproject.toml
├── go.work
├── apps/
│   ├── agent-demo/
│   ├── gateway/
│   ├── protected-tool/
│   ├── output-proxy/
│   └── egress-proxy/
├── cvztte/
│   ├── action/
│   ├── context/
│   ├── canonical/
│   ├── identity/
│   ├── policy/
│   ├── delegation/
│   ├── replay/
│   ├── behavior/
│   ├── containment/
│   ├── capability_decay/
│   ├── judge/
│   ├── ezkl/
│   ├── decision/
│   ├── audit/
│   ├── onboarding/
│   ├── adapters/
│   ├── cac/
│   ├── confidential_query/
│   └── lineage/
├── services/
│   ├── zk-authz/              # Go/gnark
│   ├── fhe-broker/            # C++/OpenFHE
│   ├── fhe-key-authority-a/
│   ├── fhe-key-authority-b/
│   ├── fhe-key-authority-c/
│   └── decrypt-coordinator/
├── enforcement/
│   ├── mcp-gateway/
│   ├── egress-proxy/
│   ├── file-broker/
│   ├── process-broker/
│   ├── secret-broker/
│   ├── output-proxy/
│   └── agent-message-broker/
├── policy/rego/
├── artifacts/
│   ├── gnark/
│   ├── judge/
│   └── fhe/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── adversarial/
│   └── performance/
└── docs/
```

------------------------------------------------------------------------

# 50. Error taxonomy

Implement structured codes covering: - parser/schema; -
Agent/key/ML-DSA; - replay/session/delegation; - OPA; - gnark; -
behavior; - containment/capability epoch; - Judge/EZKL; -
token/receipt; - bypass; - FHE
context/ciphertext/program/compute/decrypt/threshold/query governance; -
dependency unavailable.

External responses must not expose secrets, key shares, witness data,
internal paths, or stack traces.

------------------------------------------------------------------------

# 51. Mandatory adversarial test families

The final suite MUST include at least the following families, with
individual cases:

### Identity/integrity

forged Agent, wrong/revoked key, signature mutation,
action/session/policy mutation.

### Replay

exact replay, nonce reuse, sequence rollback, concurrent duplicate,
expired request/token.

### Policy/delegation

self-issued policy, scope widening, child \> parent, expired/revoked
delegation.

### gnark

fake clearance/capability, untrusted issuer, action/policy proof
substitution, proof/VK/circuit mutation.

### Behavior/evasion

multi-step exfiltration, repeated denial, destination/tool/protocol
switching, secret probing, privilege probing.

### Containment

state escalation, capability shrink, stale epoch token, quarantine
across every broker, unauthorized de-escalation, termination.

### EZKL

proof substitution, public-input mismatch, model/circuit/VK
substitution, SAFE metadata forgery, quantization boundary.

### Enforcement

SDK bypass, direct MCP, direct socket, direct DB, sensitive file,
process escape, token target/method/payload/audience mismatch, TOCTOU.

### Output/secrets

credential/PII/confidential output, raw secret read, secret in
logs/context.

### Multi-Agent

unauthorized peer, authority laundering, revoked parent/child.

### FHE/CAC

real encrypted compute, no plaintext for compute-only Agent, compute !=
decrypt, unauthorized program, arbitrary-program denial,
ciphertext/context/key-epoch substitution, threshold insufficiency,
wrong participant/share, key-share leakage tests, unauthorized
recipient, decrypt release policy, query-governance inference attempts,
FHE DoS, rotation.

### Failure injection

Redis/OPA/gnark/Judge/EZKL/OpenFHE/enforcement/audit failure.

All DENY cases assert: - protected side-effect count = 0; - unauthorized
plaintext release count = 0.

At least one complete E2E path MUST use real ML-DSA + OPA + gnark +
Behavior/Containment + EZKL (when risk requires) + actual Enforcement
Fabric.

At least one CAC E2E path MUST use real OpenFHE and genuine configured
multiparty/threshold decryption.

------------------------------------------------------------------------

# 52. Performance realism

Measure: - parse/canonicalization; - ML-DSA sign/verify; - Redis; -
OPA; - gnark prove/verify; - behavior/containment; - Judge; - EZKL
witness/prove/verify; - Decision Token; - enforcement proxy/broker; -
kill/quarantine propagation; - OpenFHE encrypt/evaluate/decrypt; -
ciphertext size/memory; - threshold partial/combine; - total latency per
risk tier.

Use bounded queues/backpressure.

Coding Agent benchmark must show sandbox-local work avoids central
per-file proof overhead.

Do not fabricate enterprise throughput.

------------------------------------------------------------------------

# 53. Deployment profiles

Provide:

### demo

Fast hackathon-friendly settings, clearly labeled.

### secure-lab

Security-appropriate crypto/runtime parameters, separate threshold
parties, stronger isolation.

### enterprise-reference

Configuration skeleton for: - separate services/hosts; - mTLS; -
HSM/KMS/TEE; - HA Redis/state; - SIEM/SOC; - signed policy/model/circuit
releases; - SBOM/image signing; - secure clock; - DR; - external
cryptographic/security audit.

Never call enterprise-reference production-certified.

------------------------------------------------------------------------

# 54. Implementation phases

## Phase 0 --- Environment/feasibility

Real smoke tests for all foundations.

## Phase 1 --- Core canonical models

AgentAction, AgentContext, provenance, strict parser, hashes.

## Phase 2 --- Identity

OpenSSL ML-DSA, signer isolation, registry, rotation/revocation.

## Phase 3 --- Sessions/delegation/replay

Policy Authority, Redis atomic freshness.

## Phase 4 --- OPA/risk

Rego bundles and risk requirements.

## Phase 5 --- gnark authorization

Trusted credential anchoring, circuit, proof binding.

## Phase 6 --- Adapters

MCP/LangGraph/LangChain/Generic/Coding.

## Phase 7 --- Enforcement Fabric

MCP/egress/file/process/secret/output/message.

## Phase 8 --- Decision Token/receipts

Exact execution binding and epochs.

## Phase 9 --- Behavior

History/state/sequence analysis.

## Phase 10 --- Containment/capability decay

State machine, quarantine, recovery, kill switch.

## Phase 11 --- Safety Judge

Deterministic features, PyTorch/ONNX.

## Phase 12 --- EZKL

Real proof, binding, quantization guard.

## Phase 13 --- Onboarding/modes

Conformance tests, OBSERVE/WARN/ENFORCE/QUARANTINE.

## Phase 14 --- OpenFHE/CAC foundations

Context/program/ciphertext registries and real CKKS.

## Phase 15 --- Threshold FHE/decrypt

Separate participants and release policy.

## Phase 16 --- Confidential query governance/lineage

Inference-leakage controls and lineage.

## Phase 17 --- Full integration

Containment + CAC + risk + approval + brokers.

## Phase 18 --- Adversarial/failure suite

All families.

## Phase 19 --- Performance/hardening

Resource limits, secure/demo profiles.

## Phase 20 --- Documentation/security review/demo

Final evidence.

Each phase: test -\> docs -\> Git commit.

------------------------------------------------------------------------

# 55. Required final documentation

Create at minimum:

``` text
docs/ENVIRONMENT.md
docs/IMPLEMENTATION_PLAN.md
docs/IMPLEMENTATION_NOTES.md
docs/ARCHITECTURE.md
docs/THREAT_MODEL.md
docs/ACTION_MODEL.md
docs/POLICY_MODEL.md
docs/GNARK_BINDING.md
docs/EZKL_BINDING.md
docs/FRAMEWORK_ADAPTERS.md
docs/ENFORCEMENT_FABRIC.md
docs/DECISION_TOKEN.md
docs/EXECUTION_RECEIPTS.md
docs/BEHAVIOR_ENGINE.md
docs/CONTAINMENT_ENGINE.md
docs/DYNAMIC_CAPABILITY_DECAY.md
docs/AGENT_ONBOARDING.md
docs/SHADOW_MODE.md
docs/KILL_SWITCH.md
docs/CAC_ARCHITECTURE.md
docs/OPENFHE_INTEGRATION.md
docs/FHE_SECURITY_MODEL.md
docs/THRESHOLD_FHE.md
docs/CONFIDENTIAL_QUERY_GOVERNANCE.md
docs/DATA_LINEAGE.md
docs/PERFORMANCE.md
docs/DEPLOYMENT.md
docs/DEMO.md
docs/FINAL_SECURITY_REVIEW.md
docs/FINAL_COMPLETION_REPORT.md
```

------------------------------------------------------------------------

# 56. Final security review questions

The final review MUST answer, from actual code:

1.  exact ML-DSA signed bytes/provider;
2.  key isolation/revocation;
3.  atomic replay;
4.  Policy Authority and self-authorization prevention;
5.  OPA decision semantics;
6.  gnark exact statement/public/private inputs/issuer anchoring;
7.  Action proof binding;
8.  adapter bypass behavior;
9.  mandatory mediation for each resource;
10. Decision Token exact constraints/epochs/audience;
11. actual action observation and TOCTOU;
12. Execution Receipt trust;
13. Behavior snapshot consistency;
14. evasion evidence and containment transitions;
15. capability-decay monotonicity/recovery;
16. quarantine propagation;
17. Judge semantics;
18. EZKL exact statement/public inputs/SAFE predicate/quantization;
19. FHE scheme/parameters/context integrity;
20. where plaintext can exist;
21. threshold key-share holders and actual threshold semantics;
22. whether any one party can decrypt;
23. FHE program allowlisting;
24. READ/COMPUTE/DECRYPT enforcement;
25. confidential-query inference leakage;
26. output release;
27. failure behavior of every dependency;
28. remaining TCB;
29. production gaps;
30. first external audit priorities.

Unanswered items block completion.

------------------------------------------------------------------------

# 57. Definition of Done

Complete only if:

-   real OpenSSL ML-DSA works;
-   real OPA works;
-   real gnark proof works with trusted credential anchoring;
-   real EZKL proof works with sound action/context binding;
-   real OpenFHE encrypted compute works;
-   genuine configured multiparty/threshold decrypt path works;
-   Generalized AgentAction and semantic adapters work;
-   malicious adapter bypass is stopped by mandatory mediation;
-   Tool/network/file/process/secret/output/message paths are
    controlled;
-   Decision Token and Execution Receipt bind decision to actual effect;
-   Behavior Engine detects sequences;
-   repeated evasion causes containment escalation;
-   Dynamic Capability Decay removes real capabilities;
-   stale tokens fail after epoch changes;
-   quarantine is enforced by brokers/proxies;
-   Agent cannot self-recover;
-   sub-Agent authority cannot widen;
-   READ/COMPUTE/DECRYPT are separate;
-   compute-only Agent never receives source plaintext/key shares;
-   confidential-query governance prevents configured inference
    patterns;
-   audit chain exists;
-   all adversarial/failure tests pass;
-   performance evidence exists;
-   docs accurately state limitations.

------------------------------------------------------------------------

# 58. Final demonstrations

## Demo A --- legitimate normal Agent

Normal authorized action succeeds through appropriate risk path.

## Demo B --- authenticated but unauthorized

ML-DSA passes; OPA/gnark denies.

## Demo C --- proof substitution

Action A proof/token cannot execute B.

## Demo D --- framework bypass

Agent bypasses SDK; direct HTTP/MCP/file attempt is forced/blocked by
Enforcement Fabric.

## Demo E --- persistent malicious Agent

Repeated evasion: `NORMAL -> SUSPICIOUS -> RESTRICTED -> QUARANTINED`,
capability epoch changes, stale token fails, all protected effects
blocked.

## Demo F --- secret/output protection

Secret broker use-without-disclosure and output redaction/deny.

## Demo G --- multi-Agent authority

Unauthorized peer/sub-Agent widening denied.

## Demo H --- Confidential Agent Collaboration

Synthetic sensitive vector encrypted with OpenFHE; Analytics Agent
computes approved aggregate without plaintext; cannot decrypt;
authorized requester passes high-risk policy/approval; genuine
multiparty/threshold decrypt releases only approved aggregate.

## Demo I --- confidential-query abuse

Repeated overlapping decrypt queries trigger governance and
deny/escalate.

------------------------------------------------------------------------

# 59. Final acceptance challenge

Assume a legitimate Agent with its valid ML-DSA identity is fully
prompt-injected and actively malicious.

It tries: - SDK bypass; - direct MCP/network/DB/file/process; - secret
extraction; - output exfiltration; - capability forgery; - proof/token
reuse; - TOCTOU; - destination/tool/protocol switching; - sub-Agent
authority laundering; - stale token use after containment; - FHE program
abuse; - ciphertext/context substitution; - threshold-share theft; -
repeated aggregate inference; - dependency-failure exploitation.

Attacker does not control the Policy Authority, trust registries,
Decision Token authority, Enforcement Fabric, threshold authorities, or
host/kernel outside the declared threat model.

Acceptance requires:

> **No unauthorized consequential side effect occurs.**

> **No unauthorized plaintext disclosure occurs.**

> **Persistent evasion causes authority to contract and eventually
> contain the Agent.**

> **Useful approved computation remains possible without unnecessary
> plaintext disclosure.**

------------------------------------------------------------------------

# 60. Normative Detailed Preservation Requirements from v2/v2.1/v2.2

This section is intentionally detailed. It preserves
implementation-level requirements from the historical v2, v2.1, v2.2,
and v2 task directive that are easy to lose when architecture is
summarized. If any earlier section of this v3 master specification is
less specific than this section, the stricter requirement here applies.

## 60.1 Environment inventory

`docs/ENVIRONMENT.md` MUST explicitly record:

-   OS/distribution and architecture;
-   Python version;
-   Go version;
-   OpenSSL runtime version and development headers;
-   loaded/available OpenSSL providers;
-   whether the selected provider actually exposes ML-DSA;
-   Docker or Podman;
-   Redis;
-   OPA;
-   PyTorch;
-   ONNX;
-   EZKL;
-   gnark;
-   gnark-crypto;
-   C/C++ compiler;
-   CMake;
-   OpenFHE;
-   exact pinned dependency versions/commits.

The implementation MUST distinguish "algorithm standardized by NIST"
from "selected provider/module is FIPS validated".

## 60.2 Exact OpenSSL ML-DSA requirements

Default algorithm is `ML-DSA-65`. Future policy MAY permit
ML-DSA-44/65/87, but automatic downgrade is forbidden.

The signature provider abstraction MUST expose the equivalent of:

``` text
generate_key
import_private_key
import_public_key
sign
verify
algorithm
provider_metadata
```

Primary provider is native OpenSSL. A liboqs fallback MAY exist only for
development compatibility, MUST be disabled by default, MUST be visibly
reported, and MUST NOT be presented as the production-equivalent path.

Prefer a small native signing helper/sidecar or carefully maintained
binding using provider-aware OpenSSL EVP APIs. Where practical, create
OpenSSL CLI/API smoke tests independent of application logic.

Production evolution points MUST include HSM/KMS/TEE-backed opaque keys,
rotation, revocation, validity periods, a dedicated audit-signing
identity, and separation of Agent identity from key identity.

## 60.3 SignedActionRequest minimum fields

The canonical signed request MUST cover at least:

``` json
{
  "protocol_version": "3.0",
  "agent_id": "agt_...",
  "key_id": "key_...",
  "session_id": "ses_...",
  "delegation_id": "dlg_...",
  "policy_hash": "sha256:...",
  "action": {},
  "action_hash": "sha256:...",
  "timestamp": "...",
  "expires_at": "...",
  "sequence": 17,
  "nonce": "...",
  "request_id": "req_...",
  "runtime_id": "runtime_..."
}
```

All security-relevant fields are signature-covered. Nonce uses a CSPRNG.
The LLM never receives the private key.

## 60.4 Structured policy minimum semantics

The policy model MUST be able to express at least:

-   DB read/write resource sets;
-   filesystem read/write path scopes;
-   network domain allowlists and external-network prohibition;
-   output credential/PII/classification constraints;
-   allowed Agent peers;
-   maximum DB rows;
-   maximum external bytes;
-   shell permission;
-   secret-access permission;
-   clearance;
-   validity interval.

OPA MUST support capability, action type, resource scope, path/domain,
classification, row/byte limits, time/environment/session constraints,
and separation-of-duty rules.

OPA decision output MUST carry the equivalent of:

``` json
{
  "allow": true,
  "reason_code": "...",
  "risk_level": 3,
  "require_gnark_authz": true,
  "require_behavior_check": true,
  "require_ezkl": true,
  "require_human_approval": false
}
```

## 60.5 gnark implementation details

The implementation MUST benchmark Groth16 and PLONK on the actual
authorization circuit and document the selected backend and curve.

Capability credentials MAY privately encode Agent binding, role,
clearance, capability bitset, resource-scope commitment, expiry,
policy/delegation version, and issuer commitment.

At minimum, proof public inputs/commitments MUST bind:

-   exact action or deterministic field-friendly action commitment;
-   approved policy/delegation commitment;
-   authenticated Agent or sound pseudonymous binding;
-   circuit version;
-   expiry/current epoch representation where sound;
-   required capability identifier.

If application binding uses SHA-256 while the circuit uses Poseidon or
another field-friendly hash, `docs/GNARK_BINDING.md` MUST define the
deterministic bridge and its substitution tests.

The gnark registry MUST version:

-   circuit source hash;
-   compiled constraint-system hash;
-   proving system;
-   curve;
-   proving key;
-   verification key;
-   credential schema version.

The Go service SHOULD retain the conceptual layout:

``` text
services/zk-authz/
  cmd/
  circuit/
  credential/
  prover/
  verifier/
  registry/
  tests/
```

It MUST expose narrow internal issue/prove/verify functions, with
credential issuance restricted to the trusted administration path.

## 60.6 Behavior state details

Behavior state MUST support rolling windows such as 10s/60s/5m and at
minimum consider:

``` text
actions_last_60s
sensitive_reads_last_5m
bytes_read
bytes_written
external_bytes
unique_resources
secret_access_count
policy_denials
privilege_escalation_attempts
new_external_destination
destructive_action_count
agent_message_fanout
```

The implementation MUST distinguish proposed, denied, bypass-attempted,
executed, and failed-execution events so a cooperative proposal and its
eventual execution are not double-counted as two independent attacks.

For proof/Judge flows, behavior state MUST have a canonical
snapshot/version/hash.
Snapshot/evaluate/reserve-or-lock/execute/event-append ordering must be
made race-safe as practical.

## 60.7 Risk tiers and decisions

The system MUST support:

``` text
L0 observational/public
L1 internal low risk
L2 sensitive read
L3 write/external/high-value
L4 secret/shell/destructive/financial/privileged/decrypt
```

Baseline controls remain schema + ML-DSA + freshness/replay + active
policy/session + OPA + audit.

The decision engine MUST support:

``` text
ALLOW
DENY
ESCALATE
SANDBOX
REDACT
RATE_LIMIT
```

High-risk asynchronous actions MAY use `PENDING_SECURITY_REVIEW` rather
than blocking a UI thread indefinitely.

## 60.8 Safety Judge and EZKL details

The reference Judge SHOULD begin with a compact auditable MLP, e.g.:

``` text
N features -> Dense(32) -> ReLU -> Dense(16) -> ReLU -> Dense(3)
```

with `UNSAFE`, `REVIEW`, and `SAFE`.

Training data MUST include synthetic normal behavior,
prompt-injection-induced dangerous actions, exfiltration sequences, bulk
access, credential access, privilege escalation, suspicious external
destinations, and benign administrative exceptions.

PyTorch, ONNX, and EZKL outputs MUST be parity-tested. Decision margins
MUST protect against quantization boundary flips; ambiguous cases become
REVIEW/DENY.

The EZKL artifact manifest MUST record:

-   model hash;
-   feature-extractor version/hash;
-   ONNX opset;
-   settings hash;
-   circuit hash;
-   SRS hash;
-   PK hash;
-   VK hash;
-   EZKL version;
-   visibility/public-input configuration;
-   decision encoding;
-   quantization calibration metadata.

Startup MUST recompute hashes and reject artifact drift.

## 60.9 Framework adapter exact requirements

The adapter layer MUST include concrete or reference implementations
for:

-   MCP;
-   LangGraph;
-   LangChain;
-   Generic/custom SDK;
-   Coding Agent runtime;
-   Agent-to-Agent messaging.

Browser Agent integration is an experimental extension point. If the
browser automation stack is available, observe
destination/navigation/form submission/upload/download/file upload. If
unavailable, preserve the interfaces and document the limitation without
blocking core completion.

The generic adapter contract SHOULD provide equivalents of:

``` python
normalize_action(framework_event)
semantic_context(framework_event)
runtime_identity(framework_event)
```

Adapters normalize/enrich/propose only; they never directly authorize.

## 60.10 AgentContext quality and provenance

Semantic context quality MUST support:

``` text
RICH
PARTIAL
BOUNDARY_ONLY
UNKNOWN
```

High-risk actions with insufficient required context default to
DENY/ESCALATE. Low-risk boundary-only actions are allowed only by
explicit policy.

Action provenance MUST identify the source boundary, adapter ID, runtime
ID, observation time, and whether actual enforcement-point observation
occurred.

For high-risk effects, enforcement-point observation is authoritative.

## 60.11 Decision Token v3 minimum fields

The execution capability MUST contain the equivalent of:

``` json
{
  "token_version": 3,
  "decision_id": "dec_...",
  "request_id": "req_...",
  "agent_id": "agt_...",
  "runtime_id": "runtime_...",
  "session_id": "ses_...",
  "action_hash": "sha256:...",
  "action_type": "NETWORK_REQUEST",
  "target_constraint": "api.internal.example",
  "operation_constraint": "POST",
  "payload_hash": "sha256:...",
  "policy_hash": "...",
  "risk_level": 3,
  "containment_state": "NORMAL",
  "decision": "ALLOW",
  "issued_at": "...",
  "not_before": "...",
  "expires_at": "...",
  "max_uses": 1,
  "nonce": "...",
  "audience": "egress-proxy-01",
  "agent_revocation_epoch": 7,
  "runtime_revocation_epoch": 2,
  "policy_epoch": 11,
  "capability_epoch": 4,
  "risk_epoch": 9,
  "checks": {
    "mldsa": true,
    "opa": true,
    "gnark": true,
    "behavior": true,
    "judge": "SAFE",
    "ezkl": true
  }
}
```

Default is single-use and very short TTL. Token replay MUST be tracked.
Broad wildcards are forbidden unless explicitly modeled as a bounded
sandbox capability.

## 60.12 Enforcement Fabric exact requirements

### MCP Gateway

MUST terminate Agent-side MCP connectivity, hide protected server
addresses/credentials, normalize calls, request a decision, validate the
execution capability, forward the exact approved tool/arguments,
optionally sanitize result, audit, and issue an Execution Receipt.

### Egress Proxy

MUST normalize destination/IP/host/port/method/path class/payload
hash/byte estimate/classification where visible. It MUST support domain
allowlists, internal/external distinction, byte limits, and
secret/confidential egress policy.

### File Broker

MUST support FILE_READ/WRITE/DELETE and defend against `..`, symlink
escape, mount escape, and path substitution/races. Descriptor-based safe
resolution is preferred.

### Process Broker

Coding profiles MUST support command allow/deny, non-root runtime,
dropped Linux capabilities, namespaces/container isolation, resource
limits, and seccomp/AppArmor where practical. `shell=True` unrestricted
execution is forbidden.

### Secret Broker

At least one real use-without-disclosure flow is mandatory.

### Output Proxy

MUST demonstrate synthetic credential, PII, and confidential-data
controls.

### Agent Message Broker

MUST enforce sender, receiver, purpose/delegation, classification, and
capability propagation.

## 60.13 Coding Agent performance model

A coding Agent MUST be able to perform high-frequency ordinary work
inside an approved workspace without central proof per syscall.

At minimum benchmark repository scan/build/test under the sandbox and
demonstrate that external network, sensitive filesystem, secrets,
production APIs, protected MCP, privileged commands, and protected
output still cross mandatory mediation.

## 60.14 Agent onboarding and conformance

`AgentRuntimeProfile` MUST cover:

1.  Agent identity;
2.  framework/runtime type;
3.  delegation/policy template;
4.  risk profile;
5.  sandbox profile;
6.  Tool/MCP policy;
7.  network policy;
8.  filesystem policy;
9.  secret policy;
10. output policy;
11. semantic adapter;
12. activation state.

Before `ENFORCED`, automatically verify:

-   direct protected Tool blocked;
-   direct external egress blocked where required;
-   sensitive file unavailable directly;
-   secret unavailable directly;
-   approved mediated action succeeds;
-   denied action fails;
-   Decision Token exact binding;
-   adapter context if installed;
-   kill switch.

Activation fails if mandatory controls are absent.

## 60.15 Deployment modes and shadow-mode reporting

Support:

``` text
OBSERVE
WARN
ENFORCE
QUARANTINE
```

Mode changes are admin-only and audited.

OBSERVE MUST produce `WOULD_ALLOW/WOULD_DENY` and is explicitly not
security enforcement.

Shadow-mode reports SHOULD include: - false-positive review
candidates; - missing policy; - normal behavior baseline; - unknown
destinations; - adapter coverage; - bypass attempts.

Recommended rollout:

``` text
OBSERVE -> WARN -> high-confidence hard-rule enforcement
        -> high-risk enforcement -> broader enforcement
```

## 60.16 Kill switch and synchronization

Kill/revocation scope MUST include: - agent_id; - runtime_id; -
session_id; - delegation_id; - optional group/type.

Kill prevents new tokens and causes brokers/proxies to deny. Reference
implementation MUST measure/test propagation latency.

## 60.17 Execution Receipt exact minimum

Receipt MUST contain at least:

``` json
{
  "receipt_version": 1,
  "decision_id": "dec_...",
  "action_hash": "sha256:...",
  "enforcement_point_id": "egress-proxy-01",
  "executed_at": "...",
  "result_status": "SUCCESS",
  "result_hash": "sha256:...",
  "token_nonce": "..."
}
```

Forged/mismatched receipts MUST be rejected/audited.

## 60.18 Containment evidence and transitions

Containment MUST track at least:

-   hard-policy denials;
-   direct Tool/network bypass;
-   denied secret access;
-   path/sandbox escape;
-   alternative destination after denial;
-   tool/protocol switching after denial;
-   proof/token misuse;
-   capability forgery;
-   sub-Agent authority laundering;
-   unexpected message fanout;
-   model/circuit/VK substitution attempts;
-   stale/replayed token use;
-   unusual privilege/process attempts;
-   high-risk output exfiltration;
-   security-control probing.

Feature examples:

``` text
denials_60s
denials_5m
unique_denied_destinations
bypass_attempts_5m
secret_probe_count
privilege_probe_count
tool_switch_after_deny
destination_switch_after_deny
protocol_switch_after_deny
proof_substitution_attempts
token_misuse_attempts
subagent_escalation_attempts
sensitive_read_to_egress_sequence
```

Transition thresholds MUST be policy/config controlled rather than
hardcoded.

Reference transition semantics:

``` text
NORMAL -> SUSPICIOUS:
  repeated unusual/denied behavior

SUSPICIOUS -> RESTRICTED:
  repeated policy denial or bypass

RESTRICTED -> QUARANTINED:
  mandatory-mediation bypass, secret exfiltration attempt, repeated evasion

QUARANTINED -> TERMINATED:
  sandbox-escape indicator, continued attack, or explicit administrator kill
```

## 60.19 Capability decay exact semantics

Effective capability MUST be computed as:

``` text
intersection(
  delegated_capabilities,
  enterprise_policy,
  runtime_profile,
  containment_capability_ceiling
)
```

Reference ceilings:

``` text
NORMAL:
  delegated capability

SUSPICIOUS:
  remove optional high-risk capabilities

RESTRICTED:
  READ_ONLY
  NO_EXTERNAL_NETWORK
  NO_SECRET_ACCESS
  NO_NEW_SUBAGENTS
  FHE_COMPUTE only on pre-approved datasets/programs

QUARANTINED:
  diagnostic/status only

TERMINATED:
  no runtime authority
```

On containment change, increment `capability_epoch` atomically,
invalidate stale tokens, update enforcement caches, and audit.

Recovery defaults: - SUSPICIOUS may recover after cooldown + clean
evidence; - RESTRICTED requires admin or fresh authenticated
session/delegation; - QUARANTINED requires admin; - TERMINATED requires
re-onboarding/new runtime.

## 60.20 Quarantine behavior

QUARANTINE MUST: - deny new consequential tokens; - invalidate stale
capabilities; - block egress; - block protected MCP; - block secrets; -
isolate Agent messages; - restrict output to policy-approved
diagnostics/user-safe output; - optionally disconnect runtime
networking; - emit high-severity SOC/SIEM telemetry.

Containment transition records MUST include old/new state, reason codes,
evidence hash, capability epoch, timestamp, Agent/runtime identity.

## 60.21 CAC exact permission model

The policy MUST explicitly represent:

``` text
plaintext_read
fhe_compute[programs]
decrypt_result
```

No implication is allowed between these permissions.

FHE AgentAction types MUST include:

``` text
FHE_ENCRYPT
FHE_COMPUTE
FHE_DECRYPT_REQUEST
FHE_PARTIAL_DECRYPT
FHE_COMBINE_DECRYPT
FHE_KEY_ROTATE
FHE_CONTEXT_CREATE
```

`FHE_REENCRYPT` remains an optional extension.

## 60.22 OpenFHE exact engineering requirements

Codex MUST: 1. inspect current stable OpenFHE; 2. inspect official
build/install guidance; 3. pin exact release/commit; 4. build/install;
5. record compiler/CMake/OpenFHE versions; 6. run real
encryption/evaluation/decryption smoke tests; 7. verify the exact
multiparty/threshold APIs used.

Prefer a narrow native C++ service around OpenFHE.

Scheme policy: - CKKS: approximate real analytics; - BFV/BGV: exact
integers; - FHEW/TFHE/scheme switching: only when justified.

The initial CAC demo SHOULD use CKKS.

## 60.23 FHE context registry exact fields

The registry MUST capture the equivalent of:

``` json
{
  "context_id": "ckks-employee-risk-v1",
  "scheme": "CKKS",
  "openfhe_version": "...",
  "security_level": "...",
  "security_profile": "secure-lab",
  "ring_dimension": 0,
  "multiplicative_depth": 0,
  "scaling_parameters": {},
  "batch_size": 0,
  "key_epoch": 3,
  "threshold": {
    "enabled": true,
    "participants": 3,
    "required_semantics": "documented actual protocol"
  },
  "context_hash": "sha256:...",
  "status": "ACTIVE"
}
```

Do not use undersized demo parameters while presenting them as secure.
Provide separate `demo`, `secure-lab`, and `enterprise-reference`
profiles.

## 60.24 Ciphertext/program/lineage details

Ciphertext envelope MUST contain: - ciphertext version; - dataset ID; -
ciphertext ID; - context ID; - key epoch; - schema ID; - plaintext
classification; - owner; - ciphertext hash; - created time; -
allowed-program-set hash.

Allowlisted program examples: `SUM_V1`, `AVERAGE_V1`,
`WEIGHTED_SCORE_V1`, `THRESHOLD_COUNT_V1`.

Program manifest MUST contain: - ID/version; - accepted schema; -
scheme; - expected multiplicative depth; - input/output shape; -
implementation hash; - policy classification; - leakage notes; -
benchmark.

Result lineage MUST link:

``` text
plaintext dataset
 -> ciphertext_id
 -> program
 -> encrypted result
 -> decrypt request
 -> released result
```

Store hashes/IDs rather than sensitive plaintext.

## 60.25 Threshold/multiparty decryption details

Reference logical authorities: - Data Owner Authority; -
Security/Privacy Authority; - CV-ZTTE Decryption Authority.

Run them as separate processes/containers in the reference PoC where
practical.

The implementation MUST document actual OpenFHE semantics. It MUST NOT
call the design `2-of-3` unless the selected protocol actually supports
that threshold.

No ordinary service should persist a reconstructed full secret key.

Key lifecycle MUST include context/key epoch, key generation, evaluation
keys, shares, rotation, revocation/deactivation, artifact integrity, and
storage permissions.

## 60.26 Decryption and release policy

Decryption is high-risk and separate from computation.

Before plaintext release: - classification; - recipient authorization; -
purpose/delegation; - Output Proxy/DLP; - result hash audit; -
precision/content minimization; - human approval where policy requires.

A compute-only Analytics Agent MUST NOT receive plaintext merely because
it produced the encrypted result.

## 60.27 Confidential Query Governance

Track per Agent/dataset/session/purpose: - number of decrypts; - query
frequency; - overlapping subsets; - precision; - result granularity.

Policy MUST be able to: - rate limit; - require minimum aggregation
group size `k`; - reduce/round precision; - deny repeated differencing
queries; - require approval; - deny individual-value release.

Do not call this differential privacy unless actual DP noise/accounting
exists.

## 60.28 FHE resource controls and caveats

Implement: - max ciphertext size; - max vector/batch; - allowed depth; -
per-Agent quotas; - queue bounds; - timeouts; - CPU/memory limits; -
cancellation; - rate limits.

Repeated expensive abuse feeds containment.

Document that FHE does not hide all metadata such as timing, size,
access pattern, program choice, or authorized output.

## 60.29 APIs

The final API surface MAY evolve to `/v3`, but MUST provide equivalents
of:

Core:

``` text
POST /v3/sessions
POST /v3/actions/evaluate-execute
POST /v3/actions/evaluate
POST /v3/approvals/{decision_id}
GET  /v3/decisions/{id}
GET  /health/live
GET  /health/ready
```

CAC:

``` text
POST /v3/cac/encrypt
POST /v3/cac/compute
POST /v3/cac/decrypt-requests
POST /v3/cac/decrypt-requests/{id}/approve
GET  /v3/cac/results/{id}
```

Containment/admin:

``` text
GET  /v3/agents/{id}/containment
POST /v3/agents/{id}/containment/reset
POST /v3/agents/{id}/quarantine
```

Admin-only APIs MUST include Agent registration, key
rotation/revocation, policy activation, delegation issuance/revocation,
and model/circuit/FHE registry activation.

Admin plane and Agent plane MUST be separated.

## 60.30 Error taxonomy

The implementation MUST provide structured errors covering at least:

``` text
SCHEMA_INVALID
DUPLICATE_JSON_KEY
PAYLOAD_TOO_LARGE
ACTION_HASH_MISMATCH
AGENT_UNKNOWN
AGENT_DISABLED
KEY_UNKNOWN
KEY_REVOKED
MLDSA_INVALID
CRYPTO_PROVIDER_UNAVAILABLE
REQUEST_EXPIRED
NONCE_REPLAY
SEQUENCE_INVALID
SESSION_UNKNOWN
SESSION_EXPIRED
DELEGATION_INVALID
POLICY_HASH_MISMATCH
OPA_DENY
OPA_UNAVAILABLE
GNARK_CREDENTIAL_INVALID
GNARK_PROOF_INVALID
GNARK_PUBLIC_INPUT_MISMATCH
GNARK_ARTIFACT_UNAPPROVED
BEHAVIOR_RISK_HIGH
BEHAVIOR_STATE_CONFLICT
JUDGE_UNSAFE
JUDGE_REVIEW
JUDGE_FAILED
EZKL_PROOF_INVALID
EZKL_PUBLIC_INPUT_MISMATCH
EZKL_ARTIFACT_UNAPPROVED
EZKL_QUANTIZATION_GUARD
EZKL_TIMEOUT
APPROVAL_REQUIRED
APPROVAL_EXPIRED
FINAL_ACTION_BINDING_FAILED
DECISION_TOKEN_INVALID
TOOL_BYPASS_DENIED
NETWORK_BYPASS_DENIED
EXECUTION_FAILED
SECURITY_DEPENDENCY_UNAVAILABLE
CONTAINMENT_SUSPICIOUS
CONTAINMENT_RESTRICTED
CONTAINMENT_QUARANTINED
CONTAINMENT_TERMINATED
CAPABILITY_DECAY_DENY
CAPABILITY_EPOCH_MISMATCH
RECOVERY_APPROVAL_REQUIRED
FHE_CONTEXT_UNKNOWN
FHE_CONTEXT_UNAPPROVED
FHE_CONTEXT_MISMATCH
FHE_KEY_EPOCH_MISMATCH
FHE_CIPHERTEXT_INVALID
FHE_CIPHERTEXT_TOO_LARGE
FHE_PROGRAM_UNKNOWN
FHE_PROGRAM_DENIED
FHE_COMPUTE_DENIED
FHE_COMPUTE_FAILED
FHE_COMPUTE_TIMEOUT
FHE_DECRYPT_DENIED
FHE_THRESHOLD_INSUFFICIENT
FHE_PARTIAL_DECRYPT_INVALID
FHE_RESULT_RELEASE_DENIED
FHE_PRIVACY_BUDGET_EXCEEDED
FHE_QUERY_PATTERN_RISK
```

## 60.31 Mandatory adversarial test inventory

The following concrete tests are mandatory in addition to any stronger
tests discovered during implementation.

### v2 identity/integrity/replay/policy

1.  forged Agent;
2.  wrong public key;
3.  one-byte signature mutation;
4.  revoked key;
5.  key-ID substitution;
6.  provider downgrade;
7.  action argument mutation;
8.  target mutation;
9.  action-type mutation;
10. session mutation;
11. policy-hash mutation;
12. exact replay;
13. nonce reuse;
14. sequence rollback;
15. expired request;
16. concurrent duplicate;
17. forbidden DB write;
18. path traversal;
19. external-domain escape;
20. classification violation;
21. self-issued policy.

### gnark

22. fake private clearance;
23. untrusted credential issuer;
24. proof A on Action B;
25. proof A on Policy B;
26. expired credential;
27. mutated proof;
28. substituted VK;
29. substituted circuit;
30. client-selected VK.

### behavior/EZKL/execution

31. individually benign actions forming exfiltration;
32. burst bulk read;
33. repeated denied privilege escalation;
34. behavior-state race/concurrency;
35. EZKL proof A on feature vector B;
36. mutated EZKL proof;
37. model substitution;
38. circuit/VK substitution;
39. SAFE metadata forgery;
40. quantization boundary;
41. unapproved model;
42. mutate action after verify;
43. swap payload behind hash;
44. expired Decision Token;
45. Action B with token A.

### v2 bypass/output/delegation/failure

46. direct MCP;
47. direct protected Tool HTTP;
48. direct external network;
49. unauthorized filesystem;
50. shell bypass;
51. credential leakage;
52. confidential-data output;
53. forbidden PII output;
54. child gains capability parent lacks;
55. child expiry exceeds parent;
56. delegation-chain revocation;
57. Redis down;
58. OPA down;
59. gnark verifier down;
60. EZKL verifier down;
61. Judge timeout;
62. audit-store failure according to mandatory audit policy.

### v2.1 mandatory mediation

63. LangGraph adapter bypass via direct HTTP;
64. LangChain adapter bypass via direct Tool;
65. direct MCP server;
66. direct socket egress;
67. direct sensitive file;
68. File Broker traversal/symlink escape;
69. github token used for evil.com;
70. POST token used for DELETE;
71. payload mutation;
72. token replay;
73. token used by another Agent;
74. token used by another runtime;
75. wrong enforcement audience;
76. expired token;
77. revoked Agent uses old token;
78. runtime kill switch;
79. policy epoch invalidates stale token;
80. semantic Action A then actual Action B;
81. high-risk action with missing context;
82. fake adapter metadata;
83. direct secret read;
84. secret in logs;
85. secret in Agent output;
86. unauthorized Agent peer;
87. authority laundering through message/sub-Agent;
88. coding Agent sudo;
89. coding Agent external curl;
90. coding Agent outside-workspace access;
91. direct protected DB;
92. Output Proxy credential leak;
93. Output Proxy PII violation;
94. OBSERVE would-deny behavior;
95. OBSERVE -\> ENFORCE transition;
96. QUARANTINE blocks effects;
97. receipt ActionHash mismatch;
98. forged receipt;
99. proposal/execution correlation;
100. boundary-only action raises risk;
101. unknown framework cannot bypass;
102. enforcement point unavailable -\> fail closed.

### v2.2 containment

103. repeated policy denials cause escalation;
104. destination switching increases evasion score;
105. protocol switching after denial;
106. direct bypass raises containment;
107. secret probing escalates;
108. proof/token misuse escalates;
109. sub-Agent laundering escalates;
110. capability set shrinks;
111. removed capability not recovered by syntax change;
112. stale token fails after capability epoch;
113. enforcement points honor new epoch;
114. quarantine blocks MCP/network/file/secret/output/message;
115. Agent cannot self-reset containment;
116. unauthorized de-escalation;
117. admin recovery audit;
118. terminated runtime cannot obtain token;
119. repeated attack while quarantined reaches termination per policy.

### v2.2 FHE/CAC

120. real OpenFHE encrypt/compute/decrypt happy path;
121. Analytics Agent sees no plaintext;
122. compute without read;
123. compute does not grant decrypt;
124. decrypt checked separately;
125. unauthorized program;
126. arbitrary-program upload;
127. ciphertext substitution;
128. context substitution;
129. key-epoch substitution;
130. modified ciphertext fails safely;
131. token A cannot compute dataset B;
132. token A cannot invoke program B;
133. quarantined Agent cannot compute;
134. quarantined Agent cannot decrypt;
135. one share cannot decrypt under configured model;
136. insufficient partial decryptions;
137. wrong participant/share;
138. key share absent from logs;
139. key share absent from LLM context;
140. Agent message contains reference, not plaintext;
141. unauthorized recipient cannot use ciphertext ref;
142. repeated aggregate queries trigger governance;
143. individual-value decrypt denied;
144. minimum aggregation enforced;
145. FHE DoS quota/rate limit;
146. oversized ciphertext;
147. compute timeout fail closed;
148. stale key epoch after rotation;
149. lineage source -\> compute -\> encrypted result -\> release;
150. released result passes Output Proxy.

All denied cases MUST assert both: - protected side-effect count = 0; -
unauthorized plaintext-release count = 0.

## 60.32 Performance benchmarks

At minimum benchmark:

-   ML-DSA sign/verify throughput;
-   OPA latency;
-   gnark prove/verify;
-   Judge inference;
-   EZKL prove/verify;
-   Redis;
-   L1/L2/L3/L4 total;
-   adapter overhead;
-   Decision Token issuance/validation;
-   MCP proxy;
-   egress proxy;
-   File Broker;
-   Output Proxy;
-   sandbox-local coding workload;
-   containment state update;
-   capability-epoch propagation;
-   quarantine propagation;
-   stale-token rejection;
-   OpenFHE context/key setup;
-   encryption;
-   ciphertext size;
-   SUM;
-   AVERAGE;
-   threshold partial decrypt;
-   combine/decrypt;
-   FHE broker overhead;
-   FHE memory usage.

Bound prover/FHE queues and implement backpressure.

## 60.33 Audit and SIEM exact behavior

Record: - identity/key; - session/delegation; - policy hash/version; -
action hash/type/target; - provenance; - risk/containment; -
OPA/gnark; - behavior snapshot hash; - Judge/EZKL; - Decision Token; -
executor/enforcement point; - Execution Receipt; - timing; - reason
codes; - FHE lineage where applicable.

Hash-chain entries as:

``` text
entry_hash_n =
SHA256(domain || previous_hash || JCS(event_without_hash))
```

Periodically sign audit checkpoints with a dedicated ML-DSA audit key
unless explicitly documented as deferred.

Provide JSON suitable for SIEM ingestion.

## 60.34 Additional enterprise extension points

Preserve extension points for: - mTLS service identities; - HSM/KMS/TEE
ML-DSA keys; - signed policy bundles; - SBOM; - image signing; -
dependency scanning; - remote attestation; - threshold approval; -
circuit/model release signing; - dual-control admin changes; - policy
simulation; - DLP; - EDR/SIEM connectors; - policy explainability; -
decision trace UI; - proof/artifact retention; - privacy minimization; -
secure clock; - HA replay store; - disaster recovery.

## 60.35 Required security-review coverage

`docs/FINAL_SECURITY_REVIEW.md` MUST explicitly answer all historical
review questions, including:

-   exact signed bytes and provider/FIPS status;
-   key storage/LLM accessibility/revocation;
-   replay atomicity;
-   policy/delegation issuer and self-widening prevention;
-   exact OPA semantics;
-   exact gnark statement, credential anchoring, public/private values,
    action binding;
-   exact behavior state and consistency;
-   exact Judge and EZKL statement/public/private values/action-history
    binding/quantization;
-   artifact approval and client trust-anchor selection;
-   execution binding and bypass resistance;
-   failure behavior;
-   what neither ZKP proves;
-   remaining TCB;
-   production gaps and first external audit;
-   containment evidence, ceilings, synchronization, recovery and
    sub-Agent/new-session bypass;
-   CAC protection/metadata leakage;
-   OpenFHE parameters and demo-vs-secure differences;
-   threshold share holders and actual threshold semantics;
-   whether any full key is reconstructed/persisted;
-   evaluation-key protection;
-   exact FHE compute capability/program restriction;
-   ciphertext/context/key-epoch binding;
-   FHE result substitution;
-   whether any computation decrypts first;
-   all plaintext locations;
-   plaintext-release authorization;
-   inference leakage/query governance;
-   key/context rotation;
-   OpenFHE and partial-decryption failure behavior.

Unanswered questions are release blockers.

------------------------------------------------------------------------

# 61. Enterprise deployment path

The implementation and documentation MUST present a realistic
progression:

``` text
Hackathon E2E
 -> Internal lab
 -> Shadow mode on real Agent traffic
 -> Non-critical pilot
 -> Security architecture review
 -> gnark/EZKL/FHE protocol and circuit review
 -> dependency/SBOM review
 -> penetration/adversarial testing
 -> cryptographic review
 -> HSM/KMS/TEE integration
 -> enterprise IAM integration
 -> SIEM/SOC integration
 -> limited production
```

The target is not immediate production certification. The target is an
architecture whose remaining work is integration, independent
validation, scaling, and operational hardening rather than redesigning
the security model.

# 62. Final product statement

CV-ZTTE v3 is:

> **A framework-agnostic, cryptographically verifiable Zero-Trust
> Agentic Security Control Plane and Enforcement Fabric that
> authenticates Agent actions with post-quantum signatures, enforces
> centrally governed least privilege, proves sensitive authorization
> predicates, monitors stateful behavior, dynamically contains evasive
> Agents, cryptographically verifies ML safety decisions, mediates real
> execution boundaries, and enables policy-governed confidential
> inter-Agent computation over encrypted data.**

Final slogans:

> **Semantic Interception for understanding. Mandatory Mediation for
> security.**

> **The action we understand, authorize, prove, and execute must be the
> same action.**

> **READ != COMPUTE != DECRYPT.**

> **A compromised Agent must lose authority faster than it can discover
> new bypass paths.**