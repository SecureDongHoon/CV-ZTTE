# Threat Model

Spec references: §1 (mission), §2 (non-claims), §3 (trust model), §4 (invariants),
§59 (acceptance challenge).

## Adversary

The central assumption: **a legitimate agent, holding its own valid ML-DSA
identity, is fully prompt-injected and actively malicious** (§59). CV-ZTTE
assumes the agent may be prompt-injected, malicious, hallucinating, compromised
through retrieved/RAG content, persistently bypass-seeking, and using legitimate
credentials while exceeding delegated authority (§1). CV-ZTTE therefore controls
**consequential actions**, never the agent's internal reasoning.

### Untrusted (§3.1)

User input; retrieved/RAG content; the LLM; the planner; agent-generated
arguments; agent memory; the agent framework/SDK; sub-agents and peer agents; the
network client; a captured request/token/proof; any ciphertext reference supplied
by the agent; and adapter-provided semantic metadata unless independently bound
and validated.

### Trusted security plane / TCB (§3.2)

The CV-ZTTE control plane; the Policy Authority; the identity/key registry; the
approved policy-bundle registry; the gnark verifier registry; the Judge/EZKL
artifact registries; the OpenFHE context/program/key registry; the Decision Token
authority; the Enforcement Fabric; the threshold-decryption authorities (per the
configured trust model); container/network isolation primitives; and trusted
time/state services. See `docs/FINAL_SECURITY_REVIEW.md` for the remaining-TCB
analysis and the production reductions (HSM/KMS/TEE, mTLS, separate hosts, signed
releases, independent audit).

## Attacks in scope (the acceptance challenge, §59)

A fully-compromised-but-authenticated agent attempts: SDK bypass; direct
MCP/network/DB/file/process access; secret extraction; output exfiltration;
capability forgery; proof/token reuse; TOCTOU; destination/tool/protocol
switching; sub-agent authority laundering; stale-token use after containment; FHE
program abuse; ciphertext/context substitution; threshold-share theft; repeated
aggregate inference; and dependency-failure exploitation.

**Acceptance requires: no unauthorized consequential side effect occurs, and no
unauthorized plaintext disclosure occurs (§59).** The adversarial suite
(`tests/adversarial/`, `docs/ADVERSARIAL_SUITE.md`) drives all of these through
the real integrated stack; every DENY asserts protected side-effect count = 0 and
unauthorized-plaintext-release count = 0.

## Explicitly out of scope / not claimed (§2)

CV-ZTTE does **not** claim to: make LLM reasoning trustworthy; prevent all prompt
injection; formally verify business-policy correctness; prove the Safety Judge is
semantically perfect; make the whole system quantum-safe merely because ML-DSA is
used; keep a host safe after kernel/hypervisor compromise; make FHE hide timing,
access patterns, ciphertext size, program identity, or all metadata; make ZKP
integration correct merely because gnark/EZKL themselves verify; or be
production-certified without independent review.

What it **does** claim: ML-DSA authenticates signed requests under registered
keys; OPA enforces deterministic enterprise policy; gnark proves explicitly
encoded authorization predicates anchored to trusted credentials; the
Behavior/Containment subsystem detects and responds to stateful evasion; EZKL
proves the approved Judge computation for proof-bound inputs; OpenFHE permits
approved computation over ciphertext without exposing source plaintext to
compute-only agents; and the Enforcement Fabric prevents cooperative-SDK bypass
within the declared runtime threat model.

## The 21 enduring invariants (§4)

Primary: **the same canonical action must be identified, signed, authorized,
policy-compliant, behavior-checked, proof-bound, and executed.** Then:

1. No protected effect without mandatory mediation.
2. Framework adapters are semantic sensors, not trust boundaries.
3. Missing semantic context never lowers protection.
4. Agent private ML-DSA keys never enter LLM context/log/audit/proof.
5. Agent cannot self-authorize or widen delegation.
6. Hard-policy DENY cannot be overridden by ML/ZKP.
7. Client cannot choose a weaker model/circuit/VK/policy/provider.
8. Replay/stale/sequence-regressed requests fail.
9. Decision Token is short-lived, scoped, and execution-bound.
10. The enforcement point independently observes/recomputes the actual action.
11. Action-A authorization/proof/token cannot execute Action B.
12. Execution requires an authenticated Execution Receipt.
13. Risk escalation can only reduce authority or add controls.
14. Capability decay is monotonic within an active escalation episode.
15. Recovery/de-escalation is explicit and audited.
16. `READ != COMPUTE != DECRYPT`.
17. FHE compute authority never implies plaintext or decryption authority.
18. Threshold mode must not leave a single unauthorized principal able to decrypt.
19. FHE programs/contexts/parameters are registry-approved, never agent-selected.
20. No security-subsystem error produces an implicit ALLOW (fail-closed, §4.20).
21. Audit records must not contain secrets/plaintext unnecessarily.

Each invariant maps to enforced code and to adversarial tests; the mapping and
per-invariant evidence live in `docs/FINAL_SECURITY_REVIEW.md`.
