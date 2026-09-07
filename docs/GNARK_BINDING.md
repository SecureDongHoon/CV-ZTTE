# CV-ZTTE gnark ZK Authorization — Binding & Hash Bridge (Phase 5 design)

Required by spec §14 / §60.5. This document is the authoritative definition of
**what the authorization circuit actually constrains**, the deterministic bridge
between the application's SHA-256 commitment world and the circuit's BN254 field,
and the versioned registry. Nothing here claims SHA-256 is constrained in-circuit
(spec §14: "Never claim SHA-256 is constrained unless it is").

## Role (spec §14, §43)

gnark **does not replace OPA**. Its job:

> Prove possession of a trusted issuer-authorized credential binding the exact
> action while minimizing disclosure.

It answers "can the holder prove a trusted delegated-authorization predicate for
*this exact* action?" — not "who signed" (ML-DSA), not "enterprise policy" (OPA),
not FHE evaluation.

## What is and is NOT constrained

**Constrained in-circuit (BN254, Poseidon2):**

- Recomputation of the **credential commitment** from private attributes and its
  equality to the issuer-anchored public commitment (credential is anchored to a
  trusted issuer; the agent cannot invent witness attributes — only the issuer,
  on the trusted admin path, knows a `salt` producing a registered commitment).
- `capability == required_capability` (required capability exists).
- `clearance >= required_clearance` (clearance satisfies requirement; range-checked).
- `expiry_epoch >= current_epoch` (not expired).
- The credential binds `resource_scope_commit` and `policy_commit` (approved
  policy/delegation commitment matches).
- A **session binding** equality tying the credential commitment to the exact
  public action commitment and current epoch:
  `session_binding == Poseidon2(credential_commitment, action_hi, action_lo, current_epoch, circuit_version)`.

**NOT constrained (bound instead by other means):**

- SHA-256 preimages are **not** recomputed in-circuit. The application's
  SHA-256 commitments are bridged into field elements (below) and bound as
  Groth16 **public inputs**; Groth16 verification is over the exact public-input
  vector, so a proof for Action A cannot verify against Action B's public inputs
  (invariant §4.11). This is a public-input binding, not an in-circuit SHA-256.

## Deterministic SHA-256 → field bridge

Application commitments are `"sha256:" || hex(32 bytes)` (domain-separated,
`cvztte.canonical.hashing.commit`). Each 32-byte digest maps to an **ordered
pair** of BN254 field elements by splitting into two big-endian 128-bit limbs:

```
digest = D[0..32)
hi = int_be(D[0..16))     # < 2^128 < r  (injective, no modular wrap)
lo = int_be(D[16..32))    # < 2^128 < r
field_pair(digest) = (hi, lo)
```

Both limbs are `< 2^128`, well below the BN254 scalar field modulus
`r ≈ 2^254`, so the map is injective and identical on both sides. The Python
side (`cvztte.zkauthz.bridge.sha256_to_field_pair`) and the Go side
(`bridge.Sha256HexToLimbs`) MUST agree bit-for-bit; `docs`-referenced
**substitution tests** assert this on shared vectors (see
`tests/integration/test_zkauthz.py` and `services/zk-authz` Go tests).

Small enumerable attributes (capability id, clearance level, epoch) are encoded
directly as field integers via a fixed, versioned dictionary
(`credential schema version`), not via SHA-256.

## Public input vector (fixed order)

```
0  agent_fp_hi
1  agent_fp_lo
2  credential_commitment
3  required_capability
4  required_clearance
5  current_epoch
6  action_commit_hi
7  action_commit_lo
8  policy_commit_hi
9  policy_commit_lo
10 scope_commit_hi
11 scope_commit_lo
12 circuit_version
13 session_binding
```

The **client cannot select the verification key** (spec §14): the verifier uses
the VK pinned by the registry for the active `circuit_version`; a client-supplied
VK is ignored.

## Backend selection: Groth16 vs PLONK (spec §14, §60.5)

Benchmarked on the actual circuit (`cmd/zk-authz bench`, results recorded in
this file's Benchmark section once measured). Selection rationale:

- **Groth16 (BN254)** — smallest constant proof (3 group elements) and cheapest,
  constant verification (well-suited to a fixed, versioned authorization
  circuit re-verified on every high-risk action). Requires a circuit-specific
  trusted setup, which is acceptable because the circuit is fixed and its setup
  artifacts are versioned/pinned in the registry.
- **PLONK (BN254)** — universal/updatable SRS, no per-circuit ceremony, but
  larger proofs and costlier verification.

**Selected: Groth16/BN254** for the fixed authorization circuit. The setup
artifacts (PK/VK) are pinned; see registry versioning below. (PLONK remains the
documented alternative for circuits expected to change frequently.)

## Registry versioning (spec §60.5)

The gnark registry versions, and the control plane pins:

- circuit source hash;
- compiled constraint-system hash;
- proving system (`groth16`);
- curve (`BN254`);
- proving key hash;
- verification key hash;
- credential schema version.

A `manifest.json` produced by `zk-authz setup` records these; the Python
`cvztte.zkauthz.registry` loads it and the client verifies only against the
registry's pinned VK for the requested `circuit_version`.

## Service surface (spec §60.5)

`services/zk-authz` exposes narrow internal functions via a CLI (JSON over
stdin/stdout, invoked as a subprocess by the Python control plane):

- `setup`  — compile + Groth16 setup; write PK/VK + `manifest.json` (admin).
- `issue`  — compute the credential commitment for attributes (trusted admin
  path only; issuance is restricted).
- `prove`  — produce a proof from private attributes + public inputs.
- `verify` — verify a proof against public inputs using the **registry-pinned** VK.
- `bench`  — Groth16 timing on the real circuit.

## Benchmark (measured)

Measured on the real `AuthzCircuit` via `zk-authz bench` (WSL2 Ubuntu 22.04,
20 iterations), Groth16 / BN254:

| Metric               | Value          |
|----------------------|----------------|
| Constraints (R1CS)   | 5839           |
| Public inputs        | 14             |
| Private witness      | 4              |
| Avg prove time       | ~53 ms         |
| Avg verify time      | ~1.1 ms        |
| Proof size           | 164 bytes (constant) |

Groth16 gives a constant 164-byte proof and ~1 ms verification, which is the
decisive property for a fixed authorization circuit re-verified on every
high-risk action. PLONK on the same circuit would remove the per-circuit trusted
setup but produce a larger proof and costlier verification; since the circuit is
fixed and its setup artifacts are versioned/pinned in the registry, the trusted
setup cost is paid once and Groth16 is selected. (PLONK is retained as the
documented alternative for circuits expected to change frequently.)

Note: the trusted-setup toxic waste is discarded by `groth16.Setup`; the PK/VK
hashes therefore differ on each `setup` run, and the registry pins whichever
artifacts a given setup produced.
