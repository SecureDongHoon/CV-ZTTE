# Action Model

Spec references: §6 (Generalized AgentAction), §8 (canonicalization / ActionHash),
§16 (enforcement re-observes and recomputes), §21 (payloads as references).

Every consequential operation an agent may perform is normalized to **one
versioned canonical model**, `AgentAction`, defined in
`cvztte/action/model.py`. The security pipeline reasons about this single model,
not about framework-specific call shapes — so "the action we understand,
authorize, prove, and execute" is literally the same object end to end.

## `AgentAction` (cvztte/action/model.py)

| Field | Type | Notes |
|---|---|---|
| `action_version` | int (default 1) | model version for forward-compat |
| `action_type` | `ActionType` | the operation family (see below) |
| `target` | str | the resource the action acts on |
| `operation` | str \| None | verb (e.g. `read`, `write`, `db_query`) |
| `resource` | str \| None | optional finer resource id |
| `arguments` | dict | structured arguments |
| `data_classification` | `DataClassification` | `PUBLIC`/`INTERNAL`/`CONFIDENTIAL`/`SECRET` |
| `payload_ref` | `PayloadRef` \| None | reference + hash, **not** inline plaintext |

`model_config = ConfigDict(extra="forbid")` — unknown fields are rejected (§8),
so an attacker cannot smuggle un-modeled fields past the parser.

### `ActionType`

A closed enum covering tool/MCP/API/DB, file read/write/delete, process/shell/code
execution, network, user output, agent/external messaging, memory read/write,
secret access, cloud-control, and the FHE/CAC family (`FHE_ENCRYPT`,
`FHE_COMPUTE`, `FHE_DECRYPT_REQUEST`, `FHE_PARTIAL_DECRYPT`,
`FHE_COMBINE_DECRYPT`, `FHE_KEY_ROTATE`, `FHE_CONTEXT_CREATE`, and the optional
`FHE_REENCRYPT`). A closed enum means every action is classifiable to a risk tier
and a mediation point; there is no "other" escape hatch.

### `DataClassification`

`PUBLIC < INTERNAL < CONFIDENTIAL < SECRET`. Drives risk tiering, CAC release
gates (human approval for `CONFIDENTIAL`/`SECRET`), and DLP.

## Payloads by reference, not value (§6, §21)

Sensitive content is carried as a `PayloadRef` — an immutable `ref` plus a
`"sha256:..."` `hash` (and optional `size`) — rather than duplicated inline.
Result lineage and audit therefore store hashes/IDs, never plaintext (§60.24).

## The ActionHash (§8, §16)

`AgentAction.action_hash()` is a **domain-separated commitment** (`Domain.ACTION`)
over the JCS-canonical bytes of `canonical_dict()` (RFC 8785 canonicalization;
`cvztte/canonical/`). Properties that matter for security:

- **Deterministic & canonical** — the same logical action always yields the same
  hash regardless of key order or serialization quirks; duplicate JSON keys and
  extra fields are rejected upstream (§8).
- **Independently recomputable** — the enforcement point recomputes the
  ActionHash from what it actually observes at execution time (§16); the agent
  can never supply a trusted ActionHash. This is the anchor for TOCTOU
  resistance: the signed/authorized/proven/mediated action must hash-match the
  action about to execute, or it is denied.
- **Domain-separated** — actions, contexts, ciphertexts, tokens, etc. each hash
  under a distinct `Domain`, so a commitment for one kind of object can never be
  replayed as another.

## How the pipeline uses it

1. A framework adapter (`cvztte/adapters/`) normalizes a proposed call into an
   `AgentAction` — adapters only **propose**; they never authorize.
2. The signed request binds the ActionHash under the agent's ML-DSA signature.
3. OPA, gnark, the Judge/EZKL, and the Decision Token all bind to this same
   canonical action / ActionHash.
4. The enforcement broker **re-observes** the real operation, recomputes the
   ActionHash, and requires an exact match before executing (§16).

See `docs/ARCHITECTURE.md` for the full flow and `docs/FRAMEWORK_ADAPTERS.md`
for normalization and the BOUNDARY_ONLY fallback.
