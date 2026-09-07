# Confidential Data Lineage

*Spec references: §60.24. Phase 16.*

## Purpose

Confidential Analytics & Compute (CAC) moves data through several representations —
a source dataset is encrypted into a ciphertext, an allowlisted program computes an
encrypted result, someone requests decryption, and a plaintext result is released.
Data Lineage records that chain as a tamper-evident provenance DAG so that any
released result can be traced back to exactly the dataset, ciphertext, program, and
approval that produced it.

> **Stores hashes and IDs, never plaintext (§60.24).** Nodes carry business
> identifiers, optional `sha256:` pins over the referenced artifacts, and
> non-sensitive labels (classification, program version, key epoch). No plaintext
> value, key material, or secret share is ever stored in the graph.

The recorder **does not authorize anything**. It is the audit/provenance substrate
that the control plane (Phase 17) and Confidential Query Governance
([CONFIDENTIAL_QUERY_GOVERNANCE](CONFIDENTIAL_QUERY_GOVERNANCE.md)) consult.

## Provenance chain

```
DATASET --ENCRYPTS--> CIPHERTEXT --COMPUTED_BY--> PROGRAM --PRODUCES--> RESULT
        --DECRYPT_OF--> DECRYPT_REQUEST --RELEASES--> RELEASED_RESULT
```

Node kinds (`LineageNodeType`): `DATASET`, `CIPHERTEXT`, `PROGRAM`, `RESULT`,
`DECRYPT_REQUEST`, `RELEASED_RESULT`. Edge kinds (`LineageRelation`): `ENCRYPTS`,
`COMPUTED_BY`, `PRODUCES`, `DECRYPT_OF`, `RELEASES`.

## Node identity

A node's id is a domain-separated commitment (`Domain.LINEAGE_NODE`) over its
`(node_type, ref)` — **what it refers to**, not its metadata. This is deliberate: a
ciphertext recorded once with its hash and again as a compute input must map to the
**same** node, or the DAG would fragment and `trace()` would lose the dataset. The
pinned `ref_hash` and `attributes` are metadata carried on the node and are folded
into the graph hash (below) for tamper-evidence, not into node identity.

`_add_node` is idempotent by id and **merge-keeps the richer record**: a bare
reference never overwrites a node that already carries a hash/attributes,
regardless of recording order.

## API

`LineageGraph` (thread-safe) records events as they occur and returns the id of the
node it created:

- `record_ciphertext(dataset_id, ciphertext_id, ciphertext_hash, classification,
  context_id, key_epoch)` → dataset → ciphertext.
- `record_result(parent_ciphertext_ids, program_id, program_version, result_id,
  result_hash, lineage_id)` → parent ciphertext(s) → program → result.
- `record_decrypt_request(result_id, request_id, requester, purpose)` → result →
  request.
- `record_release(request_id, release_id, recipient, released_hash?, approval_id?)`
  → request → released result.

Queries:

- `get_node(node_id)` → the stored `LineageNode` (or `None`).
- `trace(node_id)` → the ancestor chain of a node, **roots first, node last**, by
  DFS over reversed edges. Tracing a released result reconstructs the full
  provenance chain back to the source dataset.
- `graph_hash()` → a domain-separated commitment (`Domain.LINEAGE_GRAPH`) over the
  id-sorted nodes (with their hashes/attributes) and the insertion-ordered edges.
  Any tampering with a recorded artifact hash, attribute, or edge changes this
  value.

## Guarantees and non-goals

- **Traceability** — every released plaintext result links to its dataset,
  ciphertext, program, decrypt request, and approval.
- **Tamper-evidence** — `graph_hash()` commits over all recorded hashes/IDs and
  edges.
- **No plaintext at rest** — only IDs, `sha256:` pins, and non-sensitive labels.
- **Not authorization** — lineage records what happened; CAC gates (§42) decide
  what is allowed.
