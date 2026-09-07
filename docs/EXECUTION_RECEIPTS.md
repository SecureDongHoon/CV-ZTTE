# Execution Receipts & Audit Chain (Phase 8)

An enforcement point never merely records "ALLOW was issued." It emits an
**Execution Receipt** attesting what actually happened, and that receipt is
written into a tamper-evident, hash-chained audit log with periodically
ML-DSA-signed checkpoints (spec §32, §34). The Control Plane must not assume
execution occurred until an `EXECUTED`/`RECEIPT` event exists (§32).

## Execution Receipt

Produced by every broker's common flow (`enforcement/common.py`,
`ExecutionReceipt`): `receipt_version`, `decision_id`, `action_hash`,
`action_type`, `target`, `operation`, `audience`, `source`, `outcome`
(`EXECUTED` / `DENIED` / `FAILED`), `error_code`, `result_hash`, `observed_at`.
`receipt_hash()` is a domain-separated commit (`Domain.EXECUTION_RECEIPT`).
Receipts carry only hashes/refs — never secret values, credentials, witness
data, or plaintext (§21, §50).

## Audit lifecycle (§32)

    PROPOSED -> AUTHORIZED -> TOKEN_ISSUED -> ACTUAL_ACTION_OBSERVED
             -> EXECUTED -> RECEIPT

`AuditStage` enumerates these (plus `DENIED` / `FAILED` for non-happy paths).

## Hash-chained log (`cvztte/audit/`)

`HashChainedAuditLog.append(stage, payload)` links each entry to the previous
entry's hash (genesis-anchored). Any retroactive edit or removal breaks the
chain, detected by `verify()` (re-walks and re-hashes every link). This is the
reference in-memory store; a durable backend keeps the same discipline.

`AuditReceiptSink` implements the Phase 7 `ReceiptSink` protocol, so any broker
writes its receipts straight into the chain as `RECEIPT` events (with the
receipt hash attached).

## ML-DSA checkpoints (§34)

`checkpoint(provider, handle, public_key)` signs the current chain head with a
**dedicated** ML-DSA key — a separate identity from any agent key, so audit
integrity does not hinge on agent-key custody. The signed body is a
domain-separated commit (`Domain.AUDIT_CHECKPOINT`) over
`{covers_through_seq, head_hash}`. `verify_checkpoint(...)` recomputes and
verifies; a checkpoint whose `head_hash` doesn't match its signed body fails.
`checkpoint()` refuses to sign a chain that doesn't currently `verify()`
(`AUDIT_CHAIN_BROKEN`).

## Tests

`tests/integration/test_audit.py`: chain linkage + `verify()`; tamper detection;
full lifecycle recording; real ML-DSA checkpoint sign/verify roundtrip and
rejection of a mismatched head. The decision-token happy path
(`test_decision_token.py`) additionally asserts a broker's receipt lands in a
verifiable chain.
