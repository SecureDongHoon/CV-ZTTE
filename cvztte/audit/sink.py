"""Bridge Enforcement-Fabric receipts into the durable audit chain (§32, §34).

:class:`AuditReceiptSink` implements the Phase 7
:class:`enforcement.common.ReceiptSink` protocol, so any broker can write its
Execution Receipts straight into the hash-chained, checkpoint-signed audit log.
The receipt is already sanitized by the broker (no secret/credential values,
§21/§50); this sink adds the receipt hash and records it as a ``RECEIPT`` event.
"""

from __future__ import annotations

from cvztte.audit.log import AuditStage, HashChainedAuditLog
from enforcement.common import ExecutionReceipt


class AuditReceiptSink:
    """A ReceiptSink that appends each receipt to a hash-chained audit log."""

    def __init__(self, log: HashChainedAuditLog) -> None:
        self._log = log

    def emit(self, receipt: ExecutionReceipt) -> None:
        payload = receipt.model_dump(mode="json", exclude_none=True)
        payload["receipt_hash"] = receipt.receipt_hash()
        self._log.append(AuditStage.RECEIPT, payload)
