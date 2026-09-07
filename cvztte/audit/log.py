"""Hash-chained audit log with ML-DSA-signed checkpoints (spec §32, §34).

Every security-relevant event is appended as a tamper-evident link: each entry
commits to the previous entry's hash, so any retroactive edit/removal breaks the
chain and is detectable by :meth:`HashChainedAuditLog.verify`. Periodically the
log head is signed with a **dedicated** ML-DSA checkpoint key (spec §34) — a
separate identity from any agent key, so audit integrity does not depend on
agent-key custody.

The execution lifecycle (spec §32) is:

    PROPOSED -> AUTHORIZED -> TOKEN_ISSUED -> ACTUAL_ACTION_OBSERVED
             -> EXECUTED -> RECEIPT

The Control Plane must not assume execution merely because ALLOW was issued
(spec §32): only an ``EXECUTED``/``RECEIPT`` event attests actual effect.

Callers are responsible for passing already-sanitized payloads — secrets, key
shares, witness data, and plaintext MUST NOT be placed in audit events (§50).
"""

from __future__ import annotations

import enum
import threading
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity.provider import PrivateKeyHandle, PublicKey, SignatureProvider

_GENESIS = commit(Domain.AUDIT_EVENT, {"genesis": True})


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class AuditStage(str, enum.Enum):
    PROPOSED = "PROPOSED"
    AUTHORIZED = "AUTHORIZED"
    TOKEN_ISSUED = "TOKEN_ISSUED"
    ACTUAL_ACTION_OBSERVED = "ACTUAL_ACTION_OBSERVED"
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    FAILED = "FAILED"
    RECEIPT = "RECEIPT"
    ADMIN = "ADMIN"  # admin-only actions: mode change, onboarding activation (§60.15)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int
    stage: AuditStage
    at: str
    prev_hash: str
    payload: dict[str, Any]

    def _body(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "stage": self.stage.value,
            "at": self.at,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
        }

    def event_hash(self) -> str:
        return commit(Domain.AUDIT_EVENT, self._body())


class AuditCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checkpoint_version: int = 1
    covers_through_seq: int
    head_hash: str
    at: str
    signer_fingerprint: str
    signature_b64: str


class HashChainedAuditLog:
    """Append-only, tamper-evident audit chain (reference in-memory store)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[AuditEvent] = []

    @property
    def head_hash(self) -> str:
        with self._lock:
            return self._events[-1].event_hash() if self._events else _GENESIS

    def __len__(self) -> int:
        return len(self._events)

    def events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)

    def append(self, stage: AuditStage, payload: dict[str, Any]) -> AuditEvent:
        with self._lock:
            prev = self._events[-1].event_hash() if self._events else _GENESIS
            event = AuditEvent(
                seq=len(self._events),
                stage=stage,
                at=_now(),
                prev_hash=prev,
                payload=payload,
            )
            self._events.append(event)
            return event

    def verify(self) -> bool:
        """Re-walk the chain; return True iff every link is intact."""
        with self._lock:
            prev = _GENESIS
            for i, event in enumerate(self._events):
                if event.seq != i or event.prev_hash != prev:
                    return False
                prev = event.event_hash()
            return True

    def checkpoint(
        self,
        provider: SignatureProvider,
        handle: PrivateKeyHandle,
        public_key: PublicKey,
    ) -> AuditCheckpoint:
        """Sign the current head with the dedicated ML-DSA checkpoint key (§34)."""
        if not self.verify():
            raise CVZTTEError(
                ErrorCode.AUDIT_CHAIN_BROKEN, "refusing to checkpoint a broken chain"
            )
        import base64

        with self._lock:
            covers = len(self._events) - 1
            head = self._events[-1].event_hash() if self._events else _GENESIS
        body = {"covers_through_seq": covers, "head_hash": head}
        message = commit(Domain.AUDIT_CHECKPOINT, body).encode("utf-8")
        signature = provider.sign(handle, message)
        return AuditCheckpoint(
            covers_through_seq=covers,
            head_hash=head,
            at=_now(),
            signer_fingerprint=public_key.fingerprint,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    @staticmethod
    def verify_checkpoint(
        provider: SignatureProvider,
        public_key: PublicKey,
        checkpoint: AuditCheckpoint,
    ) -> bool:
        import base64

        body = {
            "covers_through_seq": checkpoint.covers_through_seq,
            "head_hash": checkpoint.head_hash,
        }
        message = commit(Domain.AUDIT_CHECKPOINT, body).encode("utf-8")
        try:
            signature = base64.b64decode(checkpoint.signature_b64)
        except (ValueError, TypeError):
            return False
        return provider.verify(public_key, message, signature)
