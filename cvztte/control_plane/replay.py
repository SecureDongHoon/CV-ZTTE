"""Replay/freshness seam for the Control Plane (spec §11).

The production guard is :class:`cvztte.replay.redis_freshness.ReplayGuard` (atomic
Lua over Redis). The Control Plane depends only on the narrow
:class:`ReplayGuardProtocol` so it can be wired with the real Redis guard in
deployment and a deterministic in-memory guard in tests. Both fail closed: a
replayed nonce raises ``NONCE_REPLAY`` and a non-monotonic sequence raises
``SEQUENCE_INVALID`` — a duplicate can never slip through as an implicit ALLOW.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from cvztte.errors import CVZTTEError, ErrorCode

#: Spec §11 minimum nonce entropy (128 bits => 32 hex chars).
_MIN_NONCE_HEX = 32


@runtime_checkable
class ReplayGuardProtocol(Protocol):
    def check_and_commit(self, *, session_id: str, nonce: str, sequence: int) -> None: ...


class InMemoryReplayGuard:
    """Deterministic single-process replay/sequence guard (reference/tests).

    Not for multi-process deployment — use the Redis-backed guard there. Enforces
    the same invariants: nonces are single-use and per-session sequences are
    strictly increasing.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: set[str] = set()
        self._max_sequence: dict[str, int] = {}

    def check_and_commit(self, *, session_id: str, nonce: str, sequence: int) -> None:
        if len(nonce) < _MIN_NONCE_HEX:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "nonce below 128-bit minimum")
        with self._lock:
            if nonce in self._nonces:
                raise CVZTTEError(ErrorCode.NONCE_REPLAY, "nonce already used")
            last = self._max_sequence.get(session_id)
            if last is not None and sequence <= last:
                raise CVZTTEError(ErrorCode.SEQUENCE_INVALID, "sequence not monotonic")
            # Commit only after both checks pass (atomic under the lock).
            self._nonces.add(nonce)
            self._max_sequence[session_id] = sequence
