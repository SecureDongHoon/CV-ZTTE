"""Decision Token single-use / replay tracking (spec §31: "replay MUST be tracked").

Each token carries a 128-bit nonce and a ``max_uses`` (default 1). The validator
atomically records a use and refuses once the nonce has been consumed
``max_uses`` times. The reference tracker is in-memory; a production deployment
backs this with the same atomic Redis store used for request freshness
(:mod:`cvztte.replay.redis_freshness`) so concurrent replays cannot race.

Fail-closed: if the tracker cannot record a use, the token MUST NOT authorize.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from cvztte.errors import CVZTTEError, ErrorCode


@runtime_checkable
class TokenUseTracker(Protocol):
    def consume(self, nonce: str, max_uses: int) -> None:
        """Record one use of ``nonce``; raise DECISION_TOKEN_REPLAY if exhausted."""
        ...


class InMemoryTokenUseTracker:
    """Thread-safe in-memory single-use tracker (reference implementation)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def consume(self, nonce: str, max_uses: int) -> None:
        with self._lock:
            used = self._counts.get(nonce, 0)
            if used >= max_uses:
                raise CVZTTEError(
                    ErrorCode.DECISION_TOKEN_REPLAY,
                    "decision token already consumed",
                )
            self._counts[nonce] = used + 1
