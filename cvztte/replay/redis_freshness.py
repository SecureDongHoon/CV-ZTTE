"""Atomic replay / freshness guard backed by Redis (spec §11).

Nonce insertion and monotonic-sequence validation execute as a **single atomic
Lua EVAL**, so concurrent duplicate requests cannot race past the check
(exactly one wins). Fail-closed rule: if Redis is unavailable the guard raises
``SECURITY_DEPENDENCY_UNAVAILABLE`` — there is **no protected ALLOW without a
working freshness store** (spec §11).

The nonce must carry >=128 bits of entropy (spec §11); we reject nonces shorter
than 32 hex chars before touching Redis.
"""

from __future__ import annotations

from pathlib import Path

from cvztte.errors import CVZTTEError, ErrorCode

_LUA = (Path(__file__).parent / "replay_atomic.lua").read_text()

#: 32 hex chars = 128 bits.
MIN_NONCE_HEX_LEN = 32
DEFAULT_NONCE_TTL_SECONDS = 300
_KEY_PREFIX = "cvztte:sess"


class ReplayGuard:
    """One atomic nonce+sequence check per protected request."""

    def __init__(self, redis_client, *, nonce_ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS) -> None:
        self._redis = redis_client
        self._ttl = nonce_ttl_seconds
        try:
            self._script = redis_client.register_script(_LUA)
        except Exception as exc:  # pragma: no cover - connection setup
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "replay store unavailable",
                detail=str(exc),
            ) from exc

    def _keys(self, session_id: str) -> tuple[str, str]:
        return (
            f"{_KEY_PREFIX}:{session_id}:nonces",
            f"{_KEY_PREFIX}:{session_id}:seq",
        )

    def check_and_commit(self, *, session_id: str, nonce: str, sequence: int) -> None:
        """Atomically validate + commit freshness; raise on any failure.

        Raises:
            NONCE_REPLAY, SEQUENCE_INVALID on stale/duplicate requests.
            SECURITY_DEPENDENCY_UNAVAILABLE if Redis cannot be reached
            (fail closed — the caller MUST NOT allow the action).
        """
        if len(nonce) < MIN_NONCE_HEX_LEN:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "nonce below 128-bit minimum")
        nonce_key, seq_key = self._keys(session_id)
        try:
            result = self._script(keys=[nonce_key, seq_key], args=[nonce, sequence, self._ttl])
        except CVZTTEError:
            raise
        except Exception as exc:
            # Any Redis connectivity/protocol error => no protected ALLOW.
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "replay store unavailable",
                detail=str(exc),
            ) from exc

        decoded = result.decode() if isinstance(result, (bytes, bytearray)) else str(result)
        if decoded == "OK":
            return
        if decoded == "NONCE_REPLAY":
            raise CVZTTEError(ErrorCode.NONCE_REPLAY, "nonce already used")
        if decoded == "SEQUENCE_INVALID":
            raise CVZTTEError(ErrorCode.SEQUENCE_INVALID, "sequence not monotonic")
        # Unknown result => fail closed.
        raise CVZTTEError(
            ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
            "unexpected replay-guard result",
            detail=decoded,
        )
