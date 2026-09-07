"""Atomic replay / freshness (spec §11). Redis-down ⇒ no protected ALLOW."""

from cvztte.replay.redis_freshness import (
    DEFAULT_NONCE_TTL_SECONDS,
    MIN_NONCE_HEX_LEN,
    ReplayGuard,
)

__all__ = ["ReplayGuard", "MIN_NONCE_HEX_LEN", "DEFAULT_NONCE_TTL_SECONDS"]
