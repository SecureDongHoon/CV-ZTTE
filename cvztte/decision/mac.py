"""Keyed MAC over Decision Token canonical bytes (spec §31).

The signing/MAC key is **gateway-only** (spec §31): it is held solely by the
Decision Token Authority and the enforcement-side validator, and never enters an
agent context, an LLM prompt, a log, or an audit record. This module provides
only the MAC primitive; key custody is the caller's responsibility.

The MAC is HMAC-SHA256 over ``UTF8(domain) || 0x00 || canonical_token_bytes``,
mirroring the domain-separation discipline of :mod:`cvztte.canonical.hashing`
so a MAC computed for a Decision Token can never be reinterpreted for another
object class.
"""

from __future__ import annotations

import hmac
import hashlib

from cvztte.canonical.domains import Domain
from cvztte.decision.model import DecisionToken

_PREFIX = "hmac-sha256:"
_SEP = b"\x00"


def compute_mac(key: bytes, token: DecisionToken) -> str:
    if not key:
        raise ValueError("empty MAC key")
    msg = Domain.DECISION_TOKEN.value.encode("utf-8") + _SEP + token.canonical_bytes()
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return _PREFIX + digest


def verify_mac(key: bytes, token: DecisionToken, mac: str) -> bool:
    """Constant-time MAC verification. Returns False on any mismatch."""
    try:
        expected = compute_mac(key, token)
    except ValueError:
        return False
    return hmac.compare_digest(expected, mac)
