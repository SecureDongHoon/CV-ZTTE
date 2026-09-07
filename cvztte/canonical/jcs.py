"""RFC 8785 JSON Canonicalization Scheme (JCS) for security objects (spec §8).

Canonical bytes are the single source of truth for every hash and every ML-DSA
signature. Two logically-equal objects MUST produce identical bytes regardless
of key order or insignificant formatting, and non-finite numbers are rejected.

We delegate to the ``rfc8785`` reference library for correct ECMAScript number
serialization, then re-validate structural constraints via the strict parser so
the same rejection rules apply on both the producing and verifying sides.
"""

from __future__ import annotations

from typing import Any

import rfc8785

from cvztte.errors import ErrorCode, StrictParseError


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 canonical UTF-8 bytes for ``value``.

    Raises :class:`StrictParseError` for values JCS cannot represent
    deterministically (e.g. NaN/Infinity floats).
    """
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError) as exc:
        raise StrictParseError(
            ErrorCode.SCHEMA_INVALID,
            f"value is not JCS-canonicalizable: {exc}",
        ) from exc
