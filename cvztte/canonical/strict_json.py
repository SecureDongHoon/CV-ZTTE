"""Strict JSON parsing for security objects (spec §8).

Rejects, before any security decision is made:
  * duplicate object keys
  * NaN / Infinity / -Infinity
  * invalid UTF-8
  * oversized payloads
  * excessively nested structures
  * bare control characters that indicate malformed input

Unknown/extra *fields* are a schema concern enforced by the typed models
(pydantic ``extra="forbid"``), not by this structural parser. This parser only
guarantees the byte stream is a well-formed, unambiguous JSON value.
"""

from __future__ import annotations

import json
from typing import Any

from cvztte.errors import ErrorCode, StrictParseError

# Conservative defaults; tune per deployment profile (demo/secure-lab).
MAX_PAYLOAD_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_NESTING_DEPTH = 64


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise StrictParseError(
                ErrorCode.DUPLICATE_JSON_KEY,
                f"duplicate JSON key: {key!r}",
            )
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    # json passes "NaN", "Infinity", "-Infinity" here.
    raise StrictParseError(
        ErrorCode.SCHEMA_INVALID,
        f"non-finite JSON number not allowed: {name}",
    )


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise StrictParseError(
            ErrorCode.SCHEMA_INVALID,
            f"nesting depth exceeds {MAX_NESTING_DEPTH}",
        )
    if isinstance(value, dict):
        for v in value.values():
            _check_depth(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            _check_depth(v, depth + 1)


def strict_loads(data: bytes | str) -> Any:
    """Parse ``data`` into a Python value under strict rules or raise
    :class:`StrictParseError`."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = data

    if len(raw) > MAX_PAYLOAD_BYTES:
        raise StrictParseError(
            ErrorCode.PAYLOAD_TOO_LARGE,
            f"payload {len(raw)} bytes exceeds {MAX_PAYLOAD_BYTES}",
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictParseError(ErrorCode.SCHEMA_INVALID, "invalid UTF-8") from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except StrictParseError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictParseError(ErrorCode.SCHEMA_INVALID, f"malformed JSON: {exc.msg}") from exc

    _check_depth(value)
    return value
