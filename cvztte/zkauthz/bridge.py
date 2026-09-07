"""Deterministic SHA-256 -> BN254 field bridge (docs/GNARK_BINDING.md).

MUST agree bit-for-bit with the Go ``bridge`` package. Substitution tests
(tests/integration/test_zkauthz.py) assert this on shared vectors by comparing
against the ``zk-authz encode`` subcommand.
"""

from __future__ import annotations

import hashlib

from cvztte.errors import CVZTTEError, ErrorCode

# Domain-separation tag for capability field encoding (must equal Go CapDomain).
CAP_DOMAIN = "cvztte.cap.v3"


def digest_to_limbs(digest: bytes) -> tuple[int, int]:
    """Split a 32-byte digest into two big-endian 128-bit limbs (hi, lo)."""
    if len(digest) != 32:
        raise CVZTTEError(
            ErrorCode.SCHEMA_INVALID,
            "digest must be 32 bytes",
            detail={"length": len(digest)},
        )
    hi = int.from_bytes(digest[:16], "big")
    lo = int.from_bytes(digest[16:], "big")
    return hi, lo


def sha256_to_field_pair(commit: str) -> tuple[int, int]:
    """Parse ``"sha256:<hex>"`` (or bare 64-hex) into an ordered (hi, lo) pair."""
    raw = commit[len("sha256:") :] if commit.startswith("sha256:") else commit
    try:
        digest = bytes.fromhex(raw)
    except ValueError as exc:
        raise CVZTTEError(
            ErrorCode.SCHEMA_INVALID, "invalid sha256 hex", detail={"value": commit}
        ) from exc
    return digest_to_limbs(digest)


def capability_field(name: str) -> int:
    """Encode a capability name to a single (<2^128) field integer:

    ``int_be( sha256( CAP_DOMAIN || 0x00 || name )[16:32] )``.
    """
    h = hashlib.sha256()
    h.update(CAP_DOMAIN.encode("utf-8"))
    h.update(b"\x00")
    h.update(name.encode("utf-8"))
    return int.from_bytes(h.digest()[16:], "big")
