"""Domain-separated SHA-256 commitments (spec §8).

    H(domain, bytes) = SHA256( UTF8(domain) || 0x00 || bytes )

``domain`` is drawn from :class:`~cvztte.canonical.domains.Domain`. The 0x00
separator makes the (domain, payload) split unambiguous. Object commitments are
computed over RFC 8785 canonical bytes so producer and verifier agree exactly.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cvztte.canonical.domains import Domain
from cvztte.canonical.jcs import canonicalize

_SEP = b"\x00"


def domain_hash(domain: Domain, payload: bytes) -> bytes:
    """Raw 32-byte domain-separated digest."""
    h = hashlib.sha256()
    h.update(domain.value.encode("utf-8"))
    h.update(_SEP)
    h.update(payload)
    return h.digest()


def domain_hash_hex(domain: Domain, payload: bytes) -> str:
    """``"sha256:<hex>"`` form used throughout CV-ZTTE JSON objects."""
    return "sha256:" + domain_hash(domain, payload).hex()


def commit(domain: Domain, value: Any) -> str:
    """Domain-separated commitment over the JCS-canonical bytes of ``value``.

    This is the canonical way to compute ActionHash, policy/delegation
    commitments, behavior-state hashes, receipt hashes, etc.
    """
    return domain_hash_hex(domain, canonicalize(value))
