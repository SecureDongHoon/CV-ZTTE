"""Canonicalization, strict parsing, and domain-separated commitments (spec §8)."""

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit, domain_hash, domain_hash_hex
from cvztte.canonical.jcs import canonicalize
from cvztte.canonical.strict_json import strict_loads

__all__ = [
    "Domain",
    "canonicalize",
    "commit",
    "domain_hash",
    "domain_hash_hex",
    "strict_loads",
]
