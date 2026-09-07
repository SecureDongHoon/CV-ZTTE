"""Signature-provider abstraction for Agent identity (spec §9, §60.2).

Primary provider is **native OpenSSL 3.5+ ML-DSA** (see
:mod:`cvztte.identity.openssl_signer`). The abstraction exposes exactly the
operations the spec enumerates::

    generate_key / import_private_key / import_public_key
    sign / verify / algorithm / provider_metadata

Design invariants preserved here:

* **Private keys never enter LLM context / logs / audit / proofs** (spec §9).
  Private material is referenced through an opaque :class:`PrivateKeyHandle`
  whose ``repr`` is redacted; providers keep the bytes on restricted storage,
  not in returned values.
* **No silent downgrade** (spec §60.2): the default algorithm is ML-DSA-65 and
  a provider is pinned to a single algorithm for its lifetime.
* **liboqs is not the production path**: :class:`LibOQSFallbackProvider` is
  disabled by default and visibly reports its non-production status.
"""

from __future__ import annotations

import abc
import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cvztte.errors import CVZTTEError, ErrorCode

import enum


class Algorithm(str, enum.Enum):
    """ML-DSA parameter sets standardized in FIPS 204 (spec §9, §60.2)."""

    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"


#: Default per spec §9 / §60.2. Policy MAY permit others; downgrade is forbidden.
DEFAULT_ALGORITHM = Algorithm.ML_DSA_65


def _spki_fingerprint(public_pem: bytes) -> str:
    """Format-independent fingerprint of a SubjectPublicKeyInfo PEM.

    We decode the base64 body to DER so the fingerprint is stable regardless of
    PEM line wrapping / trailing whitespace, then domain-tag it. This is a key
    *identifier*, not secret; public keys are, by definition, public.
    """
    body_lines: list[str] = []
    in_body = False
    for line in public_pem.decode("ascii", errors="strict").splitlines():
        if line.startswith("-----BEGIN"):
            in_body = True
            continue
        if line.startswith("-----END"):
            break
        if in_body:
            body_lines.append(line.strip())
    if not body_lines:
        raise CVZTTEError(
            ErrorCode.SCHEMA_INVALID, "public key PEM has no SPKI body"
        )
    der = base64.b64decode("".join(body_lines))
    return "sha256:" + hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class PublicKey:
    """A public verification key. Safe to log / audit / distribute."""

    algorithm: Algorithm
    pem: bytes  # SubjectPublicKeyInfo PEM

    @property
    def fingerprint(self) -> str:
        return _spki_fingerprint(self.pem)


@dataclass(frozen=True)
class PrivateKeyHandle:
    """Opaque reference to private key material held on restricted storage.

    The signing bytes are intentionally NOT carried in-process; the handle only
    names where the isolated signer can find them. ``repr`` is redacted so the
    location never leaks into logs/tracebacks that might reach an LLM context.
    """

    algorithm: Algorithm
    path: Path

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"PrivateKeyHandle(algorithm={self.algorithm.value}, path=<redacted>)"


class SignatureProvider(abc.ABC):
    """Abstract post-quantum signature provider (spec §60.2)."""

    #: Human-readable provider name (e.g. ``"openssl-native"``).
    name: str = "abstract"
    #: True only for providers acceptable on a real acceptance path.
    is_production_equivalent: bool = False

    @property
    @abc.abstractmethod
    def algorithm(self) -> Algorithm: ...

    @abc.abstractmethod
    def generate_key(self) -> tuple[PrivateKeyHandle, PublicKey]:
        """Create a fresh keypair; return (private handle, public key)."""

    @abc.abstractmethod
    def import_private_key(self, private_pem: bytes) -> PrivateKeyHandle:
        """Adopt existing private-key PEM into restricted storage."""

    @abc.abstractmethod
    def import_public_key(self, public_pem: bytes) -> PublicKey:
        """Adopt an external verification key."""

    @abc.abstractmethod
    def sign(self, handle: PrivateKeyHandle, message: bytes) -> bytes:
        """Produce a pure ML-DSA signature over ``message`` (raw bytes)."""

    @abc.abstractmethod
    def verify(self, public_key: PublicKey, message: bytes, signature: bytes) -> bool:
        """Return True iff ``signature`` is a valid ML-DSA signature of ``message``.

        Returns False for a well-formed-but-invalid signature (fail closed).
        Raises :class:`CVZTTEError` only when the provider itself is unavailable.
        """

    @abc.abstractmethod
    def provider_metadata(self) -> dict[str, Any]:
        """Non-secret metadata for audit/environment reporting."""


class LibOQSFallbackProvider(SignatureProvider):
    """Development-only liboqs fallback — disabled by default (spec §9, §60.2).

    MUST NOT be presented as the production-equivalent path. It refuses to
    operate unless explicitly enabled, and always reports its non-production
    status via :meth:`provider_metadata`.
    """

    name = "liboqs-fallback"
    is_production_equivalent = False

    def __init__(self, algorithm: Algorithm = DEFAULT_ALGORITHM, *, enabled: bool = False) -> None:
        self._algorithm = algorithm
        self._enabled = enabled

    @property
    def algorithm(self) -> Algorithm:
        return self._algorithm

    def _guard(self) -> None:
        # Visibly fail closed: never silently substitute a non-production path.
        raise CVZTTEError(
            ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
            "liboqs fallback is disabled (development-only, not production-equivalent)",
            detail={"enabled": self._enabled},
        )

    def generate_key(self) -> tuple[PrivateKeyHandle, PublicKey]:
        self._guard()
        raise AssertionError  # unreachable

    def import_private_key(self, private_pem: bytes) -> PrivateKeyHandle:
        self._guard()
        raise AssertionError

    def import_public_key(self, public_pem: bytes) -> PublicKey:
        self._guard()
        raise AssertionError

    def sign(self, handle: PrivateKeyHandle, message: bytes) -> bytes:
        self._guard()
        raise AssertionError

    def verify(self, public_key: PublicKey, message: bytes, signature: bytes) -> bool:
        self._guard()
        raise AssertionError

    def provider_metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "algorithm": self._algorithm.value,
            "production_equivalent": False,
            "enabled": self._enabled,
            "warning": "liboqs fallback is development-only and disabled by default",
        }
