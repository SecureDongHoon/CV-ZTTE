"""FHE Context Registry (spec §37).

A CKKS context is *registry-controlled*: crypto parameters (scheme, ring
dimension, depth, scaling, batch size, security profile, key epoch, threshold
settings) come from the enterprise registry, **never from an agent** (§37). The
context is pinned by a domain-separated ``context_hash``; substitution of a
different context or key epoch is rejected (§38).

This module holds the *declaration* + registry. The actual OpenFHE artifacts
(serialized context/keys) are produced by the native broker (Phase 14
``FHEBrokerClient``) and their bytes are hash-pinned separately.
"""

from __future__ import annotations

import enum
import threading

from pydantic import BaseModel, ConfigDict, Field

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode


class FHEScheme(str, enum.Enum):
    CKKS = "CKKS"  # approximate real analytics (§36); the Phase 14 E2E scheme
    BFV = "BFV"
    BGV = "BGV"


class ContextStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class SecurityProfile(str, enum.Enum):
    """§37: demo params may be weaker and MUST be labelled; secure-lab is 128-bit."""

    DEMO = "demo"
    SECURE_LAB = "secure-lab"


class ThresholdConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    participants: int = 0
    #: Documented semantics — e.g. "all N participants required" (§41). Do NOT
    #: claim 2-of-3 unless the selected workflow actually supports that.
    required_semantics: str = ""


class FHEContext(BaseModel):
    """Registry-controlled CKKS context declaration (spec §37)."""

    model_config = ConfigDict(extra="forbid")

    context_id: str
    scheme: FHEScheme = FHEScheme.CKKS
    openfhe_version: str
    security_profile: SecurityProfile
    ring_dimension: int = 0  # 0 => library-chosen for the security level
    multiplicative_depth: int
    scaling_mod_size: int
    batch_size: int
    key_epoch: int = Field(ge=0)
    threshold: ThresholdConfig = Field(default_factory=ThresholdConfig)
    status: ContextStatus = ContextStatus.ACTIVE

    def context_hash(self) -> str:
        """Domain-separated commitment over the pinned parameters (§37)."""
        return commit(
            Domain.FHE_CONTEXT,
            {
                "context_id": self.context_id,
                "scheme": self.scheme.value,
                "openfhe_version": self.openfhe_version,
                "security_profile": self.security_profile.value,
                "ring_dimension": self.ring_dimension,
                "multiplicative_depth": self.multiplicative_depth,
                "scaling_mod_size": self.scaling_mod_size,
                "batch_size": self.batch_size,
                "key_epoch": self.key_epoch,
                "threshold": self.threshold.model_dump(),
            },
        )


class FHEContextRegistry:
    """Holds approved contexts. Agents reference a context_id; they cannot mint one."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, FHEContext] = {}

    def register(self, context: FHEContext) -> str:
        """Register an approved context; returns its pinned hash."""
        with self._lock:
            self._by_id[context.context_id] = context
        return context.context_hash()

    def get(self, context_id: str) -> FHEContext:
        with self._lock:
            ctx = self._by_id.get(context_id)
        if ctx is None:
            raise CVZTTEError(ErrorCode.FHE_CONTEXT_UNKNOWN, "unknown FHE context")
        return ctx

    def require_active(self, context_id: str, *, expected_hash: str) -> FHEContext:
        """Resolve a context and reject substitution/retirement (fail-closed, §38)."""
        ctx = self.get(context_id)
        if ctx.status is not ContextStatus.ACTIVE:
            raise CVZTTEError(
                ErrorCode.FHE_CONTEXT_UNAPPROVED, "FHE context is not ACTIVE"
            )
        if ctx.context_hash() != expected_hash:
            raise CVZTTEError(
                ErrorCode.FHE_CONTEXT_MISMATCH, "FHE context hash mismatch (substitution)"
            )
        return ctx
