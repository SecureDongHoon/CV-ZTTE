"""CAC — Confidential Agent Collaboration (spec §35-§47).

Approved computation over ciphertext without plaintext disclosure, on real
OpenFHE CKKS. Phase 14 foundations:

* :mod:`cvztte.cac.permissions` — the READ_PLAINTEXT / COMPUTE_ON_CIPHERTEXT /
  DECRYPT_RESULT split and containment ceilings (§35, §47);
* :mod:`cvztte.cac.context` — registry-controlled CKKS contexts (§37);
* :mod:`cvztte.cac.program` — the allowlisted program registry (§39);
* :mod:`cvztte.cac.envelope` — ciphertext/result envelopes + substitution
  rejection (§38);
* :mod:`cvztte.cac.broker` — the Python client over the native C++ FHE broker
  (§36, §40);
* :mod:`cvztte.cac.guard` — the fail-closed CAC permission gate (§42, §47).

Phase 15 adds :mod:`cvztte.cac.threshold` — genuine OpenFHE N-of-N multiparty
key generation and release-gated distributed decryption, where no service holds
a reconstructed full secret key (§41, §42).
"""

from __future__ import annotations

from cvztte.cac.broker import FHEBrokerClient, default_binary_path
from cvztte.cac.context import (
    ContextStatus,
    FHEContext,
    FHEContextRegistry,
    FHEScheme,
    SecurityProfile,
    ThresholdConfig,
)
from cvztte.cac.envelope import (
    CiphertextEnvelope,
    ResultEnvelope,
    assert_no_substitution,
)
from cvztte.cac.guard import require_compute, require_decrypt, require_read_plaintext
from cvztte.cac.permissions import (
    CACPermission,
    REFERENCE_ROLE_GRANTS,
    ceiling_for,
    effective_cac_permissions,
)
from cvztte.cac.program import (
    FHEProgram,
    FHEProgramRegistry,
    ProgramId,
    default_programs,
)

__all__ = [
    "FHEBrokerClient",
    "default_binary_path",
    "ContextStatus",
    "FHEContext",
    "FHEContextRegistry",
    "FHEScheme",
    "SecurityProfile",
    "ThresholdConfig",
    "CiphertextEnvelope",
    "ResultEnvelope",
    "assert_no_substitution",
    "require_compute",
    "require_decrypt",
    "require_read_plaintext",
    "CACPermission",
    "REFERENCE_ROLE_GRANTS",
    "ceiling_for",
    "effective_cac_permissions",
    "FHEProgram",
    "FHEProgramRegistry",
    "ProgramId",
    "default_programs",
]
