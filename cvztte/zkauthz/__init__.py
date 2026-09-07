"""CV-ZTTE gnark ZK-authorization Python client (spec §14, §60.5).

The control plane invokes the ``zk-authz`` Go service as a subprocess. This
package provides the deterministic SHA-256->BN254 field bridge (mirroring the Go
``bridge`` package), the pinned artifact registry, and the fail-closed client.
See docs/GNARK_BINDING.md.
"""

from cvztte.zkauthz.bridge import (
    CAP_DOMAIN,
    capability_field,
    digest_to_limbs,
    sha256_to_field_pair,
)
from cvztte.zkauthz.client import Assignment, ZKAuthzClient
from cvztte.zkauthz.registry import ZKRegistry

__all__ = [
    "CAP_DOMAIN",
    "capability_field",
    "digest_to_limbs",
    "sha256_to_field_pair",
    "Assignment",
    "ZKAuthzClient",
    "ZKRegistry",
]
