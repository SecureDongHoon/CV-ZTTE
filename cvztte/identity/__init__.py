"""Post-quantum Agent identity (spec §9, §60.2).

Native OpenSSL 3.5+ ML-DSA is the primary provider; private keys stay isolated
on restricted storage and never enter LLM context, logs, audit, or proofs.
"""

from cvztte.identity.provider import (
    Algorithm,
    DEFAULT_ALGORITHM,
    LibOQSFallbackProvider,
    PrivateKeyHandle,
    PublicKey,
    SignatureProvider,
)
from cvztte.identity.openssl_signer import OpenSSLMLDSAProvider
from cvztte.identity.registry import (
    AgentRecord,
    KeyRecord,
    KeyRegistry,
    KeyState,
)

__all__ = [
    "Algorithm",
    "DEFAULT_ALGORITHM",
    "LibOQSFallbackProvider",
    "PrivateKeyHandle",
    "PublicKey",
    "SignatureProvider",
    "OpenSSLMLDSAProvider",
    "AgentRecord",
    "KeyRecord",
    "KeyRegistry",
    "KeyState",
]
