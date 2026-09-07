"""SignedActionRequest — the canonical, signature-covered request (spec §10, §60.3).

Every security-relevant field is covered by the ML-DSA signature over the
domain-separated canonical bytes, so mutating any of them (action, session,
policy_hash, sequence, …) invalidates the signature. The signature input is::

    signing_input = UTF8(Domain.REQUEST) || 0x00 || JCS(request_fields)

which binds the signature to the *request* object class (defends
"Action A proof/token cannot execute Action B", §4.11) and to the exact
canonical bytes both signer and verifier compute.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cvztte.action.model import AgentAction
from cvztte.canonical.domains import Domain
from cvztte.canonical.jcs import canonicalize

PROTOCOL_VERSION = "3.0"
_SEP = b"\x00"


class SignedActionRequest(BaseModel):
    """Signature-covered request fields (spec §60.3). Unknown fields rejected."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: str = PROTOCOL_VERSION
    agent_id: str
    key_id: str
    runtime_id: str
    session_id: str
    delegation_id: str
    policy_hash: str
    action: AgentAction
    action_hash: str
    timestamp: str      # RFC 3339 UTC
    expires_at: str     # RFC 3339 UTC
    sequence: int = Field(ge=0)
    nonce: str          # >=128-bit CSPRNG hex
    request_id: str

    def canonical_dict(self) -> dict[str, Any]:
        """Deterministic dict of all signature-covered fields."""
        return self.model_dump(mode="json")

    def signing_input(self) -> bytes:
        """Domain-separated canonical bytes fed to ML-DSA sign/verify."""
        return Domain.REQUEST.value.encode("utf-8") + _SEP + canonicalize(
            self.canonical_dict()
        )


class SignedEnvelope(BaseModel):
    """Wire form: the request plus its detached ML-DSA signature (base64)."""

    model_config = ConfigDict(extra="forbid")

    request: SignedActionRequest
    signature_b64: str
