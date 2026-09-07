"""Agent-SDK request assembly (spec §10, §11).

The SDK maintains a per-session monotonic **sequence** and a fresh CSPRNG
**nonce** for every request, assembles the canonical :class:`SignedActionRequest`,
and signs it via the identity registry. Per spec §10 the SDK **cannot
authorize** — it only proves origin/freshness; authorization is decided later by
the control plane. The LLM never sees the private key (signing is delegated to
the isolated provider through the registry).
"""

from __future__ import annotations

import base64
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

from cvztte.action.model import AgentAction
from cvztte.identity.registry import KeyRegistry
from cvztte.request.model import PROTOCOL_VERSION, SignedActionRequest, SignedEnvelope

#: 16 bytes = 128 bits of CSPRNG entropy (spec §11 minimum).
NONCE_BYTES = 16
DEFAULT_TTL_SECONDS = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class SequenceSource:
    """Thread-safe per-session monotonic sequence counter (SDK-side state)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, str], int] = {}

    def next(self, agent_id: str, session_id: str) -> int:
        key = (agent_id, session_id)
        with self._lock:
            nxt = self._counters.get(key, -1) + 1
            self._counters[key] = nxt
            return nxt


class RequestBuilder:
    """Assembles and signs SignedActionRequests. Cannot authorize (spec §10)."""

    def __init__(self, registry: KeyRegistry, *, sequences: SequenceSource | None = None) -> None:
        self._registry = registry
        self._sequences = sequences or SequenceSource()

    def build_and_sign(
        self,
        *,
        agent_id: str,
        runtime_id: str,
        session_id: str,
        delegation_id: str,
        policy_hash: str,
        action: AgentAction,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: datetime | None = None,
    ) -> SignedEnvelope:
        now = now or _now()
        sequence = self._sequences.next(agent_id, session_id)
        # Determine the signing key first so we can bind key_id into the
        # signature-covered fields (key_id is itself signature-covered, §60.3).
        signing_key = self._registry.active_signing_key(agent_id, now=now)
        request = SignedActionRequest(
            protocol_version=PROTOCOL_VERSION,
            agent_id=agent_id,
            key_id=signing_key.key_id,
            runtime_id=runtime_id,
            session_id=session_id,
            delegation_id=delegation_id,
            policy_hash=policy_hash,
            action=action,
            action_hash=action.action_hash(),
            timestamp=_rfc3339(now),
            expires_at=_rfc3339(now + timedelta(seconds=ttl_seconds)),
            sequence=sequence,
            nonce=secrets.token_hex(NONCE_BYTES),
            request_id="req_" + uuid.uuid4().hex,
        )
        key_id, signature = self._registry.sign_as_agent(
            agent_id, request.signing_input(), now=now
        )
        # Sanity: the key that signed must be the one named in the request.
        assert key_id == request.key_id
        return SignedEnvelope(
            request=request,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )
