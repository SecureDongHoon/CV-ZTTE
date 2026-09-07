"""SignedActionRequest verification (spec §10, §11, §16).

Order matters and every step fails closed. This covers the identity/integrity
and freshness-of-expiry checks; the *atomic* replay/sequence commit is done by
:class:`cvztte.replay.redis_freshness.ReplayGuard` (spec §11) and MUST be run by
the enforcement pipeline before an ALLOW. Nothing here can authorize an action —
it only establishes that the request is authentic, unmutated, and unexpired.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity.registry import KeyRegistry
from cvztte.request.model import PROTOCOL_VERSION, SignedActionRequest, SignedEnvelope

#: Tolerance for benign clock skew on the future-dating check.
CLOCK_SKEW = timedelta(seconds=30)


def _parse_rfc3339(value: str, *, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise CVZTTEError(
            ErrorCode.SCHEMA_INVALID, f"invalid {field} timestamp"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_request(
    registry: KeyRegistry,
    envelope: SignedEnvelope,
    *,
    now: datetime | None = None,
    expected_policy_hash: str | None = None,
) -> SignedActionRequest:
    """Cryptographically verify an envelope; raise on any defect."""
    now = now or datetime.now(timezone.utc)
    request = envelope.request

    # 1. Protocol version.
    if request.protocol_version != PROTOCOL_VERSION:
        raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "unsupported protocol version")

    # 2. ActionHash must be the control-plane-recomputed value, not trusted input
    #    (§16): same canonical action identified/signed/authorized/executed.
    recomputed = request.action.action_hash()
    if recomputed != request.action_hash:
        raise CVZTTEError(
            ErrorCode.ACTION_HASH_MISMATCH, "action_hash does not match action"
        )

    # 3. Optional policy pinning.
    if expected_policy_hash is not None and request.policy_hash != expected_policy_hash:
        raise CVZTTEError(ErrorCode.POLICY_HASH_MISMATCH, "policy hash mismatch")

    # 4. Signature over domain-separated canonical bytes, enforcing key
    #    state/window/revocation (raises KEY_REVOKED / KEY_UNKNOWN / MLDSA_INVALID).
    try:
        signature = base64.b64decode(envelope.signature_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise CVZTTEError(ErrorCode.MLDSA_INVALID, "malformed signature") from exc

    key_record = registry.get_key(request.key_id)  # raises KEY_UNKNOWN
    # 5. Bind key to the claimed agent: a valid signature under a key registered
    #    to a different agent must not authenticate this agent (§4 invariants).
    if key_record.agent_id != request.agent_id:
        raise CVZTTEError(ErrorCode.MLDSA_INVALID, "key not bound to agent")

    registry.verify_with_key(
        request.key_id, request.signing_input(), signature, now=now
    )

    # 6. Freshness (expiry / not-future-dated). Monotonic sequence + nonce
    #    replay are committed atomically by the ReplayGuard.
    expires_at = _parse_rfc3339(request.expires_at, field="expires_at")
    timestamp = _parse_rfc3339(request.timestamp, field="timestamp")
    if now >= expires_at:
        raise CVZTTEError(ErrorCode.REQUEST_EXPIRED, "request expired")
    if timestamp > now + CLOCK_SKEW:
        raise CVZTTEError(ErrorCode.REQUEST_EXPIRED, "request timestamp is in the future")

    return request
