"""Decision Token Authority (spec §31, §60.11).

The authority is the *only* component that mints Decision Tokens and the *only*
holder of the gateway-only MAC key. After the control plane has run its checks
(ML-DSA / OPA / gnark / behavior / Judge / EZKL) and produced a decision, it
calls :meth:`DecisionTokenAuthority.issue` to mint a short-lived, single-use,
execution-bound token for a specific enforcement audience.

The authority binds the token to the *canonical action* — it recomputes the
ActionHash itself and derives the exact target/operation/payload constraints
from the action, so a token can only ever authorize the action it was minted
for (§4.11). It does not accept an agent-supplied hash.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from cvztte.action.model import AgentAction
from cvztte.adapters.base import AdapterBinding
from cvztte.decision.mac import compute_mac
from cvztte.decision.model import (
    ContainmentState,
    DecisionToken,
    EpochSet,
    SignedDecisionToken,
    TokenChecks,
    TokenDecision,
)
from cvztte.errors import CVZTTEError, ErrorCode

#: Spec §31 default: single use, very short TTL.
DEFAULT_TTL_SECONDS = 30
#: 16 bytes = 128 bits of nonce entropy (spec §11 minimum).
_NONCE_BYTES = 16


class DecisionTokenAuthority:
    """Mints MAC-authenticated Decision Tokens. Holds the gateway-only key."""

    def __init__(self, mac_key: bytes, *, default_ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        if not mac_key or len(mac_key) < 32:
            # A weak/empty gateway key would undermine token authenticity.
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "decision-token MAC key must be >=32 bytes",
            )
        # Gateway-only: kept private; never returned or logged.
        self._key = bytes(mac_key)
        self._default_ttl = default_ttl_seconds

    def issue(
        self,
        *,
        action: AgentAction,
        binding: AdapterBinding,
        audience: str,
        policy_hash: str,
        epochs: EpochSet,
        decision: TokenDecision = TokenDecision.ALLOW,
        risk_level: int = 0,
        containment_state: ContainmentState = ContainmentState.NORMAL,
        checks: TokenChecks | None = None,
        request_id: str | None = None,
        max_uses: int = 1,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> SignedDecisionToken:
        if max_uses < 1:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "max_uses must be >= 1")
        now = now or datetime.now(timezone.utc)
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "ttl must be positive")

        # The authority independently derives the binding from the canonical
        # action; it never trusts an agent-supplied hash or constraint.
        token = DecisionToken(
            decision_id="dec_" + uuid.uuid4().hex,
            request_id=request_id or "req_" + uuid.uuid4().hex,
            agent_id=binding.agent_id,
            runtime_id=binding.runtime_id,
            session_id=binding.session_id,
            action_hash=action.action_hash(),
            action_type=action.action_type.value,
            target_constraint=action.target,
            operation_constraint=action.operation,
            payload_hash=action.payload_ref.hash if action.payload_ref else None,
            policy_hash=policy_hash,
            risk_level=risk_level,
            containment_state=containment_state,
            decision=decision,
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(seconds=ttl),
            max_uses=max_uses,
            nonce=secrets.token_hex(_NONCE_BYTES),
            audience=audience,
            epochs=epochs,
            checks=checks or TokenChecks(),
        )
        mac = compute_mac(self._key, token)
        return SignedDecisionToken(token=token, mac=mac)
