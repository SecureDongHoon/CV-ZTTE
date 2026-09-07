"""Decision Token validator — the real :class:`DecisionValidator` (spec §16, §31).

This is the enforcement-side counterpart to the authority. It implements the
:class:`enforcement.common.DecisionValidator` protocol (the seam Phase 7 left
open) and performs the full step-4/5 validation of the common flow:

* MAC verification with the gateway-only key (constant time);
* token version + action-type + action-hash binding;
* agent/runtime/session binding to the observed request;
* enforcement audience match;
* not-before / expiry (TTL);
* epoch freshness (stale epochs rejected, §27);
* single-use / max-uses (replay tracked, §31);
* exact target/operation/payload constraints.

Every failure raises :class:`CVZTTEError` (fail closed, §4.20). Only a valid
``ALLOW`` (or the token's own effect) yields an :class:`AuthorizedDecision`; the
broker still re-checks the exact-match constraints as defense in depth.

Because the Phase 7 protocol passes only ``(action, action_hash, binding,
audience)``, the presented token is retrieved from an injected
:class:`PresentedTokenStore` — modeling the agent presenting, at the enforcement
point, the exact token the authority issued it. The store never mints tokens.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from cvztte.action.model import AgentAction
from cvztte.adapters.base import AdapterBinding
from cvztte.decision.mac import verify_mac
from cvztte.decision.model import EpochSet, SignedDecisionToken, TokenDecision
from cvztte.decision.replay import InMemoryTokenUseTracker, TokenUseTracker
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import AuthorizedDecision, DecisionEffect


class EpochSource:
    """Holds the current epochs; enforcement rejects tokens that don't match.

    Bumping an epoch (revocation, policy change, capability decay, risk change —
    Phase 10 drives these) invalidates every token minted under the older value.
    """

    def __init__(self, epochs: EpochSet | None = None) -> None:
        self._lock = threading.Lock()
        self._epochs = epochs or EpochSet()

    def current(self) -> EpochSet:
        with self._lock:
            return self._epochs

    def set(self, epochs: EpochSet) -> None:
        with self._lock:
            self._epochs = epochs


class PresentedTokenStore:
    """Where an agent presents the token it holds, keyed by (audience, action_hash).

    Not a mint: it only carries tokens the authority already produced. Multi-use
    tokens stay presented; single-use is enforced by the :class:`TokenUseTracker`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: dict[tuple[str, str], SignedDecisionToken] = {}

    @staticmethod
    def _key(audience: str, action_hash: str) -> tuple[str, str]:
        return (audience, action_hash)

    def present(self, signed: SignedDecisionToken) -> None:
        key = self._key(signed.token.audience, signed.token.action_hash)
        with self._lock:
            self._by_key[key] = signed

    def get(self, audience: str, action_hash: str) -> SignedDecisionToken | None:
        with self._lock:
            return self._by_key.get(self._key(audience, action_hash))


class DecisionTokenValidator:
    """Validates the presented Decision Token for an observed action."""

    def __init__(
        self,
        *,
        mac_key: bytes,
        epoch_source: EpochSource,
        store: PresentedTokenStore,
        use_tracker: TokenUseTracker | None = None,
    ) -> None:
        if not mac_key:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE, "missing decision-token key"
            )
        self._key = bytes(mac_key)
        self._epochs = epoch_source
        self._store = store
        self._uses = use_tracker or InMemoryTokenUseTracker()

    def authorize(
        self,
        *,
        action: AgentAction,
        action_hash: str,
        binding: AdapterBinding,
        audience: str,
        now: datetime | None = None,
    ) -> AuthorizedDecision:
        now = now or datetime.now(timezone.utc)

        signed = self._store.get(audience, action_hash)
        if signed is None:
            raise CVZTTEError(
                ErrorCode.DECISION_TOKEN_INVALID, "no decision token presented"
            )
        token = signed.token

        # 1. Authenticity: gateway-only keyed MAC (constant time).
        if not verify_mac(self._key, token, signed.mac):
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_INVALID, "token MAC invalid")

        # 2. Version + action binding.
        if token.token_version != 3:
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_INVALID, "unsupported token version")
        if token.action_hash != action_hash:
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED, "token action_hash mismatch"
            )
        if token.action_type != action.action_type.value:
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_INVALID, "action type mismatch")

        # 3. Agent/runtime/session binding.
        if (
            token.agent_id != binding.agent_id
            or token.runtime_id != binding.runtime_id
            or token.session_id != binding.session_id
        ):
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_INVALID, "token binding mismatch")

        # 4. Audience.
        if token.audience != audience:
            raise CVZTTEError(
                ErrorCode.DECISION_TOKEN_AUDIENCE_MISMATCH, "token audience mismatch"
            )

        # 5. TTL window.
        if now < _aware(token.not_before):
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_EXPIRED, "token not yet valid")
        if now >= _aware(token.expires_at):
            raise CVZTTEError(ErrorCode.DECISION_TOKEN_EXPIRED, "token expired")

        # 6. Epoch freshness (stale epochs rejected, §27).
        if token.epochs != self._epochs.current():
            raise CVZTTEError(
                ErrorCode.DECISION_TOKEN_EPOCH_STALE, "token minted under a stale epoch"
            )

        # 7. Exact target/operation/payload constraints (§16 step 6).
        if token.target_constraint != action.target:
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED, "target constraint mismatch"
            )
        if (
            token.operation_constraint is not None
            and token.operation_constraint != action.operation
        ):
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED, "operation constraint mismatch"
            )
        supplied_payload = action.payload_ref.hash if action.payload_ref else None
        if token.payload_hash != supplied_payload:
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED, "payload hash mismatch"
            )

        # 8. Single-use / replay (record only after all checks pass).
        self._uses.consume(token.nonce, token.max_uses)

        return AuthorizedDecision(
            decision_id=token.decision_id,
            effect=DecisionEffect(token.decision.value),
            action_hash=token.action_hash,
            target_constraint=token.target_constraint,
            operation_constraint=token.operation_constraint,
            payload_hash=token.payload_hash,
            risk_level=token.risk_level,
            audience=token.audience,
        )


def _aware(dt: datetime) -> datetime:
    """Treat naive datetimes as UTC so comparisons never raise."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
