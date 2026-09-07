"""Common enforcement-point mediation flow (spec §16, §60.12).

Every broker follows the same sequence and fails closed at every step:

1. observe the actual operation and construct a canonical :class:`AgentAction`;
2. independently recompute the ActionHash (never trust an agent-supplied hash);
3. validate the Decision Token via the injected :class:`DecisionValidator`;
4. re-check the exact target/operation/payload constraints at the boundary
   (defense in depth for invariant §4.11 — a token for Action A cannot execute
   Action B);
5. execute only on an exact ALLOW match;
6. emit an :class:`ExecutionReceipt`.

The Decision Token itself is produced/validated by Phase 8; here it is an
injected protocol so the fabric is testable and the seam is explicit. Any error
in observe/authorize/exact-match prevents execution (no implicit ALLOW, §4.20).
"""

from __future__ import annotations

import abc
import datetime
import enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from cvztte.action.model import AgentAction
from cvztte.adapters.base import AdapterBinding
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.context.model import ObservationSource
from cvztte.errors import CVZTTEError, ErrorCode


def _now_rfc3339() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class DecisionEffect(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REDACT = "REDACT"


class AuthorizedDecision(BaseModel):
    """A validated decision returned by a :class:`DecisionValidator`.

    Constraints are the token's exact-match bindings (§60.11). Broad wildcards
    are forbidden (§60.11); a ``None`` constraint means "not constrained on this
    dimension" and is only produced by explicitly modeled bounded capabilities.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: str
    effect: DecisionEffect
    action_hash: str
    target_constraint: str
    operation_constraint: str | None = None
    payload_hash: str | None = None
    risk_level: int = 0
    audience: str


@runtime_checkable
class DecisionValidator(Protocol):
    """Validates the Decision Token for an observed action (Phase 8 implements).

    MUST raise :class:`CVZTTEError` on any failure (signature/MAC, hash mismatch,
    nonce/use/TTL/audience/agent/runtime/epoch, or exact-constraint mismatch).
    It returns an :class:`AuthorizedDecision` only on a valid ALLOW.
    """

    def authorize(
        self,
        *,
        action: AgentAction,
        action_hash: str,
        binding: AdapterBinding,
        audience: str,
    ) -> AuthorizedDecision: ...


class ExecutionReceipt(BaseModel):
    """Tamper-evident record of a mediated action (spec §16 step 8)."""

    model_config = ConfigDict(extra="forbid")

    receipt_version: int = 1
    decision_id: str | None
    action_hash: str
    action_type: str
    target: str
    operation: str | None
    audience: str
    source: ObservationSource
    outcome: str  # EXECUTED | DENIED | FAILED
    error_code: str | None = None
    result_hash: str | None = None
    observed_at: str

    def receipt_hash(self) -> str:
        return commit(
            Domain.EXECUTION_RECEIPT, self.model_dump(mode="json", exclude_none=True)
        )


@runtime_checkable
class ReceiptSink(Protocol):
    def emit(self, receipt: ExecutionReceipt) -> None: ...


class InMemoryReceiptSink:
    """Reference receipt sink; the durable audit log arrives in Phase 8."""

    def __init__(self) -> None:
        self.receipts: list[ExecutionReceipt] = []

    def emit(self, receipt: ExecutionReceipt) -> None:
        self.receipts.append(receipt)


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_ref: str | None = None
    result_hash: str | None = None
    detail: dict[str, Any] | None = None


class MediationOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: AgentAction
    decision: AuthorizedDecision
    result: ExecutionResult
    receipt: ExecutionReceipt


class EnforcementBroker(abc.ABC):
    """Base mandatory-mediation broker implementing the common flow.

    Subclasses implement :meth:`observe` (build the canonical action from a
    broker-specific request) and :meth:`_execute` (perform the effect — called
    ONLY after an exact ALLOW).
    """

    #: Observation source recorded in provenance/receipts.
    source: ObservationSource
    #: Token audience this broker accepts (§60.11).
    audience: str

    def __init__(self, validator: DecisionValidator, receipts: ReceiptSink) -> None:
        self._validator = validator
        self._receipts = receipts

    # -- subclass hooks ------------------------------------------------------

    @abc.abstractmethod
    def observe(self, request: Any, binding: AdapterBinding) -> AgentAction:
        """Observe the real operation and construct a canonical AgentAction."""

    @abc.abstractmethod
    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: Any
    ) -> ExecutionResult:
        """Perform the effect. Only invoked on an exact ALLOW match."""

    # -- mediation flow ------------------------------------------------------

    def mediate(self, request: Any, binding: AdapterBinding) -> MediationOutcome:
        # 1-2. observe + canonicalize.
        action = self.observe(request, binding)
        # 3. independently recompute the hash (never trust a supplied hash).
        action_hash = action.action_hash()

        # 4. validate the Decision Token (fail closed on any error).
        try:
            decision = self._validator.authorize(
                action=action,
                action_hash=action_hash,
                binding=binding,
                audience=self.audience,
            )
        except CVZTTEError as exc:
            self._emit(action, None, "DENIED", error_code=exc.code.value)
            raise

        # 5. re-check exact constraints at the boundary (defense in depth §4.11).
        self._assert_exact_match(action, action_hash, decision)
        if decision.effect is not DecisionEffect.ALLOW:
            self._emit(action, decision, "DENIED", error_code=ErrorCode.ENFORCEMENT_DENIED.value)
            raise CVZTTEError(
                ErrorCode.ENFORCEMENT_DENIED,
                "decision was not ALLOW",
                detail={"effect": decision.effect.value},
            )

        # 6. execute only on match.
        try:
            result = self._execute(action, decision, request)
        except CVZTTEError as exc:
            self._emit(action, decision, "FAILED", error_code=exc.code.value)
            raise
        except Exception as exc:  # unexpected: fail closed, do not leak internals
            self._emit(action, decision, "FAILED", error_code=ErrorCode.EXECUTION_FAILED.value)
            raise CVZTTEError(ErrorCode.EXECUTION_FAILED, "execution failed") from exc

        # 7. receipt.
        receipt = self._emit(
            action, decision, "EXECUTED", result_hash=result.result_hash
        )
        return MediationOutcome(
            action=action, decision=decision, result=result, receipt=receipt
        )

    # -- internals -----------------------------------------------------------

    def _assert_exact_match(
        self, action: AgentAction, action_hash: str, decision: AuthorizedDecision
    ) -> None:
        if decision.action_hash != action_hash:
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED,
                "decision action_hash does not match recomputed hash",
            )
        if decision.target_constraint != action.target:
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED, "target constraint mismatch"
            )
        if (
            decision.operation_constraint is not None
            and decision.operation_constraint != action.operation
        ):
            raise CVZTTEError(
                ErrorCode.FINAL_ACTION_BINDING_FAILED, "operation constraint mismatch"
            )
        if decision.payload_hash is not None:
            supplied = action.payload_ref.hash if action.payload_ref else None
            if decision.payload_hash != supplied:
                raise CVZTTEError(
                    ErrorCode.FINAL_ACTION_BINDING_FAILED, "payload hash mismatch"
                )

    def _emit(
        self,
        action: AgentAction,
        decision: AuthorizedDecision | None,
        outcome: str,
        *,
        error_code: str | None = None,
        result_hash: str | None = None,
    ) -> ExecutionReceipt:
        receipt = ExecutionReceipt(
            decision_id=decision.decision_id if decision else None,
            action_hash=action.action_hash(),
            action_type=action.action_type.value,
            target=action.target,
            operation=action.operation,
            audience=self.audience,
            source=self.source,
            outcome=outcome,
            error_code=error_code,
            result_hash=result_hash,
            observed_at=_now_rfc3339(),
        )
        self._receipts.emit(receipt)
        return receipt
