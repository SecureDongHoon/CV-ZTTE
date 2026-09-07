"""Secret Broker (spec §21, §60.12).

Implements **use-without-disclosure**: the agent references a logical secret
*handle* and a registered downstream *operation*; the broker retrieves the
secret internally, injects it into the controlled downstream operation, and
returns only the operation's non-secret result. The secret value never appears
in the agent context, the response, the receipt, or any log/audit record. A
direct raw secret read is denied (spec §21).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.context.model import ObservationSource
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import (
    AuthorizedDecision,
    EnforcementBroker,
    ExecutionResult,
)

# Downstream operation: receives the resolved secret + params, returns a
# NON-SECRET result. The operation is responsible for not echoing the secret.
DownstreamOp = Callable[[str, dict], Any]

# Operation names that would disclose the raw secret are always refused.
_DISCLOSURE_OPS = frozenset({"reveal", "read", "read_secret", "get", "export"})


@dataclass(frozen=True)
class SecretRequest:
    secret_handle: str
    operation: str
    params: dict[str, Any] | None = None


class SecretBroker(EnforcementBroker):
    source = ObservationSource.SECRET_BROKER
    audience = "secret-broker-01"

    def __init__(
        self,
        *args,
        secrets: dict[str, str],
        operations: dict[str, DownstreamOp],
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        # Internal only; never exposed through any public method.
        self._secrets = dict(secrets)
        self._operations = dict(operations)

    def observe(self, request: SecretRequest, binding: AdapterBinding) -> AgentAction:
        # The canonical action binds the handle + operation, NOT the secret value
        # (the secret never enters the action, hash, or any signed/audited field).
        return AgentAction(
            action_type=ActionType.SECRET_ACCESS,
            target=request.secret_handle,
            operation=request.operation,
            data_classification=DataClassification.SECRET,
        )

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: SecretRequest
    ) -> ExecutionResult:
        if request.operation in _DISCLOSURE_OPS:
            raise CVZTTEError(
                ErrorCode.SECRET_DISCLOSURE_FORBIDDEN,
                "raw secret disclosure is not permitted; use a downstream operation",
            )
        if request.secret_handle not in self._secrets:
            raise CVZTTEError(ErrorCode.SECRET_UNKNOWN, "unknown secret handle")
        op = self._operations.get(request.operation)
        if op is None:
            raise CVZTTEError(
                ErrorCode.ENFORCEMENT_DENIED,
                "unknown downstream operation",
                detail={"operation": request.operation},
            )

        secret = self._secrets[request.secret_handle]
        result = op(secret, dict(request.params or {}))
        # Defense in depth: never allow the secret to leak into the result.
        serialized = json.dumps(result, sort_keys=True, default=str)
        if secret in serialized:
            raise CVZTTEError(
                ErrorCode.SECRET_DISCLOSURE_FORBIDDEN,
                "downstream result contained the secret; refusing to release",
            )
        digest = "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return ExecutionResult(
            result_ref=f"secret-op:{request.operation}",
            result_hash=digest,
            detail={"result": result},
        )
