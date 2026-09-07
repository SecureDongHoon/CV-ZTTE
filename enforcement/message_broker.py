"""Agent Message Broker (spec §23, §60.12).

Mediates protected agent-to-agent (and outbound external) messaging. Enforces
sender, receiver, purpose/delegation, classification, and capability
propagation, and prevents authority laundering: an authority propagated in a
message must be a delegation that was legitimately issued to the receiver
(subset of the parent, expiry ≤ parent, non-widened scope, valid chain) — which
the :class:`DelegationRegistry` guarantees. A fabricated or invalid delegation
is refused.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.context.model import ObservationSource
from cvztte.delegation.model import DelegationRegistry
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import (
    AuthorizedDecision,
    EnforcementBroker,
    ExecutionResult,
)


@dataclass(frozen=True)
class MessageRequest:
    to_agent: str
    purpose_code: str
    content: str
    external: bool = False
    data_classification: DataClassification = DataClassification.INTERNAL
    propagate_delegation_id: str | None = None


@dataclass(frozen=True)
class MessageConfig:
    allowed_external_recipients: frozenset[str] = field(default_factory=frozenset)
    allow_secret_external: bool = False


class MessageBroker(EnforcementBroker):
    source = ObservationSource.MESSAGE_BROKER
    audience = "agent-message-broker-01"

    def __init__(
        self,
        config: MessageConfig,
        *args,
        delegations: DelegationRegistry | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._cfg = config
        self._delegations = delegations

    def observe(self, request: MessageRequest, binding: AdapterBinding) -> AgentAction:
        return AgentAction(
            action_type=(
                ActionType.EXTERNAL_MESSAGE if request.external else ActionType.AGENT_MESSAGE
            ),
            target=request.to_agent,
            operation="send",
            arguments={"purpose_code": request.purpose_code},
            data_classification=request.data_classification,
        )

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: MessageRequest
    ) -> ExecutionResult:
        # External recipient allowlist.
        if request.external and request.to_agent not in self._cfg.allowed_external_recipients:
            raise CVZTTEError(
                ErrorCode.MESSAGE_DENIED,
                "external recipient not permitted",
                detail={"to": request.to_agent},
            )
        # Classification egress.
        if (
            request.external
            and request.data_classification
            in (DataClassification.SECRET, DataClassification.CONFIDENTIAL)
            and not self._cfg.allow_secret_external
        ):
            raise CVZTTEError(
                ErrorCode.MESSAGE_DENIED, "confidential/secret external message denied"
            )
        # Capability propagation / anti-laundering.
        if request.propagate_delegation_id is not None:
            if self._delegations is None:
                raise CVZTTEError(
                    ErrorCode.MESSAGE_DENIED,
                    "cannot validate propagated delegation (no registry)",
                )
            try:
                # The propagated authority MUST be a delegation legitimately bound
                # to the receiver with a still-valid chain. issue_child already
                # enforced subset/expiry/scope; here we reject fabricated/invalid.
                self._delegations.validate_for_agent(
                    request.propagate_delegation_id, request.to_agent
                )
            except CVZTTEError as exc:
                raise CVZTTEError(
                    ErrorCode.MESSAGE_DENIED,
                    "propagated delegation invalid (authority laundering refused)",
                ) from exc

        digest = "sha256:" + hashlib.sha256(request.content.encode("utf-8")).hexdigest()
        return ExecutionResult(
            result_ref=f"message:{request.to_agent}",
            result_hash=digest,
            detail={
                "to": request.to_agent,
                "purpose_code": request.purpose_code,
                "external": request.external,
            },
        )
