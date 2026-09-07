"""Output Proxy (spec §22, §60.12).

Protected final output (USER_OUTPUT) is consequential and audited. Beyond the
Decision Token, the proxy applies DLP-like content controls and decides
ALLOW / REDACT / DENY (spec §22): synthetic-credential detection, a PII sample,
and confidential-classification handling. Content is carried by ephemeral ref +
hash. A raw credential in the output is never released.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from cvztte.action.model import (
    ActionType,
    AgentAction,
    DataClassification,
    PayloadRef,
)
from cvztte.adapters.base import AdapterBinding
from cvztte.context.model import ObservationSource
from cvztte.errors import CVZTTEError, ErrorCode
from enforcement.common import (
    AuthorizedDecision,
    DecisionEffect,
    EnforcementBroker,
    ExecutionResult,
)

# Synthetic credential patterns (release is always DENIED if matched).
_CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # generic secret-key style token
    re.compile(r"(?i)(password|api[_-]?key|secret)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
]

# PII sample (redacted before release).
_PII_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # US SSN-like
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),  # card-like number run
]


@dataclass(frozen=True)
class OutputRequest:
    content: str
    data_classification: DataClassification = DataClassification.INTERNAL


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class OutputProxy(EnforcementBroker):
    source = ObservationSource.OUTPUT_PROXY
    audience = "output-proxy-01"

    def observe(self, request: OutputRequest, binding: AdapterBinding) -> AgentAction:
        return AgentAction(
            action_type=ActionType.USER_OUTPUT,
            target="user-output",
            operation="release",
            data_classification=request.data_classification,
            payload_ref=PayloadRef(
                ref="ephemeral-output", hash=_digest(request.content),
                size=len(request.content),
            ),
        )

    def _decide(self, request: OutputRequest) -> tuple[DecisionEffect, str]:
        content = request.content
        for pat in _CREDENTIAL_PATTERNS:
            if pat.search(content):
                return DecisionEffect.DENY, content
        if request.data_classification is DataClassification.SECRET:
            return DecisionEffect.DENY, content
        redacted = content
        pii_found = False
        for pat in _PII_PATTERNS:
            redacted, n = pat.subn("[REDACTED]", redacted)
            pii_found = pii_found or n > 0
        if pii_found or request.data_classification is DataClassification.CONFIDENTIAL:
            return DecisionEffect.REDACT, redacted
        return DecisionEffect.ALLOW, content

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: OutputRequest
    ) -> ExecutionResult:
        effect, content = self._decide(request)
        if effect is DecisionEffect.DENY:
            raise CVZTTEError(
                ErrorCode.OUTPUT_DENIED, "output release denied by DLP controls"
            )
        return ExecutionResult(
            result_ref="ephemeral-output",
            result_hash=_digest(content),
            detail={"effect": effect.value, "content": content},
        )
