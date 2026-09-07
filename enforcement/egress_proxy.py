"""Network Egress Proxy (spec §18, §60.12).

In ENFORCE mode the agent runtime has no unrestricted egress; all outbound
network effects cross this proxy. It normalizes scheme/host/IP/port/method/path
class/payload hash/byte estimate/classification, and enforces boundary egress
controls: domain allowlist, internal/external distinction, byte limits, and
secret/confidential egress policy. These are enforced IN ADDITION to the
Decision Token (both must pass — fail closed).

This reference does NOT terminate TLS or inspect HTTPS content (spec §18: do not
claim content inspection unless TLS is actually terminated under controlled
policy). Actual forwarding is delegated to an injected sender; if none is
provided, the proxy validates and records the normalized request without making
a live connection.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

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
    EnforcementBroker,
    ExecutionResult,
)


@dataclass(frozen=True)
class EgressRequest:
    url: str
    method: str = "GET"
    body: bytes | None = None
    data_classification: DataClassification = DataClassification.INTERNAL


@dataclass(frozen=True)
class EgressConfig:
    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    internal_domain_suffixes: frozenset[str] = field(default_factory=frozenset)
    max_bytes: int = 1_000_000
    allow_secret_egress_external: bool = False


def _is_internal_host(host: str, cfg: EgressConfig) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    return any(host == s or host.endswith("." + s) for s in cfg.internal_domain_suffixes)


class EgressProxy(EnforcementBroker):
    source = ObservationSource.EGRESS_PROXY
    audience = "egress-proxy-01"

    def __init__(
        self,
        config: EgressConfig,
        *args,
        sender: Callable[[dict], ExecutionResult] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._cfg = config
        self._sender = sender

    def observe(self, request: EgressRequest, binding: AdapterBinding) -> AgentAction:
        parsed = urlparse(request.url)
        if not parsed.scheme or not parsed.hostname:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "malformed egress URL")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path_class = (parsed.path or "/").split("/", 2)[1] if parsed.path.strip("/") else "root"
        body = request.body or b""
        payload_ref = PayloadRef(
            ref=f"egress-body:{host}{parsed.path}",
            hash="sha256:" + hashlib.sha256(body).hexdigest(),
            size=len(body),
        )
        return AgentAction(
            action_type=ActionType.NETWORK_REQUEST,
            target=host,
            operation=request.method.upper(),
            resource=f"{parsed.scheme}://{host}:{port}{parsed.path}",
            arguments={
                "scheme": parsed.scheme,
                "port": port,
                "path_class": path_class,
            },
            data_classification=request.data_classification,
            payload_ref=payload_ref,
        )

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: EgressRequest
    ) -> ExecutionResult:
        host = action.target
        cfg = self._cfg
        internal = _is_internal_host(host, cfg)
        size = action.payload_ref.size if action.payload_ref else 0

        # Byte limit.
        if size > cfg.max_bytes:
            raise CVZTTEError(
                ErrorCode.EGRESS_DENIED,
                "payload exceeds egress byte limit",
                detail={"size": size, "limit": cfg.max_bytes},
            )
        # External destinations must be explicitly allowlisted.
        if not internal and host not in cfg.allowed_domains:
            raise CVZTTEError(
                ErrorCode.EGRESS_DENIED,
                "external destination not on allowlist",
                detail={"host": host},
            )
        # Secret/confidential egress policy.
        if (
            not internal
            and action.data_classification
            in (DataClassification.SECRET, DataClassification.CONFIDENTIAL)
            and not cfg.allow_secret_egress_external
        ):
            raise CVZTTEError(
                ErrorCode.EGRESS_DENIED, "confidential/secret egress to external denied"
            )

        normalized = {
            "host": host,
            "resource": action.resource,
            "method": action.operation,
            "internal": internal,
            "payload_hash": action.payload_ref.hash if action.payload_ref else None,
            "size": size,
        }
        if self._sender is not None:
            return self._sender(normalized)
        # No live sender wired: record the validated, normalized request.
        return ExecutionResult(
            result_ref=action.resource,
            result_hash=action.payload_ref.hash if action.payload_ref else None,
            detail={"forwarded": False, "normalized": normalized},
        )
