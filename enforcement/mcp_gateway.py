"""MCP Gateway (spec §17, §60.12).

The agent receives the gateway endpoint, never the protected MCP server address
or its credentials. The gateway terminates agent-side MCP, maps logical server
names to protected servers, hides credentials, normalizes the call, validates
the decision, forwards the exact approved tool/arguments (injecting the protected
credential internally), optionally sanitizes the result, and emits a receipt.

Direct protected-MCP access is impossible through this object: protected
endpoints/credentials are internal and there is no accessor for them. A call to
an unmapped logical server is refused (``MCP_BYPASS_DENIED``).
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

# Handler for a protected server: (tool, arguments, credential) -> result. The
# credential is supplied by the gateway internally; the agent never sees it.
ProtectedHandler = Callable[[str, dict, str], Any]


@dataclass(frozen=True)
class ProtectedServer:
    endpoint: str  # internal; hidden from the agent
    credential: str  # internal; injected by the gateway, never exposed
    handler: ProtectedHandler


@dataclass(frozen=True)
class MCPRequest:
    server: str  # logical name only
    tool: str
    arguments: dict[str, Any] | None = None
    data_classification: DataClassification = DataClassification.INTERNAL


class MCPGateway(EnforcementBroker):
    source = ObservationSource.MCP_GATEWAY
    audience = "mcp-gateway-01"

    def __init__(
        self,
        *args,
        servers: dict[str, ProtectedServer],
        sanitizer: Callable[[Any], Any] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._servers = dict(servers)  # internal only
        self._sanitizer = sanitizer

    def observe(self, request: MCPRequest, binding: AdapterBinding) -> AgentAction:
        return AgentAction(
            action_type=ActionType.MCP_CALL,
            target=f"{request.server}/{request.tool}",
            operation=request.tool,
            resource=request.server,
            arguments=dict(request.arguments or {}),
            data_classification=request.data_classification,
        )

    def _execute(
        self, action: AgentAction, decision: AuthorizedDecision, request: MCPRequest
    ) -> ExecutionResult:
        server = self._servers.get(request.server)
        if server is None:
            # Unmapped logical server: no protected endpoint is reachable.
            raise CVZTTEError(
                ErrorCode.MCP_BYPASS_DENIED,
                "unknown MCP server; direct/protected access refused",
                detail={"server": request.server},
            )
        # Forward the EXACT approved tool/arguments; inject the credential here.
        result = server.handler(request.tool, dict(request.arguments or {}), server.credential)
        if self._sanitizer is not None:
            result = self._sanitizer(result)

        serialized = json.dumps(result, sort_keys=True, default=str)
        # Defense in depth: never let the protected credential leak into output.
        if server.credential in serialized:
            raise CVZTTEError(
                ErrorCode.SECRET_DISCLOSURE_FORBIDDEN,
                "MCP result contained the protected credential; refusing to release",
            )
        digest = "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return ExecutionResult(
            result_ref=f"mcp:{request.server}/{request.tool}",
            result_hash=digest,
            detail={"result": result},
        )
