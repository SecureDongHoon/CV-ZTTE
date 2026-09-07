"""Concrete framework adapters (spec §15, §60.9).

Each adapter maps its framework's tool/message events into a canonical
:class:`AgentAction`. They enrich and propose only — authorization and execution
happen later in the pipeline. Unknown/ambiguous events degrade the context
quality rather than guessing a low-risk action type (§4.3).
"""

from __future__ import annotations

from typing import ClassVar, Mapping

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import FrameworkAdapter, FrameworkEvent
from cvztte.context.model import SemanticContextQuality

# Coarse tool-kind -> ActionType mapping shared by several adapters. Unknown
# kinds fall back to TOOL_CALL (a consequential, non-privileged default) and the
# adapter lowers context quality.
_KIND_TO_ACTION: dict[str, ActionType] = {
    "http": ActionType.NETWORK_REQUEST,
    "network": ActionType.NETWORK_REQUEST,
    "api": ActionType.API_REQUEST,
    "db": ActionType.DB_OPERATION,
    "database": ActionType.DB_OPERATION,
    "file_read": ActionType.FILE_READ,
    "file_write": ActionType.FILE_WRITE,
    "file_delete": ActionType.FILE_DELETE,
    "shell": ActionType.SHELL_EXEC,
    "process": ActionType.PROCESS_EXEC,
    "code": ActionType.CODE_EXECUTION,
    "secret": ActionType.SECRET_ACCESS,
    "memory_read": ActionType.MEMORY_READ,
    "memory_write": ActionType.MEMORY_WRITE,
    "user_output": ActionType.USER_OUTPUT,
}


def _classification(payload: Mapping[str, object]) -> DataClassification:
    raw = payload.get("data_classification")
    if raw is None:
        return DataClassification.INTERNAL
    try:
        return DataClassification(str(raw))
    except ValueError:
        return DataClassification.INTERNAL


def _arguments(payload: Mapping[str, object]) -> dict:
    args = payload.get("arguments", {})
    return dict(args) if isinstance(args, Mapping) else {}


class MCPAdapter(FrameworkAdapter):
    """Model Context Protocol tool calls."""

    framework: ClassVar[str] = "mcp"
    adapter_id: ClassVar[str] = "mcp-v1"
    default_quality: ClassVar[SemanticContextQuality] = SemanticContextQuality.RICH

    def normalize_action(self, event: FrameworkEvent) -> AgentAction:
        p = event.payload
        server = self._str(p, "server") or "unknown"
        tool = str(self._require(p, "tool"))
        return AgentAction(
            action_type=ActionType.MCP_CALL,
            target=f"{server}/{tool}",
            operation=tool,
            resource=server,
            arguments=_arguments(p),
            data_classification=_classification(p),
        )


class _KindAdapter(FrameworkAdapter):
    """Shared normalization for frameworks that expose a tool ``kind``/``type``."""

    default_quality: ClassVar[SemanticContextQuality] = SemanticContextQuality.RICH

    def normalize_action(self, event: FrameworkEvent) -> AgentAction:
        p = event.payload
        kind = (self._str(p, "kind") or self._str(p, "tool_type") or "").lower()
        action_type = _KIND_TO_ACTION.get(kind, ActionType.TOOL_CALL)
        target = self._str(p, "target") or self._str(p, "tool") or "unknown"
        return AgentAction(
            action_type=action_type,
            target=str(target),
            operation=self._str(p, "operation") or self._str(p, "tool"),
            resource=self._str(p, "resource"),
            arguments=_arguments(p),
            data_classification=_classification(p),
        )

    def semantic_context(self, event: FrameworkEvent):
        ctx = super().semantic_context(event)
        # If we could not resolve a specific tool kind, degrade quality so policy
        # treats it more strictly (§60.10) instead of trusting a TOOL_CALL guess.
        kind = (self._str(event.payload, "kind") or self._str(event.payload, "tool_type") or "").lower()
        if kind not in _KIND_TO_ACTION:
            return ctx.model_copy(
                update={"semantic_context_quality": SemanticContextQuality.PARTIAL}
            )
        return ctx


class LangGraphAdapter(_KindAdapter):
    framework: ClassVar[str] = "langgraph"
    adapter_id: ClassVar[str] = "langgraph-v1"


class LangChainAdapter(_KindAdapter):
    framework: ClassVar[str] = "langchain"
    adapter_id: ClassVar[str] = "langchain-v1"


class CodingAgentAdapter(_KindAdapter):
    """Coding-agent runtime (shell/file/code operations)."""

    framework: ClassVar[str] = "coding-agent"
    adapter_id: ClassVar[str] = "coding-agent-v1"


class GenericSDKAdapter(FrameworkAdapter):
    """Generic/custom SDK: caller provides an explicit canonical action_type."""

    framework: ClassVar[str] = "generic"
    adapter_id: ClassVar[str] = "generic-v1"
    default_quality: ClassVar[SemanticContextQuality] = SemanticContextQuality.PARTIAL

    def normalize_action(self, event: FrameworkEvent) -> AgentAction:
        p = event.payload
        raw_type = str(self._require(p, "action_type"))
        try:
            action_type = ActionType(raw_type)
        except ValueError:
            action_type = ActionType.TOOL_CALL
        return AgentAction(
            action_type=action_type,
            target=str(self._require(p, "target")),
            operation=self._str(p, "operation"),
            resource=self._str(p, "resource"),
            arguments=_arguments(p),
            data_classification=_classification(p),
        )


class AgentMessageAdapter(FrameworkAdapter):
    """Agent-to-agent (and outbound external) messaging."""

    framework: ClassVar[str] = "agent-messaging"
    adapter_id: ClassVar[str] = "agent-msg-v1"
    default_quality: ClassVar[SemanticContextQuality] = SemanticContextQuality.RICH

    def normalize_action(self, event: FrameworkEvent) -> AgentAction:
        p = event.payload
        external = bool(p.get("external", False))
        recipient = self._str(p, "to") or self._str(p, "recipient") or "unknown"
        action_type = ActionType.EXTERNAL_MESSAGE if external else ActionType.AGENT_MESSAGE
        return AgentAction(
            action_type=action_type,
            target=str(recipient),
            operation="send",
            resource=self._str(p, "channel"),
            arguments=_arguments(p),
            data_classification=_classification(p),
        )


class BrowserAdapter(FrameworkAdapter):
    """Experimental browser-automation extension point (spec §60.9).

    The live browser automation stack is not wired in this reference build; the
    interfaces are preserved and events are normalized deterministically so the
    rest of the pipeline is exercised. Because no live boundary observation
    occurs, quality is capped at PARTIAL and callers should treat browser
    proposals as advisory until a real browser boundary is integrated.
    """

    framework: ClassVar[str] = "browser"
    adapter_id: ClassVar[str] = "browser-v1"
    default_quality: ClassVar[SemanticContextQuality] = SemanticContextQuality.PARTIAL
    experimental: ClassVar[bool] = True

    _EVENT_MAP: ClassVar[dict[str, ActionType]] = {
        "navigate": ActionType.NETWORK_REQUEST,
        "form_submit": ActionType.NETWORK_REQUEST,
        "upload": ActionType.FILE_READ,
        "download": ActionType.FILE_WRITE,
    }

    def normalize_action(self, event: FrameworkEvent) -> AgentAction:
        p = event.payload
        kind = str(self._require(p, "event")).lower()
        action_type = self._EVENT_MAP.get(kind, ActionType.NETWORK_REQUEST)
        target = self._str(p, "url") or self._str(p, "target") or "unknown"
        return AgentAction(
            action_type=action_type,
            target=str(target),
            operation=kind,
            resource=self._str(p, "domain"),
            arguments=_arguments(p),
            data_classification=_classification(p),
        )
