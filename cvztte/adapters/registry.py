"""Adapter registry and the adapter-absent fallback (spec §15, §60.10).

When a framework is known, its adapter provides RICH/PARTIAL semantic context.
When an adapter is **absent or bypassed**, mandatory mediation still applies:
the enforcement point constructs a ``BOUNDARY_ONLY`` context with stricter risk
policy (§15). This module provides both the registry and the boundary-only
context/provenance builder used by the enforcement fabric.
"""

from __future__ import annotations

import datetime

from cvztte.action.model import DataClassification
from cvztte.adapters.base import AdapterBinding, FrameworkAdapter
from cvztte.adapters.frameworks import (
    AgentMessageAdapter,
    BrowserAdapter,
    CodingAgentAdapter,
    GenericSDKAdapter,
    LangChainAdapter,
    LangGraphAdapter,
    MCPAdapter,
)
from cvztte.context.model import (
    AgentContext,
    ObservationSource,
    Provenance,
    SemanticContextQuality,
)


def _now_rfc3339() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class AdapterRegistry:
    """Maps a framework name to its adapter instance."""

    def __init__(self) -> None:
        self._by_framework: dict[str, FrameworkAdapter] = {}
        for adapter in (
            MCPAdapter(),
            LangGraphAdapter(),
            LangChainAdapter(),
            CodingAgentAdapter(),
            GenericSDKAdapter(),
            AgentMessageAdapter(),
            BrowserAdapter(),
        ):
            self.register(adapter)

    def register(self, adapter: FrameworkAdapter) -> None:
        self._by_framework[adapter.framework] = adapter

    def get(self, framework: str) -> FrameworkAdapter | None:
        """Return the adapter for ``framework`` or ``None`` if unknown."""
        return self._by_framework.get(framework)

    def frameworks(self) -> list[str]:
        return sorted(self._by_framework)


def boundary_only_context(
    binding: AdapterBinding,
    *,
    data_classification: DataClassification = DataClassification.INTERNAL,
) -> AgentContext:
    """Context used when no adapter observed the action (§15, §60.10).

    Semantic quality is ``BOUNDARY_ONLY``; policy applies stricter risk handling
    and high-risk actions default to DENY/ESCALATE.
    """
    return AgentContext(
        agent_id=binding.agent_id,
        runtime_id=binding.runtime_id,
        session_id=binding.session_id,
        delegation_id=binding.delegation_id,
        framework=None,
        adapter_id=None,
        data_classification=data_classification,
        semantic_context_quality=SemanticContextQuality.BOUNDARY_ONLY,
    )


def boundary_provenance(
    binding: AdapterBinding,
    source: ObservationSource,
    *,
    observed_at: str | None = None,
) -> Provenance:
    """Provenance for an effect observed at an enforcement boundary.

    Unlike an adapter proposal, a boundary observation IS authoritative for
    high-risk effects (§7): ``boundary_observed`` is ``True``.
    """
    return Provenance(
        source=source,
        adapter_id=None,
        runtime_id=binding.runtime_id,
        observed_at=observed_at or _now_rfc3339(),
        boundary_observed=True,
    )
