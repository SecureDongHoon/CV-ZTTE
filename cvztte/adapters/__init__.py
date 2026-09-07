"""Framework adapter layer (spec §15, §60.9).

Adapters are semantic sensors, not trust boundaries: they normalize framework
events into canonical actions and propose only — they never authorize or
execute. If an adapter is absent or bypassed, mandatory mediation still applies
with a ``BOUNDARY_ONLY`` context (see :func:`boundary_only_context`).
"""

from cvztte.adapters.base import (
    ActionProposal,
    AdapterBinding,
    FrameworkAdapter,
    FrameworkEvent,
)
from cvztte.adapters.frameworks import (
    AgentMessageAdapter,
    BrowserAdapter,
    CodingAgentAdapter,
    GenericSDKAdapter,
    LangChainAdapter,
    LangGraphAdapter,
    MCPAdapter,
)
from cvztte.adapters.registry import (
    AdapterRegistry,
    boundary_only_context,
    boundary_provenance,
)

__all__ = [
    "ActionProposal",
    "AdapterBinding",
    "FrameworkAdapter",
    "FrameworkEvent",
    "MCPAdapter",
    "LangGraphAdapter",
    "LangChainAdapter",
    "CodingAgentAdapter",
    "GenericSDKAdapter",
    "AgentMessageAdapter",
    "BrowserAdapter",
    "AdapterRegistry",
    "boundary_only_context",
    "boundary_provenance",
]
