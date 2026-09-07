"""Framework adapter contract (spec §15, §60.9).

Adapters are **semantic sensors, not trust boundaries** (§4.2). They normalize a
framework-specific event into a canonical :class:`AgentAction`, enrich it with an
:class:`AgentContext`, and record :class:`Provenance` — then stop. An adapter
**never authorizes, signs, mints a token, or executes** (§60.9); it produces an
:class:`ActionProposal` that the control plane must still drive through the full
request → verify → policy → enforcement pipeline.

Key consequences enforced here:

* Adapter observation is NOT boundary observation: ``provenance.boundary_observed``
  is always ``False`` for an adapter proposal. For high-risk effects the
  enforcement point is authoritative (§7), never the adapter.
* A missing/degraded semantic context never lowers protection (§4.3); it only
  lowers ``semantic_context_quality``, which policy treats more strictly.
"""

from __future__ import annotations

import abc
import datetime
from typing import ClassVar, Mapping

from pydantic import BaseModel, ConfigDict

from cvztte.action.model import AgentAction
from cvztte.context.model import (
    AgentContext,
    ObservationSource,
    Provenance,
    SemanticContextQuality,
)
from cvztte.errors import CVZTTEError, ErrorCode


def _now_rfc3339() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class AdapterBinding(BaseModel):
    """The CV-ZTTE identity the runtime binds to a framework event.

    This is supplied by the onboarding/runtime layer, NOT invented by the
    adapter — the adapter only observes framework semantics.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: str
    runtime_id: str
    session_id: str
    delegation_id: str | None = None


class FrameworkEvent(BaseModel):
    """A normalized envelope around one framework-specific tool/message event.

    ``payload`` carries the framework's own semantics (adapter-interpreted).
    Identity comes from ``binding``; adapters must not read identity from the
    untrusted payload.
    """

    model_config = ConfigDict(extra="forbid")

    binding: AdapterBinding
    payload: Mapping[str, object]
    workflow_id: str | None = None
    node_id: str | None = None
    purpose_code: str | None = None
    observed_at: str | None = None


class ActionProposal(BaseModel):
    """An adapter's proposal: a canonical action + context + provenance.

    A proposal carries NO authorization artifacts (no signature, token, or
    decision). It is inert until the control plane processes it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: AgentAction
    context: AgentContext
    provenance: Provenance

    def action_hash(self) -> str:
        return self.action.action_hash()


class FrameworkAdapter(abc.ABC):
    """Base adapter. Subclasses implement :meth:`normalize_action` only; the rest
    of the contract (context, provenance, proposal) is provided here so every
    adapter is guaranteed to propose-only."""

    framework: ClassVar[str]
    adapter_id: ClassVar[str]
    default_quality: ClassVar[SemanticContextQuality] = SemanticContextQuality.PARTIAL
    #: Experimental extension points (e.g. browser) set this True (§60.9).
    experimental: ClassVar[bool] = False

    @abc.abstractmethod
    def normalize_action(self, event: FrameworkEvent) -> AgentAction:
        """Map a framework event into a canonical :class:`AgentAction`."""

    def runtime_identity(self, event: FrameworkEvent) -> str:
        """Return the bound runtime id (spec §60.9)."""
        return event.binding.runtime_id

    def semantic_context(self, event: FrameworkEvent) -> AgentContext:
        """Build the :class:`AgentContext` from the binding + framework metadata."""
        action = self.normalize_action(event)
        return AgentContext(
            agent_id=event.binding.agent_id,
            runtime_id=event.binding.runtime_id,
            session_id=event.binding.session_id,
            delegation_id=event.binding.delegation_id,
            framework=self.framework,
            adapter_id=self.adapter_id,
            workflow_id=event.workflow_id,
            node_id=event.node_id,
            purpose_code=event.purpose_code,
            data_classification=action.data_classification,
            semantic_context_quality=self.default_quality,
        )

    def propose(self, event: FrameworkEvent) -> ActionProposal:
        """Produce an inert :class:`ActionProposal`. Never authorizes (§60.9)."""
        action = self.normalize_action(event)
        context = self.semantic_context(event)
        provenance = Provenance(
            source=ObservationSource.ADAPTER,
            adapter_id=self.adapter_id,
            runtime_id=event.binding.runtime_id,
            observed_at=event.observed_at or _now_rfc3339(),
            # An adapter is a sensor, not a boundary (§7): never authoritative.
            boundary_observed=False,
        )
        return ActionProposal(action=action, context=context, provenance=provenance)

    # -- helpers for subclasses ---------------------------------------------

    @staticmethod
    def _require(payload: Mapping[str, object], key: str) -> object:
        if key not in payload:
            raise CVZTTEError(
                ErrorCode.SCHEMA_INVALID,
                "framework event missing required field",
                detail={"field": key},
            )
        return payload[key]

    @staticmethod
    def _str(payload: Mapping[str, object], key: str, default: str | None = None) -> str | None:
        val = payload.get(key, default)
        if val is None:
            return None
        return str(val)
