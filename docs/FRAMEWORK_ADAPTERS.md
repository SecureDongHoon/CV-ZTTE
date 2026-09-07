# CV-ZTTE Framework Adapter Layer (Phase 6)

Spec §15 / §60.9. Adapters provide **semantic visibility, not security
authority**. They are sensors on the agent side of the trust boundary; the
enforcement fabric (Phase 7) remains the authoritative mediation point.

## Contract

Every adapter subclasses `cvztte.adapters.base.FrameworkAdapter` and implements
exactly one method:

```python
normalize_action(event: FrameworkEvent) -> AgentAction
```

The base class provides the rest of the §60.9 contract so it cannot be
subverted per-adapter:

```python
runtime_identity(event) -> str          # bound runtime id
semantic_context(event) -> AgentContext # framework/adapter/quality enrichment
propose(event)          -> ActionProposal
```

`FrameworkEvent` separates **identity** (`binding`: agent/runtime/session/
delegation, supplied by the runtime) from **framework semantics** (`payload`,
adapter-interpreted). Adapters never read identity from the untrusted payload.

## Propose-only invariant (§60.9)

`propose()` returns an `ActionProposal(action, context, provenance)`. The
proposal is **inert**:

- it carries no signature, decision token, or authorization decision;
- `provenance.source == ADAPTER` and `provenance.boundary_observed == False` —
  an adapter observation is never authoritative for high-risk effects (§7);
- the model is frozen (`extra="forbid", frozen=True`).

The control plane must still drive the proposal through
request → verify → policy → enforcement. An adapter cannot authorize or execute.

## Adapters implemented

| Framework        | adapter_id        | Quality | Notes |
|------------------|-------------------|---------|-------|
| MCP              | `mcp-v1`          | RICH    | `{server, tool, arguments}` → `MCP_CALL` |
| LangGraph        | `langgraph-v1`    | RICH    | tool `kind`/`tool_type` → action type |
| LangChain        | `langchain-v1`    | RICH    | tool `kind`/`tool_type` → action type |
| Coding agent     | `coding-agent-v1` | RICH    | shell/file/code runtime |
| Generic/SDK      | `generic-v1`      | PARTIAL | caller supplies explicit `action_type` |
| Agent messaging  | `agent-msg-v1`    | RICH    | internal `AGENT_MESSAGE` / external `EXTERNAL_MESSAGE` |
| Browser          | `browser-v1`      | PARTIAL | **experimental** (see below) |

Unknown/ambiguous tool kinds map to the conservative `TOOL_CALL` and **degrade**
`semantic_context_quality` to PARTIAL rather than guessing a low-risk type — a
missing/uncertain context never lowers protection (§4.3, §60.10).

## Browser extension point (§60.9)

`BrowserAdapter` is an experimental extension point (`experimental = True`). The
live browser-automation stack is not wired in this reference build; the adapter
interfaces are preserved and events (`navigate`, `form_submit`, `upload`,
`download`) are normalized deterministically so the downstream pipeline is
exercised. Because no live boundary observation occurs, quality is capped at
PARTIAL and browser proposals are advisory until a real browser boundary is
integrated. This limitation is documented rather than blocking core completion.

## Adapter absent or bypassed (§15, §60.10)

If no adapter observed the action, mandatory mediation still applies. The
enforcement fabric builds a `BOUNDARY_ONLY` context via
`boundary_only_context(binding)` and records boundary provenance via
`boundary_provenance(binding, source)` (which IS authoritative —
`boundary_observed = True`). Policy treats BOUNDARY_ONLY more strictly, and
high-risk actions with insufficient context default to DENY/ESCALATE.

A `fake adapter metadata` claim (spec attack #82) changes only the *semantic*
context; it cannot alter the canonically recomputed action hash, the signature,
or the enforcement decision — the adapter is not a trust boundary.
