# Enforcement Fabric (Phase 7)

The Enforcement Fabric is the set of mandatory-mediation brokers that sit on
every protected boundary. In ENFORCE mode the agent runtime has no direct path
to files, network, secrets, processes, downstream MCP servers, other agents, or
user output — each such effect crosses a broker that observes the real
operation, independently authorizes it, and executes **only** on an exact match.

Spec references: §16 (common flow), §18 (egress), §19 (file), §20 (process),
§21 (secret), §22 (output DLP), §23 (agent messaging / anti-laundering),
§17 (MCP gateway), §60.12 (enforcement points), §4.11 / §4.20 (invariants).

## Common mediation flow (`enforcement/common.py`)

Every broker derives from `EnforcementBroker` and runs the identical sequence,
failing closed at each step (`§4.20`: no security-subsystem error maps to an
implicit ALLOW):

1. **observe** — build a canonical `AgentAction` from the broker-specific
   request. The broker observes the *actual* operation; it never trusts an
   agent-declared description.
2. **recompute the ActionHash** independently (`action.action_hash()`), never a
   supplied hash.
3. **authorize** via the injected `DecisionValidator`. Any `CVZTTEError` →
   `DENIED` receipt is emitted and the error re-raised. The real cryptographic
   Decision Token validator arrives in **Phase 8**; the fabric depends only on
   the `DecisionValidator` protocol, keeping the seam explicit and testable.
4. **exact-match binding** (`_assert_exact_match`) — re-check `action_hash`,
   `target_constraint`, `operation_constraint`, and `payload_hash` at the
   boundary. This is defense-in-depth for invariant §4.11: *a token for Action A
   cannot execute Action B.* A mismatch → `FINAL_ACTION_BINDING_FAILED`.
5. **effect gate** — the decision must be `ALLOW`; `DENY`/`REDACT` → no execute.
6. **execute** — `_execute()` performs the effect. A `CVZTTEError` yields a
   `FAILED` receipt and re-raise; any *unexpected* exception is wrapped as
   `EXECUTION_FAILED` (internals never leak).
7. **receipt** — an `ExecutionReceipt` is emitted (`EXECUTED` / `DENIED` /
   `FAILED`) via the injected `ReceiptSink`. Receipts are hashable with a
   domain-separated commit (`Domain.EXECUTION_RECEIPT`). The durable, chained
   audit log is delivered in Phase 8; Phase 7 ships `InMemoryReceiptSink`.

`AuthorizedDecision` carries the exact-match constraints (`§60.11` forbids broad
wildcards; a `None` constraint means "not constrained on this dimension" and is
only produced by explicitly modeled bounded capabilities).

## Brokers

| Module | Boundary | Key controls |
| --- | --- | --- |
| `file_broker.py` | FILE_READ/WRITE/DELETE | bounded workspace root; reject absolute + `..`; realpath containment; `O_NOFOLLOW` + `/proc/self/fd` re-verify to close the TOCTOU/symlink-escape window (§19) |
| `egress_proxy.py` | NETWORK_REQUEST | scheme/host/port/path-class normalization; internal-vs-external (private/loopback IPs, internal suffixes); domain allowlist; byte limit; secret/confidential egress policy. **No TLS content-inspection claim** (§18) |
| `secret_broker.py` | SECRET_ACCESS | **use-without-disclosure** (§21): agent names a handle + registered downstream op; broker injects the secret internally, returns only the non-secret result; raw `reveal`/`read`/`export` refused; result re-scanned so the secret can never leak |
| `output_proxy.py` | USER_OUTPUT | DLP ALLOW/REDACT/DENY (§22): synthetic-credential patterns → DENY; PII sample + CONFIDENTIAL → REDACT; SECRET → DENY |
| `process_broker.py` | PROCESS_EXEC | command allowlist (basename); **never `shell=True`** (argv only, §20); CPU + address-space + output rlimits; non-root; best-effort `unshare --user --net` namespace isolation with documented fallback |
| `message_broker.py` | AGENT_MESSAGE / EXTERNAL_MESSAGE | external-recipient allowlist; classification egress; **anti-authority-laundering** (§23): a propagated delegation must be a valid chain legitimately bound to the receiver, else `MESSAGE_DENIED` |
| `mcp_gateway.py` | MCP_CALL | agent sees only a logical server name + gateway endpoint; protected endpoints/credentials are internal with no accessor; forwards the exact approved tool/args, injects the credential internally, optional result sanitizer; unmapped server → `MCP_BYPASS_DENIED`; credential-leak defense |

## Secrets & credentials never surface

The secret broker and MCP gateway both serialize their result and refuse to
release it if the raw secret/credential appears (`SECRET_DISCLOSURE_FORBIDDEN`).
Receipts bind the *handle*/*server*, never the secret value — verified by tests
that assert the value is absent from the emitted receipt JSON.

## Fail-closed summary

- Missing/failing validator, hash mismatch, constraint mismatch, non-ALLOW
  effect, or any execution error → **no effect performed**, receipt records the
  denial/failure.
- Absent adapter semantic context never lowers protection (§4.3): the brokers
  observe the real operation regardless of what a framework adapter proposed.

## Error codes (added in `cvztte/errors.py`)

`ENFORCEMENT_DENIED`, `FILE_PATH_ESCAPE`, `FILE_ACCESS_DENIED`, `EGRESS_DENIED`,
`PROCESS_COMMAND_DENIED`, `SECRET_DISCLOSURE_FORBIDDEN`, `SECRET_UNKNOWN`,
`OUTPUT_DENIED`, `MESSAGE_DENIED`, `MCP_BYPASS_DENIED`.

## Tests

`tests/integration/test_enforcement.py` (26 tests) drives every broker through
the common flow with a deterministic **test-only** `RefValidator` (clearly not a
production crypto validator — that is Phase 8). Coverage: roundtrips; traversal /
absolute / symlink-escape rejection; denied-token no-effect; exact-match §4.11
mismatch; egress allowlist / byte-limit / secret-egress / internal-allowed;
use-without-disclosure + leak refusal + unknown handle; DLP allow/redact/deny;
command allow/deny; message external-allowlist + anti-laundering + valid
propagation; MCP forward + credential hiding + bypass denial.
