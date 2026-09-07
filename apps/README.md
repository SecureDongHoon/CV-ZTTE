# apps/ — runnable reference entrypoints

Thin, runnable wrappers around the CV-ZTTE library and Enforcement Fabric (§49
layout). They are **reference** runners — single process, in-memory stores, HTTP
without TLS, demo keys — never production-certified (see `docs/DEPLOYMENT.md`,
`docs/FINAL_SECURITY_REVIEW.md` §29). The security logic lives in `cvztte/` and
`enforcement/`; these apps only wire and drive it.

Run any of them after `source env.sh`:

| App | Command | Shows |
|---|---|---|
| `gateway/` | `python apps/gateway/server.py` | Real Control-Plane HTTP API (§60.29) over real ML-DSA identity + real OPA; admin plane separated by `X-CVZTTE-Admin`; fails closed. |
| `agent-demo/` | `python apps/agent-demo/demo.py` | Full ALLOW path (evaluate → mint token → broker executes → audit verifies) and a quarantine DENY with zero side effects, all real crypto/token/containment (Demo A + E). |
| `protected-tool/` | `python apps/protected-tool/run.py` | Mandatory mediation: mediated success, path-traversal escape denied, tokenless bypass denied by the real validator. |
| `egress-proxy/` | `python apps/egress-proxy/run.py` | Egress boundary controls: allowlist, internal/external, byte limit, secret-egress. |
| `output-proxy/` | `python apps/output-proxy/run.py` | Output DLP: allow / redact (PII, CONFIDENTIAL) / deny (credentials, SECRET). |

`gateway` and `agent-demo` use the real `DecisionTokenValidator`. The three broker
runners focus on each broker's own boundary controls and inject
`apps/_refvalidator.ReferenceAllowValidator` (a demo shim, not part of the TCB) to
reach layer (2) offline — the same pattern as
`tests/integration/test_enforcement.py`. The token layer they rely on is
demonstrated end to end in `agent-demo`/`gateway`.

For the mapping of every §58 demonstration (A–I) to a real test, see
`docs/DEMO.md`.
