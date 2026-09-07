# apps/gateway — reference Control-Plane HTTP server

Serves the §60.29 Control-Plane API (`cvztte.control_plane.http_api`) over the
**real** wiring: native-OpenSSL ML-DSA identity, the pinned `policy/rego` OPA
bundle, and the real `ControlPlane` / `AgentPlane` / `AdminPlane` with a shared
`EpochSource` and a gateway-only Decision-Token MAC key.

```bash
source env.sh
python apps/gateway/server.py          # http://127.0.0.1:8080 by default
```

Environment:

| Var | Default | Meaning |
|---|---|---|
| `CVZTTE_HOST` | `127.0.0.1` | bind host |
| `CVZTTE_PORT` | `8080` | bind port |
| `CVZTTE_KEYSTORE` | `./.gateway-keystore` | ML-DSA keystore dir (0700) |
| `CVZTTE_POLICY_BUNDLE` | `./policy/rego` | pinned Rego bundle |
| `CVZTTE_ADMINS` | `admin_root` | comma-separated admin principals |
| `CVZTTE_TOKEN_KEY` | ephemeral | 32-byte gateway-only MAC key |

Routes (see `http_api.py`): `GET /health/live`, `GET /health/ready`,
`POST /v3/sessions`, `POST /v3/actions/evaluate`,
`GET /v3/decisions/{id}`, `GET /v3/agents/{subject}/containment`, and the
admin-gated `POST /v3/approvals/{id}`, `POST /v3/agents/{subject}/quarantine`,
`POST /v3/agents/{subject}/containment/reset` (require `X-CVZTTE-Admin`).

Fail-closed: a fresh gateway has no registered agents, so `POST /v3/sessions`
returns `AGENT_UNKNOWN` until an agent is onboarded (`cvztte/onboarding/`); admin
routes without the principal header return `ENFORCEMENT_DENIED`; if the `opa`
binary or bundle is missing, evaluation returns `OPA_UNAVAILABLE`.
`/v3/actions/evaluate-execute` intentionally returns
`SECURITY_DEPENDENCY_UNAVAILABLE` — a native enforcement broker must be wired for
execution (see `apps/protected-tool`).

**Reference only, not production-certified**: HTTP (no TLS), in-memory stores,
demo MAC key. Production terminates TLS, authenticates the admin plane properly,
holds the MAC key in an HSM/KMS, and uses durable stores — `docs/DEPLOYMENT.md`,
`docs/FINAL_SECURITY_REVIEW.md` §29.
