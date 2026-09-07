# CV-ZTTE Policy Model (Phase 4)

Authoritative deterministic policy is OPA/Rego (spec §13). This document
describes the bundle, its input/decision contract, the risk tiers, and how the
bundle is versioned and hash-pinned.

## Authority and flow

Agents never self-authorize (spec §12). Policy originates from a **trusted
Policy Authority** (security admin / authorized user / orchestrator-IAM),
optionally via a natural-language → compiler → strict-validation → admin-approval
pipeline. The **active** policy is deterministic, versioned, hash-pinned, and
auditable. Natural language is UX input only.

## Bundle

- Location: `policy/rego/cvztte/authz.rego`, package `cvztte.authz`, Rego v1.
- Evaluated via the pinned `opa` CLI (`opa eval -f json -I -d <bundle> data.cvztte.authz.decision`).
- Fail-closed: a missing binary, eval error, malformed output, or **undefined
  decision** all raise `OPA_UNAVAILABLE` — never an implicit ALLOW
  (`cvztte/policy/opa_client.py`).

## Input contract (`cvztte.policy.build_authz_input`)

```json
{
  "action": {
    "action_type": "FILE_READ",
    "operation": "read",
    "resource": "fs:/data/report.csv",
    "data_classification": "INTERNAL",
    "destination_domain": "api.example.com",   // network actions only
    "row_count": 10,                             // optional
    "byte_count": 1024                           // optional
  },
  "grant": {
    "capabilities": ["fs:read"],
    "resource_scopes": ["fs:/data"],
    "clearance": "CONFIDENTIAL",
    "allow_external_network": false,
    "network_allowlist": ["api.example.com"],
    "shell_permitted": false,
    "secret_access_permitted": false,
    "max_db_rows": 1000,
    "max_external_bytes": 1048576
  }
}
```

The `grant` is the authorization envelope the Policy Authority binds to an agent.
`grant_from_delegation` derives it from a **validated** delegation: capability
set and resource scopes come straight from the delegation (so they can never
exceed what was delegated), boolean gates (`shell_permitted`,
`secret_access_permitted`, `allow_external_network`) are derived from the
delegated capability set, and quantitative limits/allowlists are policy config.

## Decision contract (spec §60.4)

```json
{
  "allow": true,
  "reason_code": "ALLOW",
  "risk_level": 2,
  "require_gnark_authz": false,
  "require_behavior_check": true,
  "require_ezkl": false,
  "require_human_approval": false
}
```

**Hard DENY is final** (spec §13): if any `violation` holds, `allow` is false and
downstream risk logic cannot re-enable it. `authorize()` raises `OPA_DENY`.
`reason_code` is the lexicographically-first violation, one of:
`CAPABILITY_MISSING`, `SCOPE_NOT_COVERED`, `CLEARANCE_INSUFFICIENT`,
`EXTERNAL_NETWORK_FORBIDDEN`, `DOMAIN_NOT_ALLOWLISTED`, `SHELL_FORBIDDEN`,
`SECRET_ACCESS_FORBIDDEN`, `DB_ROW_LIMIT_EXCEEDED`, `EXTERNAL_BYTE_LIMIT_EXCEEDED`.

## Risk tiers (spec §28)

| Tier | Trigger | Added controls |
|---|---|---|
| L0 | observational / public | — |
| L1 | internal, low-risk | — |
| L2 | sensitive read | + behavior check |
| L3 | write / external / high-value | + gnark + EZKL + behavior |
| L4 | secret / shell / destructive / decrypt | + human approval (strongest) |

`risk_level` is the max over deterministic contributions of action type and
classification. Risk may **add** controls but never removes the mandatory
baseline (strict parse, ML-DSA, replay, OPA, audit, containment) enforced by the
pipeline regardless of tier.

## Versioning and pinning (spec §12, §13)

`compute_bundle_hash(bundle, version)` is a domain-separated commitment
(`Domain.POLICY`) over the bundle `version` plus a canonical manifest of every
`.rego` file's SHA-256. `PolicyBundleRegistry` tracks the **active** bundle;
`require_pinned(policy_hash)` rejects any request whose `policy_hash` differs
from the active pin (`POLICY_HASH_MISMATCH`). Changing any policy file or the
version changes the pin.
