# apps/agent-demo — full-stack demonstration (Demo A + E)

Narrated end-to-end run through the **real** integrated stack (the same code
`tests/e2e/test_full_path.py` asserts on):

```bash
source env.sh
python apps/agent-demo/demo.py
```

1. **ALLOW** — a registered agent opens a session; the file broker observes the
   real write; the request is signed with native ML-DSA; the control plane
   evaluates to ALLOW and mints a short-lived, execution-bound Decision Token; the
   broker independently re-observes, re-validates, and executes; the file is
   written and the hash-chained audit log verifies.
2. **QUARANTINE** — an admin quarantines the subject (bumping the shared
   capability epoch); a fresh action is denied with `CONTAINMENT_QUARANTINED` and
   nothing is executed.

Real: `OpenSSLMLDSAProvider`, `DecisionTokenAuthority` + `DecisionTokenValidator`
over one shared `EpochSource`, `ContainmentEngine`, real `FileBroker`. The OPA
decision is injected with a fixed ALLOW shim so the demo is deterministic/offline;
the real OPA path runs in `apps/gateway` and `tests/integration/test_opa.py`.
