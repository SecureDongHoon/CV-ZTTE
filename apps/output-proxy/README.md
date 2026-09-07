# apps/output-proxy — output DLP demo

Exercises the real `OutputProxy` DLP over final user output (§19):

```bash
source env.sh
python apps/output-proxy/run.py
```

Demonstrates ALLOW (benign), REDACT (PII sample, CONFIDENTIAL classification), and
DENY (synthetic credential patterns, SECRET classification → `OUTPUT_DENIED`).
Enforced in addition to the Decision Token; this runner injects
`apps/_refvalidator` to focus on the DLP layer. See `docs/ENFORCEMENT_FABRIC.md`.
