# apps/egress-proxy — network egress boundary demo

Exercises the real `EgressProxy` boundary controls (§18):

```bash
source env.sh
python apps/egress-proxy/run.py
```

Demonstrates ALLOW for an allowlisted/internal host and `EGRESS_DENIED` for a
non-allowlisted domain, an over-byte-limit body, and SECRET egress to an external
host. These are enforced in addition to the Decision Token (demonstrated in
`apps/agent-demo`/`apps/gateway`); this runner injects `apps/_refvalidator` to
focus on the boundary layer. No live network connection is made. This reference
does not terminate TLS or inspect HTTPS content. See `docs/ENFORCEMENT_FABRIC.md`.
