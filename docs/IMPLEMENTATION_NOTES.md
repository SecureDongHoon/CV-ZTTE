# CV-ZTTE v3 — Implementation Notes & Deviations

Per spec §0 rule 9, any deviation from the document's examples that is forced by
the host environment or a current library API is recorded here, together with
how the underlying **security property is preserved**. Nothing here weakens a
security property for convenience (spec §0 rule 8).

---

## D-1: User-local, no-sudo toolchain

**Context:** the shell has no passwordless sudo; the host lacked OpenSSL 3.5+,
Go, Redis, OPA, and OpenFHE.

**Decision (user-approved):** install everything user-local — OpenSSL 3.5.8,
Redis 8.10.1, and OpenFHE 1.5.1 built from source into `$HOME/opt`; Go 1.27.1 and
OPA v1.20.2 as binaries; Python deps in a project `virtualenv`. `source env.sh`
reconstructs the environment.

**Security impact:** none. Versions/commits are pinned in `ENVIRONMENT.md`.
Production would consume signed distro/vendor packages or signed release
artifacts (spec §53 enterprise-reference).

## D-2: OpenSSL 3.5.8 built from source (host had 3.0.2)

**Context:** spec §9 mandates native OpenSSL 3.5+ ML-DSA; the host OpenSSL was
3.0.2 (no ML-DSA).

**Decision:** build OpenSSL 3.5.8 (LTS line) from source; `env.sh` puts it first
on `PATH`/`LD_LIBRARY_PATH`. Verified the native `default` provider exposes
ML-DSA-44/65/87 and that ML-DSA-65 sign/verify works (`smoke/openssl_mldsa_smoke.sh`).

**Security impact:** preserves the primary-provider requirement. **liboqs is NOT
used** and remains an explicitly-disabled development-only fallback (spec §9).
This is algorithm conformance, not FIPS module validation (see `ENVIRONMENT.md`).

## D-3: Python venv created via `virtualenv` (ensurepip missing)

**Context:** `python3 -m venv` failed — `python3.10-venv` (ensurepip) is not
installed and needs apt/sudo.

**Decision:** `pip install --user virtualenv` (bundles pip/setuptools), then
`virtualenv .venv`. Functionally equivalent isolated environment.

**Security impact:** none.

## D-4: Container isolation deferred; `unshare` namespaces as validated fallback

**Context:** the spec's Enforcement Fabric / threshold-party separation targets
Docker/compose, but Docker is not reachable in this WSL distro yet (user will
enable WSL integration). Needed only from Phase 7 (Enforcement Fabric) and
Phase 15 (threshold FHE).

**Decision:** proceed through Phases 0–6 (which need no containers). For Phase 7+,
target Docker if available; otherwise use kernel-enforced isolation via
unprivileged `unshare` user/net/pid/mount namespaces — validated working on this
host (an agent runtime in a fresh net namespace has loopback only, forcing all
egress through the brokered proxy). Separate threshold authorities run as
separate OS processes.

**Security impact:** the *network-egress-must-be-brokered* and
*runtime-isolation* properties are still enforced at the kernel boundary via
namespaces; container packaging is an operational/ergonomic layer, documented as
an enterprise extension point. Final choice is re-confirmed at Phase 7.

## D-5: EZKL bindings are async; ONNX export uses legacy exporter

**Context:** several EZKL 23.0.5 functions (e.g. `get_srs`) are pyo3-asyncio
coroutines requiring a running event loop; torch 2.14's default ONNX exporter
requires `onnxscript` (not installed).

**Decision:** run EZKL pipelines under `asyncio` and `await` any awaitable
result; export ONNX with `dynamo=False` (legacy TorchScript exporter).

**Security impact:** none — same artifacts and proofs; documented so Phase 12
uses the same call convention.
