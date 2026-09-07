# CV-ZTTE v3 — Environment Inventory (Phase 0)

Captured on **2026-09-07**. Required by spec §0 (steps 2–5) and §60.1. All
tooling is installed **user-local without sudo** (see `docs/IMPLEMENTATION_NOTES.md`
for the rationale and deviations). Re-establish the environment with
`source env.sh` from the repo root.

## Host

| Item | Value |
|---|---|
| OS / distribution | Ubuntu 22.04.4 LTS (Jammy) |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| Architecture | x86_64 |
| CPUs | 8 |
| RAM | 3.7 GiB (constrains parallel builds & FHE/ZK proving — see notes) |
| Disk free | ~910 GiB |
| Container runtime | **Docker/Podman NOT available** in this WSL distro (pending WSL integration) |
| Unprivileged namespaces | user / net / pid / mount all usable via `unshare` (kernel-level isolation fallback) |
| sudo | not available non-interactively |

## Toolchain (pinned)

| Tool | Version | Source | Path |
|---|---|---|---|
| Python | 3.10.12 | system | `/usr/bin/python3` (project venv via `virtualenv`) |
| Go | **1.27.1** | go.dev tarball | `$HOME/opt/go` |
| OpenSSL | **3.5.8** (25 Aug 2026) | built from source | `$HOME/opt/openssl-3.5.8` |
| — dev headers | present (`include/openssl/evp.h`) | | |
| — loaded providers | `default` (active) | | |
| — provider exposes ML-DSA? | **YES** — ML-DSA-44/65/87 in the native `default` provider | | |
| Redis | **8.10.1** | built from source | `$HOME/.local/bin/redis-server` |
| OPA | **v1.20.2** (Rego v1) | static binary | `$HOME/.local/bin/opa` |
| gcc / g++ | 13.1.0 | system | |
| clang | 14.0.0 | system | |
| CMake | 3.22.1 | system | |
| OpenFHE | **v1.5.1** | built from source | `$HOME/opt/openfhe` |

## Python packages (pinned; full lock in `requirements.lock.txt`)

| Package | Version |
|---|---|
| torch | 2.14.0+cpu |
| onnx | 1.22.0 |
| onnxruntime | 1.23.2 |
| ezkl | 23.0.5 |
| numpy | 2.2.6 |
| fastapi | 0.141.1 |
| uvicorn | 0.52.4 |
| pydantic | 2.13.5 |
| httpx | 0.28.1 |
| redis (client) | 8.1.0 |
| rfc8785 (JCS) | 0.1.4 |
| pytest | 9.1.1 |

## Go modules (pinned)

| Module | Version |
|---|---|
| github.com/consensys/gnark | **v0.16.3** |
| github.com/consensys/gnark-crypto | **v0.21.0** |

## NIST standardization vs FIPS validation (spec §0.8, §60.1)

ML-DSA is the algorithm **standardized by NIST as FIPS 204**. The OpenSSL 3.5.8
`default` provider used here implements ML-DSA but is **NOT a FIPS-validated
cryptographic module**. CV-ZTTE therefore claims *ML-DSA algorithm conformance*,
**not** FIPS 140-3 module validation. A FIPS-validated provider / HSM / KMS is an
enterprise extension point (spec §9, §60.2), not part of this reference build.

## Phase 0 feasibility smoke results

Run all with `bash smoke/run_all.sh`. Results on 2026-09-07: **6/6 PASS**.

| Foundation | Smoke | Result | Notes |
|---|---|---|---|
| OpenSSL ML-DSA | `smoke/openssl_mldsa_smoke.sh` | ✅ | ML-DSA-65 sign/verify; tampered msg rejected; 3309-byte sig |
| Redis atomic | `smoke/redis_atomic_smoke.py` | ✅ | fresh/replay/rollback + concurrent → exactly one OK (atomic Lua) |
| OPA | `smoke/opa_smoke.rego` | ✅ | allow→risk 1, deny→risk 4 decision object |
| gnark | `smoke/gnark/` | ✅ | Groth16/BN254; wrong public input rejected |
| EZKL | `smoke/ezkl_smoke.py` | ✅ | full pipeline; tampered proof rejected |
| OpenFHE | `smoke/openfhe/` | ✅ | CKKS enc/add/mult/dec + genuine 2-party threshold fusion decrypt; ring dim 16384 |
| container/network | — | ⏳ deferred | Docker pending; `unshare` netns fallback validated (Phase 7) |
