# Performance & Hardening (Phase 19)

Spec references: §52 (performance realism), §60.32 (benchmark inventory).

This document reports **observed medians on the reference build's development
host** and describes the fail-closed resource bounds (bounded queues /
backpressure) required by §52. Per §52 we **do not fabricate enterprise
throughput**: every number here is a measured median from
`tests/performance/`, on one shared WSL2 laptop, and is a regression signal —
not a certified or enterprise figure.

## How to run

```bash
source env.sh
python -m pytest tests/performance/ -s          # always-on CPU/enforcement/token/judge
python -m pytest tests/performance/ -s -m slow  # + native OpenFHE and gnark
```

The suite records real medians via `time.perf_counter` (`tests/performance/bench.py`)
and prints a summary table at teardown. Assertions use deliberately generous
upper bounds: they catch a gross regression, they are **not** spec throughput.

## Observed medians (reference host, illustrative)

Measured on a WSL2 Ubuntu laptop (no dedicated hardware, no HSM/TEE). Your
numbers will differ; treat these as order-of-magnitude only.

| Benchmark (§60.32 item) | Median | Notes |
|---|---:|---|
| parse / canonicalize + domain hash | ~0.01 ms | JCS canonicalization + SHA-256 |
| ML-DSA sign (native OpenSSL 3.5.8) | ~6 ms | ML-DSA-65 |
| ML-DSA verify | ~4.5 ms | ML-DSA-65 |
| Safety Judge inference | ~0.06 ms | ONNX MLP, deterministic features |
| Decision Token issuance | ~0.09 ms | MAC mint, gateway-only key |
| containment update + capability-epoch bump | ~0.04 ms | escalate + atomic epoch propagation |
| behavior snapshot | ~0.01 ms | rolling 10s/60s/5m windows |
| egress proxy (deny) | ~0.10 ms | domain allowlist |
| output proxy (allow) | ~0.07 ms | DLP scan |
| MCP gateway (deny) | ~0.05 ms | bypass refusal |
| backpressure admit | ~0.003 ms | bounded semaphore |
| **full ALLOW path L2** (sign→pipeline→mint→mediate→execute→receipt) | ~13 ms | dominated by ML-DSA sign |
| quarantine propagation + blocked evaluate (stale-token rejection) | ~12 ms | epoch bump invalidates in-flight tokens |
| OpenFHE context + key setup | ~210 ms | real CKKS KeyGen + EvalSum key |
| OpenFHE encrypt | ~65 ms | CKKS, batch 8, depth 2 |
| OpenFHE SUM | ~510 ms | homomorphic EvalSum |
| OpenFHE AVERAGE | ~330 ms | EvalSum + scalar mult |
| OpenFHE decrypt (single-key) | ~77 ms | |
| ciphertext size | ~1.05 MB | one CKKS ciphertext, ring dim library-chosen |
| gnark prove (Groth16/BN254) | ~285 ms | credential-binding circuit |
| gnark verify | ~12 ms | |

Redis, EZKL prove/verify, and threshold partial/combine are exercised for
correctness in their own guarded integration suites
(`tests/integration/test_replay.py`, `test_ezkl.py`, `test_threshold_e2e.py`);
the threshold decrypt inherits the OpenFHE per-party costs above times the party
count.

### Risk-tier latency

Total latency is dominated by the heaviest enabled stage. For plaintext actions
(L1/L2) the ML-DSA signature (~6 ms) dominates, so an end-to-end ALLOW is
~10–15 ms. Adding a gnark authorization proof (L3) adds the prove cost (~285 ms).
CAC/FHE actions (L4) add the OpenFHE evaluate cost (hundreds of ms to seconds)
and, for release, threshold decryption across every party.

## Coding-agent benchmark: sandbox-local avoids central per-file overhead (§52)

`tests/performance/test_benchmarks.py::test_sandbox_local_avoids_central_per_file_overhead`
demonstrates the architectural claim with the **real** Decision Token authority
as the per-file central cost. Processing N=50 files:

* **central per-file** — one boundary crossing (token mint) per file: ~4.7 ms
  total, scaling ~linearly with N;
* **sandbox-local** — N cheap in-sandbox content hashes, then a **single**
  aggregate boundary crossing: ~0.17 ms total.

The test asserts sandbox-local < central. The lesson: mediate at the sandbox
boundary and cross the control plane once per task, not once per file — central
per-file proof/mediation overhead does not scale to a coding agent touching
hundreds of files.

## Bounded queues / backpressure (§52, §60.32)

The prover (gnark/EZKL) and the FHE broker are the expensive, memory-heavy
stages. `cvztte/config/backpressure.py` provides `BoundedAdmission`, a
fail-closed concurrency bound:

* at most `capacity` jobs run concurrently;
* an over-capacity admission is **shed immediately** with
  `SECURITY_DEPENDENCY_UNAVAILABLE` rather than buffered on an unbounded queue;
* callers already map that error to **DENY** — never an implicit ALLOW (§4.20).

Shedding load safely is preferred to unbounded buffering (a DoS/memory-exhaustion
risk). There is deliberately no "resource-exhausted → allow later" path. The
per-profile bounds (`max_inflight_proofs`, `max_inflight_fhe`) live in
`ResourceLimits` on each deployment profile — see `docs/DEPLOYMENT.md`.

## Ciphertext resource bound (memory-exhaustion guard, §60.31 #146)

`ResourceLimits.max_ciphertext_bytes` caps ciphertext size at the FHE broker.
An oversized ciphertext — presented as input or produced as output — is refused
with `FHE_CIPHERTEXT_TOO_LARGE` before it is processed (and an offending output
file is removed). This is a runtime DoS guard, not a cryptographic binding, so
it lives on the deployment profile rather than in the `context_hash`. Verified
end-to-end against the real OpenFHE broker in
`tests/integration/test_cac_e2e.py::test_case146_oversized_ciphertext_rejected`.
