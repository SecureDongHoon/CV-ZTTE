# OpenFHE Integration

Spec references: §36, §37, §46.

## Library

- **OpenFHE 1.5.1**, built from source, installed user-local at
  `~/opt/openfhe` (no sudo). `env.sh` exports `CVZTTE_OPENFHE_HOME` and adds its
  `lib/` to `LD_LIBRARY_PATH`.
- Math backend 4, OpenMP on, native size 64, CKKS. Shared libraries
  `libOPENFHEcore/pke/binfhe.so.1.5.1`.

No toy crypto (§36): the broker uses OpenFHE's genuine CKKS scheme.

## Native broker (`services/fhe-broker/`)

A narrow single-purpose C++17 executable, `fhe_broker`, that performs the
mathematical FHE operations only. It makes **no** authorization decision.

Build:

```bash
source env.sh
cmake -S services/fhe-broker -B services/fhe-broker/build \
      -DOpenFHE_DIR=$CVZTTE_OPENFHE_HOME/lib/OpenFHE
cmake --build services/fhe-broker/build
```

(The single translation unit is compile-heavy — it pulls in OpenFHE's cereal
serialization headers at `-O3` — expect a multi-minute build.)

### Commands

| Command | Effect |
|---------|--------|
| `gen-context <dir> <depth> <scale_mod> <batch> [ring]` | Build a CKKS context (128-bit security level), KeyGen + EvalMult + EvalSum keys; serialize context/keys; print `ring_dimension` |
| `encrypt <dir> <out_ct> <v0,v1,...>` | CKKS-pack + encrypt a vector |
| `evaluate <dir> <program> <out_ct> <in_ct...> [--weights ...] [--count N]` | Run an allowlisted program |
| `decrypt <dir> <in_ct> <length>` | Decrypt (single-key; see FHE_SECURITY_MODEL) |

Programs (§39): `SUM_V1` (EvalSum), `AVERAGE_V1` (EvalSum × 1/N),
`WEIGHTED_SCORE_V1` (elementwise EvalMult by a plaintext weight vector, then
EvalSum).

### Protocol

- Crypto parameters come from the FHE Context Registry via argv — **an agent
  cannot supply them** (§37).
- Serialized artifacts (context, public/secret keys, eval keys, ciphertexts)
  live in a context directory. The Python client computes and pins content
  hashes over those bytes.
- Output is a single-line JSON object on stdout. Any error prints
  `{"error":"..."}` on stderr and exits non-zero — the Python client maps that
  to a fail-closed `CVZTTEError` (`FHE_COMPUTE_FAILED` / `FHE_COMPUTE_TIMEOUT`).
- The broker prints plaintext only on an explicit `decrypt` command (a separate
  high-risk action, §42) and **never** prints key material.

## Python client (`cvztte/cac/broker.py`)

`FHEBrokerClient` invokes the binary with a fixed path + list argv (never
`shell=True`, per §60.12). It locates the binary via `$CVZTTE_FHE_BROKER` or the
repo default `services/fhe-broker/build/fhe_broker`. If the binary is absent it
fails closed with `SECURITY_DEPENDENCY_UNAVAILABLE`.

## Resource controls (§46)

The reference honors depth limits (program depth ≤ context depth) and a broker
subprocess timeout. Batch/vector size, queue, per-agent/dataset quota, and rate
limits are enforced by the surrounding control plane / query governance (Phase
16) and are documented as extension points here.

## Verified end to end

The integration suite (`tests/integration/test_cac_e2e.py`) runs the real
binary: `SUM([10,20,30,40]) = 100`, `AVERAGE = 25`, `WEIGHTED·[.1,.2,.3,.4] = 30`,
plus ciphertext/context substitution rejection and allowed-program enforcement.
