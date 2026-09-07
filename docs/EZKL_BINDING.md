# EZKL ZKML — proving the approved Judge (Phase 12)

EZKL proves, in zero knowledge, that the **approved mathematical Safety Judge**
(Phase 11) was computed on proof-bound inputs (spec §30). It does *not* prove
semantic correctness, and it does not prove any OpenFHE computation (§30) — its
sole job is: "these public logits are the output of *this* pinned circuit on
*these* public features."

## Pipeline (`cvztte/ezkl/`)

```
ONNX -> settings -> calibration -> SRS -> circuit -> setup -> witness -> proof -> verify
```

- **`prover.build(...)`** (`cvztte/ezkl/build.py`, `python -m cvztte.ezkl.build`)
  runs the one-time trusted ceremony: `gen_settings` (public input, public
  output, fixed params), `calibrate_settings` over a representative feature set,
  `compile_circuit`, `gen_srs` (generated **locally** — no network; an
  unsafe-but-deterministic SRS adequate for a reference deployment), and `setup`.
  It writes the artifacts and the pinned `EZKLManifest`.
- **`EZKLProver`** loads the manifest, verifies artifact hashes (drift rejected),
  and `prove(features)` produces a proof plus the public input/output field
  elements.
- **`EZKLVerifier`** loads settings + SRS + VK (no proving key) and performs the
  full §30 binding.

## Proof binding (the security-critical part, §30)

Metadata next to a proof is **not** cryptographic binding (§30). `EZKLVerifier.verify`
enforces four checks, all fail-closed:

1. **Cryptographic validity** — `ezkl.verify` against the pinned VK/SRS/settings.
   Failure → `EZKL_PROOF_INVALID`.
2. **Public-input binding** — the gateway independently derives the feature
   vector from the exact action/policy/behavior/containment snapshot, converts it
   to field elements (`float_to_felt(f, input_scale)`), and requires equality
   with the proof's public input instances. A proof about any other features →
   `EZKL_PUBLIC_INPUT_MISMATCH`.
3. **SAFE predicate** — the public output field elements are decoded
   (`felt_to_float(x, output_scale)`) and the argmax verdict is read from the
   proven logits.
4. **Quantization guard** — the proven (quantized) verdict must equal the trusted
   float ONNX verdict; a quantization-boundary flip is rejected
   (`EZKL_QUANTIZATION_GUARD`), never silently accepted (§60.8).

The public instances are laid out as the 25 input feature felts followed by the
3 output logit felts (`instance_shapes = [[1, N], [1, 3]]`).

## Artifact manifest + drift rejection (`cvztte/ezkl/model.py`)

`EZKLManifest` pins: EZKL version, ONNX opset, ONNX model hash, feature-extractor
version/hash + names (binding to the Phase 11 Judge), decision encoding,
input/param/output scales, logrows, input/output/param visibility, and the
sha256 of every artifact (settings, compiled circuit, SRS, PK, VK).
`verify_against_runtime` recomputes these at load and rejects any drift
(`EZKL_ARTIFACT_UNAPPROVED`) — the startup integrity check of §60.8. Provers
require the PK; verify-only deployments do not.

## Reproducibility & what is committed

`setup`/`gen_srs` use randomness, so the proving key and SRS are **not**
byte-reproducible across rebuilds and are large (100+ MB). They are therefore
**not committed** (`.gitignore` excludes `cvztte/ezkl/artifacts/`); in a real
deployment they come from a trusted ceremony and are distributed with the
manifest that pins their hashes. Run `python -m cvztte.ezkl.build` to materialize
them locally. The Phase 12 tests build a fresh artifact set per session and prove
against it (`tests/integration/test_ezkl.py`, marked `slow`).

## Parity & limitations

PyTorch↔ONNX parity is covered in Phase 11; ONNX↔EZKL verdict parity is asserted
here (the quantized argmax matches the float argmax on the tested inputs). The
reference SRS is unsafe (locally generated); a production deployment MUST use a
proper trusted setup. Detection quality of the Judge itself is not overclaimed
(§29).
