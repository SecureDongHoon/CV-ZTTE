# artifacts/gnark — pointer

This directory is part of the §49 recommended layout. The reference build does
**not** commit gnark proving/verifying keys here; they are **generated
deterministically** from the pinned circuit and consumed from a run-local
directory.

- **Circuit source & registry manifest:** `services/zk-authz/` (Go). The circuit
  is `services/zk-authz/circuit/authz.go` (Groth16/BN254, `CircuitVersion=3`); the
  approved-artifact manifest fields (`circuit_source_hash`,
  `constraint_system_hash`, `proving_key_hash`, `verification_key_hash`) are in
  `services/zk-authz/registry/registry.go`.
- **How keys are produced:** the `zk-authz` binary (`services/zk-authz/bin/`)
  runs setup and writes the proving/verifying keys into a working directory; the
  Python side pins and loads them via `ZKRegistry(artifact_dir)`
  (`cvztte/zkauthz/registry.py`), which recomputes the on-disk VK hash and rejects
  any drift with `GNARK_ARTIFACT_UNAPPROVED`.
- **Where the test suite gets them:** `tests/integration/test_zkauthz.py` builds
  them into a temp dir per session (`tmp_path_factory.mktemp("zk_artifacts")`) —
  real prover/verifier, no mocks.

To materialize keys into this directory for inspection, run the `zk-authz` setup
command pointing `--out` here (see `docs/GNARK_BINDING.md`). Nothing here is a
trust anchor by itself — only a VK whose hash matches the pinned manifest is
accepted.
