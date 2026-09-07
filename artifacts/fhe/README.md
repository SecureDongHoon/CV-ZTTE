# artifacts/fhe — pointer

This directory is part of the §49 recommended layout. FHE material is **not**
committed here; it is created at runtime and is either public evaluation material
or a per-party secret share that must never be centralized.

- **Native broker & key ceremony:** `services/fhe-broker/` (C++, OpenFHE 1.5.1).
  Contexts, the joint public key, and joint eval-sum keys are written into a
  run-local context directory; each threshold party's secret **share** stays in
  that party's own `share_dir` and is never collected
  (`services/fhe-key-authority-{a,b,c}/`).
- **Registry (agent cannot supply parameters):** contexts/programs are pinned by
  domain-separated hashes in `cvztte/cac/context.py` and `cvztte/cac/program.py`;
  an agent references a `context_id` only.
- **Where the test suite gets them:** `tests/integration/test_cac_e2e.py` and
  `tests/integration/test_threshold_e2e.py` provision a real context/keys into a
  temp workspace and run genuine encrypt / evaluate / (threshold) decrypt.

No full secret key is persisted on the threshold path. See
`docs/OPENFHE_INTEGRATION.md`, `docs/THRESHOLD_FHE.md`, and
`docs/FHE_SECURITY_MODEL.md`.
