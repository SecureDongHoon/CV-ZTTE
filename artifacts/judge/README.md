# artifacts/judge — pointer

This directory is part of the §49 recommended layout. The committed Safety-Judge
artifacts actually live **next to the code that pins them**, so the loader and the
manifest cannot drift apart:

- **ONNX model + manifest:** `cvztte/judge/artifacts/judge_mlp.onnx`,
  `cvztte/judge/artifacts/judge_manifest.json`.
- **Loader / pin check:** `cvztte/judge/judge.py` (`_ARTIFACT_DIR`) verifies the
  manifest at construction and rejects drift (fail-closed); features are pinned by
  `feature_extractor_hash()` (`cvztte/judge/features.py`).
- **Regenerate:** `python -m cvztte.judge.train` re-exports the model + manifest
  (see `docs/SAFETY_JUDGE.md`).

The EZKL proving/verifying artifacts for this model are under
`cvztte/ezkl/artifacts/` (manifest + settings), regenerated with
`python -m cvztte.ezkl.build` (see `docs/EZKL_BINDING.md`).
