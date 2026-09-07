"""EZKL artifact manifest + hash pinning (spec §30, §60.8).

The manifest binds the proving/verifying artifacts (settings, compiled circuit,
SRS, proving/verifying keys) to a specific Judge model and feature extractor.
Startup MUST recompute hashes and reject artifact drift (§60.8); a verifier that
loaded a different circuit or VK than the one approved would silently break the
"prove the approved mathematical Judge" guarantee (§30).

Metadata sitting next to a proof is *not* cryptographic binding (§30) — binding
comes from checking the proof's public input instances against independently
derived features (see :mod:`cvztte.ezkl.verifier`); this manifest only pins
*which* circuit/VK is authoritative.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.judge.features import FEATURE_NAMES, FEATURE_VERSION, N_FEATURES, feature_extractor_hash
from cvztte.judge.manifest import file_sha256


class EZKLManifest(BaseModel):
    """Pinned identity of an EZKL proving/verifying artifact set (§60.8)."""

    model_config = ConfigDict(extra="forbid")

    manifest_version: int = 1
    ezkl_version: str
    onnx_opset: int
    # Judge/model binding.
    model_hash: str  # sha256 of the ONNX the circuit was compiled from
    feature_extractor_version: int = FEATURE_VERSION
    feature_extractor_hash: str
    n_features: int = N_FEATURES
    feature_names: list[str]
    decision_encoding: list[str]
    # Quantization / circuit config.
    input_scale: int
    param_scale: int
    output_scale: int
    logrows: int
    input_visibility: str
    output_visibility: str
    param_visibility: str
    # Artifact filenames + pinned hashes.
    settings_file: str
    compiled_file: str
    srs_file: str
    pk_file: str
    vk_file: str
    settings_hash: str
    compiled_hash: str
    srs_hash: str
    pk_hash: str
    vk_hash: str

    def manifest_hash(self) -> str:
        return commit(Domain.CIRCUIT, self.model_dump(mode="json"))

    def write(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True))

    @staticmethod
    def load(path: str | Path) -> "EZKLManifest":
        try:
            return EZKLManifest.model_validate_json(Path(path).read_text())
        except FileNotFoundError as exc:
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, "ezkl manifest missing") from exc

    def _check_feature_identity(self) -> None:
        if self.feature_extractor_version != FEATURE_VERSION:
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, "feature extractor version drift")
        if self.feature_names != FEATURE_NAMES:
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, "feature name/order drift")
        if self.feature_extractor_hash != feature_extractor_hash():
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, "feature extractor hash drift")
        if self.n_features != N_FEATURES:
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, "feature count drift")

    def _check_file(self, artifact_dir: Path, name: str, pinned: str) -> None:
        path = artifact_dir / name
        if not path.exists():
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, f"artifact missing: {name}")
        if file_sha256(path) != pinned:
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, f"artifact hash drift: {name}")

    def verify_against_runtime(self, artifact_dir: str | Path, *, require_pk: bool) -> None:
        """Recompute hashes and reject drift (spec §60.8). Fail-closed.

        ``require_pk`` is True for provers (need the proving key) and False for
        verify-only deployments (settings + SRS + VK suffice).
        """
        artifact_dir = Path(artifact_dir)
        self._check_feature_identity()
        self._check_file(artifact_dir, self.settings_file, self.settings_hash)
        self._check_file(artifact_dir, self.compiled_file, self.compiled_hash)
        self._check_file(artifact_dir, self.srs_file, self.srs_hash)
        self._check_file(artifact_dir, self.vk_file, self.vk_hash)
        if require_pk:
            self._check_file(artifact_dir, self.pk_file, self.pk_hash)
