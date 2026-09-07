"""Judge artifact manifest + hash pinning (spec §30, §60.8).

The manifest binds the deployed model to its identity so startup can recompute
hashes and reject artifact drift (§60.8). Phase 11 records the model/feature/
opset fields; Phase 12 (EZKL) extends the same manifest with settings/circuit/
SRS/PK/VK hashes for the proving artifacts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.judge.features import FEATURE_NAMES, FEATURE_VERSION, N_FEATURES, feature_extractor_hash


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


class JudgeManifest(BaseModel):
    """Pinned identity of a Judge model artifact (§60.8)."""

    model_config = ConfigDict(extra="forbid")

    manifest_version: int = 1
    judge_version: int = 1
    onnx_file: str
    onnx_opset: int
    model_hash: str  # sha256 of the ONNX file
    feature_extractor_version: int = FEATURE_VERSION
    feature_extractor_hash: str
    n_features: int = N_FEATURES
    feature_names: list[str]
    decision_encoding: list[str]  # class index -> verdict
    #: Inference margin guard threshold (quantization-boundary protection, §60.8).
    margin: float = 0.15

    def manifest_hash(self) -> str:
        body = self.model_dump(mode="json")
        return commit(Domain.MODEL, body)

    def write(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True))

    @staticmethod
    def load(path: str | Path) -> "JudgeManifest":
        return JudgeManifest.model_validate_json(Path(path).read_text())

    def verify_against_runtime(self, artifact_dir: str | Path) -> None:
        """Recompute hashes and reject drift (spec §60.8 startup check). Fail-closed."""
        # 1. Feature extractor must match the code the gateway will run.
        if self.feature_extractor_version != FEATURE_VERSION:
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "feature extractor version drift")
        if self.feature_names != FEATURE_NAMES:
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "feature name/order drift")
        if self.feature_extractor_hash != feature_extractor_hash():
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "feature extractor hash drift")
        if self.n_features != N_FEATURES:
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "feature count drift")
        # 2. ONNX artifact must match the pinned hash.
        onnx_path = Path(artifact_dir) / self.onnx_file
        if not onnx_path.exists():
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "onnx artifact missing")
        if file_sha256(onnx_path) != self.model_hash:
            raise CVZTTEError(ErrorCode.JUDGE_FAILED, "onnx artifact hash drift")
