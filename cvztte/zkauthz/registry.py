"""Pinned gnark artifact registry (spec §60.5).

Loads the ``manifest.json`` produced by ``zk-authz setup`` and pins the active
circuit's proving system, curve, schema version, and — critically — the
verification-key hash. The client verifies proofs ONLY against this pinned VK;
a client cannot supply or select its own VK (spec §14).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cvztte.errors import CVZTTEError, ErrorCode

EXPECTED_PROVING_SYSTEM = "groth16"
EXPECTED_CURVE = "BN254"
EXPECTED_SCHEMA_VERSION = 3

_VK_FILE = "vk.bin"
_MANIFEST_FILE = "manifest.json"


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ZKRegistry:
    """A pinned, validated view of one artifact directory."""

    def __init__(self, artifact_dir: str | Path) -> None:
        self._dir = Path(artifact_dir)
        manifest_path = self._dir / _MANIFEST_FILE
        if not manifest_path.is_file():
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED,
                "manifest missing",
                detail={"dir": str(self._dir)},
            )
        try:
            self._manifest = json.loads(manifest_path.read_text("utf-8"))
        except (OSError, ValueError) as exc:
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED, "manifest unreadable"
            ) from exc

        self._validate()

    def _validate(self) -> None:
        m = self._manifest
        if m.get("proving_system") != EXPECTED_PROVING_SYSTEM:
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED,
                "unexpected proving system",
                detail={"proving_system": m.get("proving_system")},
            )
        if m.get("curve") != EXPECTED_CURVE:
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED,
                "unexpected curve",
                detail={"curve": m.get("curve")},
            )
        if m.get("schema_version") != EXPECTED_SCHEMA_VERSION:
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED,
                "unexpected schema version",
                detail={"schema_version": m.get("schema_version")},
            )
        # Pin integrity: the on-disk VK must hash to the manifest-recorded value.
        vk_path = self._dir / _VK_FILE
        if not vk_path.is_file():
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED, "verification key missing"
            )
        actual = _sha256_hex(vk_path.read_bytes())
        if actual != m.get("verification_key_hash"):
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED,
                "verification key hash mismatch",
                detail={"expected": m.get("verification_key_hash"), "actual": actual},
            )

    @property
    def artifact_dir(self) -> str:
        return str(self._dir)

    @property
    def circuit_version(self) -> int:
        return int(self._manifest["circuit_version"])

    @property
    def verification_key_hash(self) -> str:
        return str(self._manifest["verification_key_hash"])

    @property
    def circuit_source_hash(self) -> str:
        return str(self._manifest["circuit_source_hash"])

    @property
    def manifest(self) -> dict:
        return dict(self._manifest)
