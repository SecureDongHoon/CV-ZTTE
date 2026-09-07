"""EZKL circuit build + proof generation (spec §30, §60.8).

Pipeline (§30):

    ONNX -> settings -> calibration -> SRS -> circuit -> setup -> witness -> proof

:meth:`EZKLProver.build` runs the one-time trusted ceremony (settings/calibrate/
compile/SRS/setup) and writes the pinned :class:`EZKLManifest`. A running prover
loads that manifest, verifies artifact hashes (drift rejected fail-closed), and
:meth:`prove` turns a deterministic Judge feature vector into a proof plus its
public input/output field elements.

SRS is generated locally (``gen_srs``) rather than fetched, so the reference
build needs no network — an unsafe-but-deterministic SRS, adequate for a
reference deployment (documented in EZKL_BINDING.md).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.ezkl.model import EZKLManifest
from cvztte.judge.features import FEATURE_NAMES, N_FEATURES, feature_extractor_hash
from cvztte.judge.manifest import file_sha256
from cvztte.judge.model import VERDICT_BY_INDEX

SETTINGS_FILE = "settings.json"
COMPILED_FILE = "model.compiled"
SRS_FILE = "kzg.srs"
PK_FILE = "pk.key"
VK_FILE = "vk.key"
MANIFEST_FILE = "ezkl_manifest.json"


class EZKLProof(BaseModel):
    """A generated proof plus the public field elements it commits to."""

    model_config = ConfigDict(extra="forbid")

    proof_json: str  # the raw ezkl proof document (JSON string)
    public_instances: list[str]  # flat public instances (inputs ++ outputs)
    input_felts: list[str]  # first N_FEATURES public inputs
    output_felts: list[str]  # remaining public outputs (logits)


def _ezkl():
    try:
        import ezkl  # noqa: PLC0415

        return ezkl
    except Exception as exc:  # pragma: no cover - import guard
        raise CVZTTEError(ErrorCode.EZKL_PROOF_INVALID, "ezkl unavailable") from exc


class EZKLProver:
    """Loads a pinned EZKL artifact set and generates proofs."""

    def __init__(self, manifest_path: str | Path) -> None:
        manifest_path = Path(manifest_path)
        self._dir = manifest_path.parent
        self._manifest = EZKLManifest.load(manifest_path)
        self._manifest.verify_against_runtime(self._dir, require_pk=True)
        self._ezkl = _ezkl()

    @property
    def manifest(self) -> EZKLManifest:
        return self._manifest

    def prove(self, features: list[float]) -> EZKLProof:
        """Generate a proof for a Judge feature vector."""
        if len(features) != N_FEATURES:
            raise CVZTTEError(ErrorCode.EZKL_PUBLIC_INPUT_MISMATCH, "wrong feature length")
        ez = self._ezkl
        d = self._dir
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            in_path = tmp / "input.json"
            wit_path = tmp / "witness.json"
            proof_path = tmp / "proof.json"
            in_path.write_text(json.dumps({"input_data": [list(features)]}))
            try:
                ez.gen_witness(str(in_path), str(d / self._manifest.compiled_file),
                               str(wit_path), str(d / self._manifest.vk_file),
                               str(d / self._manifest.srs_file))
                ez.prove(str(wit_path), str(d / self._manifest.compiled_file),
                         str(d / self._manifest.pk_file), str(proof_path),
                         str(d / self._manifest.srs_file))
            except CVZTTEError:
                raise
            except Exception as exc:
                raise CVZTTEError(ErrorCode.EZKL_PROOF_INVALID, "proof generation failed") from exc
            proof = json.loads(proof_path.read_text())
        instances = list(proof["instances"][0])
        n = N_FEATURES
        return EZKLProof(
            proof_json=json.dumps(proof),
            public_instances=instances,
            input_felts=instances[:n],
            output_felts=instances[n:],
        )


def build(
    *,
    onnx_path: str | Path,
    calibration_features: list[list[float]],
    out_dir: str | Path,
    onnx_opset: int = 17,
    input_scale: int = 13,
    param_scale: int = 13,
) -> EZKLManifest:
    """One-time trusted ceremony: compile the circuit, run setup, pin the manifest.

    ``calibration_features`` is a small representative set spanning the feature
    space (used by ``calibrate_settings`` to pick lookup ranges / scales).
    """
    ez = _ezkl()
    onnx_path = Path(onnx_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    settings = out_dir / SETTINGS_FILE
    compiled = out_dir / COMPILED_FILE
    srs = out_dir / SRS_FILE
    pk = out_dir / PK_FILE
    vk = out_dir / VK_FILE

    run = ez.PyRunArgs()
    run.input_visibility = "public"   # public: bound to gateway-derived features
    run.output_visibility = "public"  # public: SAFE predicate checked by verifier
    run.param_visibility = "fixed"    # weights are fixed and pinned by hash
    run.input_scale = input_scale
    run.param_scale = param_scale

    with tempfile.TemporaryDirectory() as tmp:
        calib = Path(tmp) / "calibration.json"
        calib.write_text(json.dumps({"input_data": [list(f) for f in calibration_features]}))
        try:
            ez.gen_settings(str(onnx_path), str(settings), py_run_args=run)
            ez.calibrate_settings(str(calib), str(onnx_path), str(settings), "resources")
            ez.compile_circuit(str(onnx_path), str(compiled), str(settings))
            resolved = json.loads(settings.read_text())["run_args"]
            logrows = int(resolved["logrows"])
            ez.gen_srs(str(srs), logrows)
            ez.setup(str(compiled), str(vk), str(pk), str(srs))
        except Exception as exc:
            raise CVZTTEError(ErrorCode.EZKL_ARTIFACT_UNAPPROVED, "ezkl build failed") from exc

    settings_doc = json.loads(settings.read_text())
    resolved = settings_doc["run_args"]
    output_scales = settings_doc.get("model_output_scales") or [int(resolved["input_scale"])]
    manifest = EZKLManifest(
        ezkl_version=str(getattr(ez, "__version__", "unknown")),
        onnx_opset=onnx_opset,
        model_hash=file_sha256(onnx_path),
        feature_extractor_hash=feature_extractor_hash(),
        feature_names=FEATURE_NAMES,
        decision_encoding=[v.value for v in VERDICT_BY_INDEX],
        input_scale=int(resolved["input_scale"]),
        param_scale=int(resolved["param_scale"]),
        output_scale=int(output_scales[0]),
        logrows=int(resolved["logrows"]),
        input_visibility=str(resolved["input_visibility"]),
        output_visibility=str(resolved["output_visibility"]),
        param_visibility=str(resolved["param_visibility"]),
        settings_file=SETTINGS_FILE,
        compiled_file=COMPILED_FILE,
        srs_file=SRS_FILE,
        pk_file=PK_FILE,
        vk_file=VK_FILE,
        settings_hash=file_sha256(settings),
        compiled_hash=file_sha256(compiled),
        srs_hash=file_sha256(srs),
        pk_hash=file_sha256(pk),
        vk_hash=file_sha256(vk),
    )
    manifest.write(out_dir / MANIFEST_FILE)
    return manifest
