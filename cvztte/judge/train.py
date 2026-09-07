"""Train the Safety-Judge MLP and export the pinned ONNX artifact (spec §29, §60.8).

Run as a module to (re)generate the committed artifacts::

    python -m cvztte.judge.train

Training is deterministic (seeded) so the ONNX artifact and its manifest hashes
are reproducible. The reference model is small and trained on the synthetic +
adversarial dataset; we deliberately do not overclaim its detection quality
(§29) — its role is to demonstrate a real, ZKML-provable mathematical Judge, not
to be a production classifier.
"""

from __future__ import annotations

from pathlib import Path

from cvztte.judge.features import (
    FEATURE_NAMES,
    N_FEATURES,
    extract,
    feature_extractor_hash,
)
from cvztte.judge.manifest import JudgeManifest, file_sha256
from cvztte.judge.model import VERDICT_BY_INDEX, build_mlp
from cvztte.judge.synthetic import generate_dataset

ONNX_OPSET = 17
ARTIFACT_DIR = Path(__file__).parent / "artifacts"
ONNX_FILE = "judge_mlp.onnx"
WEIGHTS_FILE = "judge_mlp.pt"
MANIFEST_FILE = "judge_manifest.json"


def train_model(n: int = 8000, epochs: int = 60, seed: int = 1337):
    """Train the MLP deterministically; return (model, accuracy)."""
    import torch

    torch.manual_seed(seed)
    inputs, labels = generate_dataset(n=n, seed=seed)
    X = torch.tensor([extract(i) for i in inputs], dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.long)

    # Class weights counter the (mild) imbalance so REVIEW/UNSAFE aren't ignored.
    counts = torch.bincount(y, minlength=3).float()
    weights = counts.sum() / (3.0 * counts.clamp(min=1.0))

    model = build_mlp()
    opt = torch.optim.Adam(model.parameters(), lr=1e-2)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)

    model.train()
    for _ in range(epochs):
        opt.zero_grad()
        loss = loss_fn(model(X), y)
        loss.backward()
        opt.step()

    model.eval()
    with torch.no_grad():
        pred = model(X).argmax(dim=1)
        acc = float((pred == y).float().mean())
    return model, acc


def export(model, artifact_dir: Path = ARTIFACT_DIR) -> JudgeManifest:
    """Export ONNX + weights and write the pinned manifest."""
    import torch

    artifact_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = artifact_dir / ONNX_FILE
    dummy = torch.zeros(1, N_FEATURES, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        str(onnx_path),
        input_names=["features"],
        output_names=["logits"],
        opset_version=ONNX_OPSET,
        dynamic_axes=None,
        dynamo=False,  # legacy TorchScript exporter (no onnxscript dependency)
    )
    torch.save(model.state_dict(), artifact_dir / WEIGHTS_FILE)

    manifest = JudgeManifest(
        onnx_file=ONNX_FILE,
        onnx_opset=ONNX_OPSET,
        model_hash=file_sha256(onnx_path),
        feature_extractor_hash=feature_extractor_hash(),
        feature_names=FEATURE_NAMES,
        decision_encoding=[v.value for v in VERDICT_BY_INDEX],
    )
    manifest.write(artifact_dir / MANIFEST_FILE)
    return manifest


def main() -> None:
    model, acc = train_model()
    manifest = export(model)
    print(f"trained Judge MLP: train_acc={acc:.4f}")
    print(f"model_hash={manifest.model_hash}")
    print(f"manifest_hash={manifest.manifest_hash()}")


if __name__ == "__main__":
    main()
