"""Safety-Judge MLP + verdict types (spec §29, §60.8).

Compact, auditable, ZKML-friendly architecture (§60.8):

    N features -> Dense(32) -> ReLU -> Dense(16) -> ReLU -> Dense(3)

The three logits map to ``UNSAFE`` / ``REVIEW`` / ``SAFE``. The model is
intentionally small so it can be exported to ONNX and proven in EZKL (Phase 12)
and so its behavior stays inspectable — the spec explicitly says not to overclaim
detection quality (§29).
"""

from __future__ import annotations

import enum

from cvztte.judge.features import N_FEATURES

HIDDEN_1 = 32
HIDDEN_2 = 16
N_CLASSES = 3


class JudgeVerdict(str, enum.Enum):
    """Ordered most-restrictive first (index = class logit position)."""

    UNSAFE = "UNSAFE"
    REVIEW = "REVIEW"
    SAFE = "SAFE"


#: Class index <-> verdict. Index 0 is the most restrictive (fail-closed order).
VERDICT_BY_INDEX: list[JudgeVerdict] = [
    JudgeVerdict.UNSAFE,
    JudgeVerdict.REVIEW,
    JudgeVerdict.SAFE,
]


def build_mlp():
    """Construct the untrained PyTorch MLP (import torch lazily)."""
    import torch.nn as nn  # local import: torch is only needed for train/export

    return nn.Sequential(
        nn.Linear(N_FEATURES, HIDDEN_1),
        nn.ReLU(),
        nn.Linear(HIDDEN_1, HIDDEN_2),
        nn.ReLU(),
        nn.Linear(HIDDEN_2, N_CLASSES),
    )
