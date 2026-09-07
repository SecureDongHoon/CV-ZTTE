"""Safety Judge — deterministic-feature MLP verdict (spec §29, §60.8)."""

from __future__ import annotations

from cvztte.judge.features import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    N_FEATURES,
    JudgeInput,
    extract,
    feature_extractor_hash,
)
from cvztte.judge.judge import JudgeResult, SafetyJudge
from cvztte.judge.manifest import JudgeManifest
from cvztte.judge.model import VERDICT_BY_INDEX, JudgeVerdict

__all__ = [
    "JudgeInput",
    "extract",
    "feature_extractor_hash",
    "FEATURE_NAMES",
    "FEATURE_VERSION",
    "N_FEATURES",
    "SafetyJudge",
    "JudgeResult",
    "JudgeManifest",
    "JudgeVerdict",
    "VERDICT_BY_INDEX",
]
