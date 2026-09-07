"""Fixtures for the adversarial suite. The reusable harness lives in ``lab.py``
so test modules can import :class:`AdversarialLab` directly (pytest prepend mode
puts this directory on ``sys.path``)."""

from __future__ import annotations

import pytest

from lab import AdversarialLab, make_allow_decision
from cvztte.policy.model import PolicyDecision


@pytest.fixture()
def allow_decision() -> PolicyDecision:
    return make_allow_decision()


@pytest.fixture()
def lab(registry, tmp_path, allow_decision) -> AdversarialLab:
    return AdversarialLab(registry, tmp_path, decision=allow_decision)
