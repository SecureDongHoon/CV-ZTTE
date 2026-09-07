"""Differential-privacy extension point (spec §45).

§45 requires a DP **extension point** but forbids calling anything DP unless a
real noise mechanism *with privacy accounting* is implemented. This module
provides the seam and a truthful default that adds **no** noise and does **no**
accounting — so nothing here may be described as differential privacy.

To add genuine DP later, implement :class:`NoiseMechanism` with a real mechanism
(e.g. calibrated Laplace/Gaussian) **and** an epsilon/delta accountant, then set
``accounts_privacy = True``. Until then :class:`NoDP` is used and the governor
reports ``is_differential_privacy() == False``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class NoiseMechanism(Protocol):
    """A pluggable output-perturbation mechanism."""

    name: str
    #: MUST be True only for a mechanism that performs real DP noise + accounting.
    accounts_privacy: bool

    def perturb(self, value: float, *, sensitivity: float) -> float: ...


class NoDP:
    """Default: identity. Adds no noise and performs no privacy accounting.

    This is explicitly **not** differential privacy; it exists so the governance
    pipeline has a mechanism slot without overclaiming (§45).
    """

    name = "none"
    accounts_privacy = False

    def perturb(self, value: float, *, sensitivity: float) -> float:  # noqa: ARG002
        return value
