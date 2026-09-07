"""Tiny, honest micro-benchmark helper for the §52 / §60.32 suite.

We measure real medians with :func:`time.perf_counter` and *record* them. We do
NOT fabricate enterprise throughput (§52): assertions use deliberately generous
upper bounds that catch gross regressions but tolerate a shared laptop/CI host,
and the measured median is printed so the reported number is the observed one,
never an aspirational spec figure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Callable


@dataclass
class BenchResult:
    name: str
    median_ms: float
    iters: int
    ops_per_s: float


@dataclass
class BenchRecorder:
    results: list[BenchResult] = field(default_factory=list)

    def measure(
        self,
        name: str,
        fn: Callable[[], object],
        *,
        iters: int = 30,
        warmup: int = 3,
        max_ms: float | None = None,
    ) -> BenchResult:
        for _ in range(max(0, warmup)):
            fn()
        samples: list[float] = []
        for _ in range(iters):
            t0 = perf_counter()
            fn()
            samples.append((perf_counter() - t0) * 1000.0)
        samples.sort()
        median = samples[len(samples) // 2]
        ops = (1000.0 / median) if median > 0 else float("inf")
        res = BenchResult(name=name, median_ms=median, iters=iters, ops_per_s=ops)
        self.results.append(res)
        if max_ms is not None:
            assert median <= max_ms, (
                f"{name}: median {median:.3f} ms exceeded generous bound {max_ms} ms "
                f"(regression, not a spec throughput claim)"
            )
        return res

    def render(self) -> str:
        if not self.results:
            return "(no benchmarks recorded)"
        width = max(len(r.name) for r in self.results)
        lines = [
            f"{'benchmark'.ljust(width)}   median(ms)     ops/s   iters",
            f"{'-' * width}   ----------   -------   -----",
        ]
        for r in self.results:
            lines.append(
                f"{r.name.ljust(width)}   {r.median_ms:10.3f}   {r.ops_per_s:7.1f}   {r.iters:5d}"
            )
        return "\n".join(lines)
