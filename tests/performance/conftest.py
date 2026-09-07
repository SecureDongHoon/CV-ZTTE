"""Session-scoped benchmark recorder + a printed summary table (§60.32).

The recorder is shared across the performance module so every benchmark lands in
one table, printed at session teardown (visible with ``pytest -s``). The numbers
are observed medians on the host running the suite — not fabricated throughput.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.performance.bench import BenchRecorder


@pytest.fixture(scope="session")
def recorder() -> Iterator[BenchRecorder]:
    rec = BenchRecorder()
    yield rec
    print("\n\n=== CV-ZTTE performance benchmarks (observed medians, §60.32) ===")
    print(rec.render())
    print("Note: observed on this host; NOT a certified/enterprise throughput claim (§52).\n")
