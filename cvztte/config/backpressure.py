"""Bounded admission / backpressure for saturating subsystems (spec §52, §60.32).

The prover (gnark/EZKL) and the FHE broker are the expensive, memory-heavy
stages. Under load an unbounded work queue is itself a denial-of-service and a
memory-exhaustion risk. §52/§60.32 require *bounded queues with backpressure*.

:class:`BoundedAdmission` caps the number of concurrent in-flight jobs for one
subsystem. It is **fail-closed** (§4.20): when saturated it does not queue
unboundedly and never silently proceeds — admission raises
``SECURITY_DEPENDENCY_UNAVAILABLE``, which every caller already maps to DENY
(never an implicit ALLOW). There is deliberately no dedicated "resource
exhausted → allow later" path: shedding load safely is preferred to unbounded
buffering.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from cvztte.errors import CVZTTEError, ErrorCode


class BoundedAdmission:
    """A fail-closed concurrency bound for one saturating subsystem.

    ``capacity`` in-flight jobs are permitted at once. A further admission while
    full is *shed* (fail-closed) rather than buffered without limit.
    """

    def __init__(self, *, name: str, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._name = name
        self._capacity = capacity
        self._sem = threading.BoundedSemaphore(capacity)
        self._lock = threading.Lock()
        self._inflight = 0
        self._admitted = 0
        self._shed = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def inflight(self) -> int:
        with self._lock:
            return self._inflight

    @property
    def shed_count(self) -> int:
        with self._lock:
            return self._shed

    @property
    def admitted_count(self) -> int:
        with self._lock:
            return self._admitted

    @contextmanager
    def admit(self) -> Iterator[None]:
        """Admit one job or fail closed if the subsystem is at capacity.

        Non-blocking: an over-capacity request is shed immediately with
        ``SECURITY_DEPENDENCY_UNAVAILABLE`` rather than waiting on an unbounded
        queue. Use as ``with admission.admit(): ...``.
        """
        if not self._sem.acquire(blocking=False):
            with self._lock:
                self._shed += 1
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "subsystem at capacity — request shed (backpressure)",
                detail={"subsystem": self._name, "capacity": self._capacity},
            )
        with self._lock:
            self._inflight += 1
            self._admitted += 1
        try:
            yield
        finally:
            with self._lock:
                self._inflight -= 1
            self._sem.release()
