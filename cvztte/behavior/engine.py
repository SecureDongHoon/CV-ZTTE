"""Stateful Behavior Engine (spec §24, §60.6).

Maintains per-scope rolling behavior state with race-safe transitions. Each
scope has its own lock; recording an event and computing a snapshot are atomic,
and :meth:`BehaviorEngine.transition` exposes the scope lock so a caller can run
the ``snapshot -> evaluate -> reserve/execute -> append`` sequence (§60.6)
without another writer interleaving.

Windowed features (``actions_last_*``, ``sensitive_reads_last_5m``) count
``EXECUTED`` events only, so a proposal and its execution are not double-counted
(§60.6). Cumulative features track denials, bypass attempts, secret accesses,
bytes, unique resources, destinations, destructive actions, and message fanout.
"""

from __future__ import annotations

import threading
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

from cvztte.behavior.model import (
    WINDOW_5M,
    WINDOW_10S,
    WINDOW_60S,
    BehaviorEvent,
    BehaviorEventKind,
    BehaviorScope,
    BehaviorSnapshot,
)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class _ScopeState:
    """Per-scope mutable state, guarded by its own lock."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        # Recent EXECUTED events (pruned to the largest window) for windowed counts.
        self.executed: deque[datetime] = deque()
        self.sensitive_reads: deque[datetime] = deque()
        # Cumulative counters.
        self.bytes_read = 0
        self.bytes_written = 0
        self.external_bytes = 0
        self.unique_resources: set[str] = set()
        self.secret_access_count = 0
        self.policy_denials = 0
        self.privilege_escalation_attempts = 0
        self.destructive_action_count = 0
        self.bypass_attempts = 0
        self.destinations_seen: set[str] = set()
        self.new_external_destination = 0
        self.message_recipients: set[str] = set()

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=WINDOW_5M)
        for dq in (self.executed, self.sensitive_reads):
            while dq and dq[0] < cutoff:
                dq.popleft()


class BehaviorEngine:
    """Per-scope behavior state with atomic, race-safe transitions."""

    def __init__(self) -> None:
        self._global = threading.Lock()
        self._scopes: dict[tuple, _ScopeState] = {}

    def _state(self, scope: BehaviorScope) -> _ScopeState:
        key = (scope.agent_id, scope.session_id, scope.runtime_id, scope.delegation_id)
        with self._global:
            st = self._scopes.get(key)
            if st is None:
                st = _ScopeState()
                self._scopes[key] = st
            return st

    @contextmanager
    def transition(self, scope: BehaviorScope) -> Iterator[_ScopeState]:
        """Hold the scope lock across a snapshot/evaluate/execute/append sequence."""
        st = self._state(scope)
        with st.lock:
            yield st

    def record(
        self, scope: BehaviorScope, event: BehaviorEvent, *, now: datetime | None = None
    ) -> None:
        now = _aware(now or datetime.now(timezone.utc))
        st = self._state(scope)
        with st.lock:
            self._apply(st, event, now)

    def _apply(self, st: _ScopeState, event: BehaviorEvent, now: datetime) -> None:
        kind = event.kind
        if kind is BehaviorEventKind.DENIED:
            st.policy_denials += 1
        if kind is BehaviorEventKind.BYPASS_ATTEMPTED:
            st.bypass_attempts += 1
        # Attempts are counted regardless of outcome (not only when executed).
        if event.privilege_escalation and kind in (
            BehaviorEventKind.PROPOSED,
            BehaviorEventKind.DENIED,
            BehaviorEventKind.BYPASS_ATTEMPTED,
            BehaviorEventKind.EXECUTED,
        ):
            st.privilege_escalation_attempts += 1

        # Real effects are attributed to EXECUTED only (no double counting).
        if kind is BehaviorEventKind.EXECUTED:
            st.executed.append(_aware(event.at))
            st.bytes_read += event.bytes_read
            st.bytes_written += event.bytes_written
            st.external_bytes += event.external_bytes
            if event.resource:
                st.unique_resources.add(event.resource)
            if event.secret_access:
                st.secret_access_count += 1
            if event.destructive:
                st.destructive_action_count += 1
            if event.sensitive_read:
                st.sensitive_reads.append(_aware(event.at))
            if event.external_destination:
                if event.external_destination not in st.destinations_seen:
                    st.destinations_seen.add(event.external_destination)
                    st.new_external_destination += 1
            if event.message_recipient:
                st.message_recipients.add(event.message_recipient)
        st._prune(now)

    def snapshot(
        self, scope: BehaviorScope, *, now: datetime | None = None
    ) -> BehaviorSnapshot:
        now = _aware(now or datetime.now(timezone.utc))
        st = self._state(scope)
        with st.lock:
            st._prune(now)
            c10 = now - timedelta(seconds=WINDOW_10S)
            c60 = now - timedelta(seconds=WINDOW_60S)
            c5m = now - timedelta(seconds=WINDOW_5M)
            return BehaviorSnapshot(
                scope=scope,
                actions_last_10s=sum(1 for t in st.executed if t >= c10),
                actions_last_60s=sum(1 for t in st.executed if t >= c60),
                actions_last_5m=sum(1 for t in st.executed if t >= c5m),
                sensitive_reads_last_5m=sum(1 for t in st.sensitive_reads if t >= c5m),
                bytes_read=st.bytes_read,
                bytes_written=st.bytes_written,
                external_bytes=st.external_bytes,
                unique_resources=len(st.unique_resources),
                secret_access_count=st.secret_access_count,
                policy_denials=st.policy_denials,
                privilege_escalation_attempts=st.privilege_escalation_attempts,
                new_external_destination=st.new_external_destination,
                destructive_action_count=st.destructive_action_count,
                agent_message_fanout=len(st.message_recipients),
                bypass_attempts=st.bypass_attempts,
                computed_at=_iso(now),
            )
