"""Behavior Engine tests (spec §24, §60.6)."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

from cvztte.action.model import DataClassification
from cvztte.behavior import (
    BehaviorEngine,
    BehaviorEvent,
    BehaviorEventKind,
    BehaviorScope,
)

T0 = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
SCOPE = BehaviorScope(agent_id="agt_alice", session_id="ses_1", runtime_id="rt_1")


def _ev(kind: BehaviorEventKind, at: datetime, **kw) -> BehaviorEvent:
    return BehaviorEvent(kind=kind, action_type=kw.pop("action_type", "FILE_READ"), at=at, **kw)


def test_windowed_actions_count_executed_only() -> None:
    eng = BehaviorEngine()
    # 4 executed spread over 5 minutes.
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0 - timedelta(seconds=5)), now=T0)
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0 - timedelta(seconds=30)), now=T0)
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0 - timedelta(seconds=120)), now=T0)
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0 - timedelta(seconds=290)), now=T0)
    snap = eng.snapshot(SCOPE, now=T0)
    assert snap.actions_last_10s == 1
    assert snap.actions_last_60s == 2
    assert snap.actions_last_5m == 4


def test_proposal_and_execution_not_double_counted() -> None:
    eng = BehaviorEngine()
    eng.record(SCOPE, _ev(BehaviorEventKind.PROPOSED, T0), now=T0)
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0), now=T0)
    snap = eng.snapshot(SCOPE, now=T0)
    assert snap.actions_last_60s == 1  # proposal not counted as a second action


def test_denial_bypass_and_attempt_counters() -> None:
    eng = BehaviorEngine()
    eng.record(SCOPE, _ev(BehaviorEventKind.DENIED, T0), now=T0)
    eng.record(SCOPE, _ev(BehaviorEventKind.DENIED, T0), now=T0)
    eng.record(SCOPE, _ev(BehaviorEventKind.BYPASS_ATTEMPTED, T0), now=T0)
    eng.record(
        SCOPE, _ev(BehaviorEventKind.DENIED, T0, privilege_escalation=True), now=T0
    )
    snap = eng.snapshot(SCOPE, now=T0)
    assert snap.policy_denials == 3
    assert snap.bypass_attempts == 1
    assert snap.privilege_escalation_attempts == 1


def test_cumulative_effect_features() -> None:
    eng = BehaviorEngine()
    eng.record(
        SCOPE,
        _ev(
            BehaviorEventKind.EXECUTED, T0, resource="db/x", bytes_read=100,
            sensitive_read=True, data_classification=DataClassification.CONFIDENTIAL,
        ),
        now=T0,
    )
    eng.record(
        SCOPE,
        _ev(
            BehaviorEventKind.EXECUTED, T0, action_type="SECRET_ACCESS",
            resource="db/x", secret_access=True,
        ),
        now=T0,
    )
    eng.record(
        SCOPE,
        _ev(
            BehaviorEventKind.EXECUTED, T0, action_type="NETWORK_REQUEST",
            external_destination="api.ext.example", external_bytes=50, bytes_written=50,
        ),
        now=T0,
    )
    eng.record(
        SCOPE,
        _ev(BehaviorEventKind.EXECUTED, T0, action_type="FILE_DELETE", destructive=True),
        now=T0,
    )
    eng.record(
        SCOPE,
        _ev(BehaviorEventKind.EXECUTED, T0, action_type="AGENT_MESSAGE",
            message_recipient="agt_bob"),
        now=T0,
    )
    snap = eng.snapshot(SCOPE, now=T0)
    assert snap.bytes_read == 100
    assert snap.bytes_written == 50
    assert snap.external_bytes == 50
    assert snap.unique_resources == 1  # db/x touched twice, counted once
    assert snap.secret_access_count == 1
    assert snap.sensitive_reads_last_5m == 1
    assert snap.destructive_action_count == 1
    assert snap.new_external_destination == 1
    assert snap.agent_message_fanout == 1


def test_new_external_destination_dedup() -> None:
    eng = BehaviorEngine()
    for host in ("a.example", "a.example", "b.example"):
        eng.record(
            SCOPE,
            _ev(BehaviorEventKind.EXECUTED, T0, action_type="NETWORK_REQUEST",
                external_destination=host),
            now=T0,
        )
    assert eng.snapshot(SCOPE, now=T0).new_external_destination == 2


def test_snapshot_hash_excludes_time_but_reflects_content() -> None:
    eng = BehaviorEngine()
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0, bytes_read=10), now=T0)
    s1 = eng.snapshot(SCOPE, now=T0)
    s2 = eng.snapshot(SCOPE, now=T0)
    assert s1.snapshot_hash().startswith("sha256:")
    assert s1.snapshot_hash() == s2.snapshot_hash()  # same content, hash stable
    # A later snapshot where the action has aged out of every window differs.
    s3 = eng.snapshot(SCOPE, now=T0 + timedelta(seconds=301))
    assert s3.actions_last_5m == 0
    assert s3.snapshot_hash() != s1.snapshot_hash()


def test_scopes_are_isolated() -> None:
    eng = BehaviorEngine()
    other = BehaviorScope(agent_id="agt_bob", session_id="ses_2", runtime_id="rt_1")
    eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0), now=T0)
    assert eng.snapshot(SCOPE, now=T0).actions_last_60s == 1
    assert eng.snapshot(other, now=T0).actions_last_60s == 0


def test_concurrent_records_are_race_safe() -> None:
    eng = BehaviorEngine()
    threads_n, per = 8, 50

    def worker() -> None:
        for _ in range(per):
            eng.record(SCOPE, _ev(BehaviorEventKind.DENIED, T0), now=T0)

    threads = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert eng.snapshot(SCOPE, now=T0).policy_denials == threads_n * per


def test_transition_holds_scope_lock() -> None:
    eng = BehaviorEngine()
    with eng.transition(SCOPE) as st:
        # Inside the transition we can append and the same lock is reentrant.
        eng.record(SCOPE, _ev(BehaviorEventKind.EXECUTED, T0), now=T0)
        assert len(st.executed) == 1
    assert eng.snapshot(SCOPE, now=T0).actions_last_60s == 1
