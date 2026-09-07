"""Phase 3 atomic replay/freshness against a real Redis (spec §11).

Covers the §60 replay adversarial cases: exact replay, nonce reuse, sequence
rollback, concurrent duplicate, and the fail-closed behavior when the store is
unavailable.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.replay import ReplayGuard


def test_fresh_request_ok(redis_client) -> None:
    guard = ReplayGuard(redis_client)
    guard.check_and_commit(session_id="S1", nonce="a" * 32, sequence=1)


def test_exact_nonce_replay_rejected(redis_client) -> None:
    guard = ReplayGuard(redis_client)
    guard.check_and_commit(session_id="S1", nonce="a" * 32, sequence=1)
    with pytest.raises(CVZTTEError) as exc:
        guard.check_and_commit(session_id="S1", nonce="a" * 32, sequence=2)
    assert exc.value.code == ErrorCode.NONCE_REPLAY


def test_sequence_rollback_rejected(redis_client) -> None:
    guard = ReplayGuard(redis_client)
    guard.check_and_commit(session_id="S1", nonce="a" * 32, sequence=5)
    with pytest.raises(CVZTTEError) as exc:
        guard.check_and_commit(session_id="S1", nonce="b" * 32, sequence=5)
    assert exc.value.code == ErrorCode.SEQUENCE_INVALID


def test_increasing_sequence_ok(redis_client) -> None:
    guard = ReplayGuard(redis_client)
    guard.check_and_commit(session_id="S1", nonce="a" * 32, sequence=1)
    guard.check_and_commit(session_id="S1", nonce="b" * 32, sequence=2)


def test_short_nonce_rejected(redis_client) -> None:
    guard = ReplayGuard(redis_client)
    with pytest.raises(CVZTTEError) as exc:
        guard.check_and_commit(session_id="S1", nonce="deadbeef", sequence=1)
    assert exc.value.code == ErrorCode.SCHEMA_INVALID


def test_concurrent_duplicate_exactly_one_ok(redis_client) -> None:
    guard = ReplayGuard(redis_client)

    def attempt(_):
        try:
            guard.check_and_commit(session_id="S2", nonce="d" * 32, sequence=5)
            return "OK"
        except CVZTTEError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(attempt, range(20)))
    assert results.count("OK") == 1


def test_redis_unavailable_fails_closed() -> None:
    import redis

    dead = redis.Redis(host="127.0.0.1", port=1)  # nothing listening
    with pytest.raises(CVZTTEError) as exc:
        ReplayGuard(dead).check_and_commit(session_id="S", nonce="a" * 32, sequence=1)
    assert exc.value.code == ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE
