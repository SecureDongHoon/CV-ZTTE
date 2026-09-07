"""Phase 3 sessions (spec §11)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.session import SessionStore
from cvztte.session.model import _utcnow


@pytest.fixture()
def store() -> SessionStore:
    return SessionStore()


def test_create_and_validate(store: SessionStore) -> None:
    s = store.create(agent_id="agt_alice", runtime_id="rt_1")
    assert store.validate(s.session_id, agent_id="agt_alice", runtime_id="rt_1").session_id == s.session_id


def test_unknown_session(store: SessionStore) -> None:
    with pytest.raises(CVZTTEError) as exc:
        store.validate("ses_nope", agent_id="agt_alice", runtime_id="rt_1")
    assert exc.value.code == ErrorCode.SESSION_UNKNOWN


def test_wrong_binding(store: SessionStore) -> None:
    s = store.create(agent_id="agt_alice", runtime_id="rt_1")
    with pytest.raises(CVZTTEError) as exc:
        store.validate(s.session_id, agent_id="agt_bob", runtime_id="rt_1")
    assert exc.value.code == ErrorCode.SESSION_UNKNOWN


def test_expired_session(store: SessionStore) -> None:
    s = store.create(agent_id="agt_alice", runtime_id="rt_1", ttl_seconds=10)
    later = _utcnow() + timedelta(seconds=20)
    with pytest.raises(CVZTTEError) as exc:
        store.validate(s.session_id, agent_id="agt_alice", runtime_id="rt_1", now=later)
    assert exc.value.code == ErrorCode.SESSION_EXPIRED


def test_revoked_session(store: SessionStore) -> None:
    s = store.create(agent_id="agt_alice", runtime_id="rt_1")
    store.revoke(s.session_id)
    with pytest.raises(CVZTTEError) as exc:
        store.validate(s.session_id, agent_id="agt_alice", runtime_id="rt_1")
    assert exc.value.code == ErrorCode.SESSION_EXPIRED
