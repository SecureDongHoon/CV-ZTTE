"""Sessions and runtimes (spec §11).

A session binds an agent to a runtime for a bounded interval. Sessions are
short-lived and revocable (kill switch, spec §27). Session validity is a
freshness input to every protected action; an unknown/expired/revoked session
fails closed.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cvztte.errors import CVZTTEError, ErrorCode

DEFAULT_SESSION_TTL_SECONDS = 3600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SessionState(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class Session:
    session_id: str
    agent_id: str
    runtime_id: str
    created_at: datetime
    expires_at: datetime
    revoked: bool = False

    def state(self, now: datetime) -> SessionState:
        if self.revoked:
            return SessionState.REVOKED
        if now >= self.expires_at:
            return SessionState.EXPIRED
        return SessionState.ACTIVE


class SessionStore:
    """In-memory session store (PoC; DB-backed in production)."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create(
        self,
        *,
        agent_id: str,
        runtime_id: str,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        now: datetime | None = None,
    ) -> Session:
        now = now or _utcnow()
        sess = Session(
            session_id="ses_" + uuid.uuid4().hex,
            agent_id=agent_id,
            runtime_id=runtime_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self._sessions[sess.session_id] = sess
        return sess

    def get(self, session_id: str) -> Session:
        sess = self._sessions.get(session_id)
        if sess is None:
            raise CVZTTEError(ErrorCode.SESSION_UNKNOWN, "unknown session")
        return sess

    def validate(
        self,
        session_id: str,
        *,
        agent_id: str,
        runtime_id: str,
        now: datetime | None = None,
    ) -> Session:
        """Return the session iff active and bound to the given agent/runtime."""
        now = now or _utcnow()
        sess = self.get(session_id)
        if sess.agent_id != agent_id or sess.runtime_id != runtime_id:
            raise CVZTTEError(
                ErrorCode.SESSION_UNKNOWN, "session not bound to agent/runtime"
            )
        state = sess.state(now)
        if state == SessionState.REVOKED:
            raise CVZTTEError(ErrorCode.SESSION_EXPIRED, "session revoked")
        if state == SessionState.EXPIRED:
            raise CVZTTEError(ErrorCode.SESSION_EXPIRED, "session expired")
        return sess

    def revoke(self, session_id: str) -> None:
        self.get(session_id).revoked = True
