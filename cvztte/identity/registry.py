"""Agent-identity and key registry (spec §9, §60.2).

Enforces the mandated separations and lifecycle:

* **Agent identity != key identity** — a stable ``agent_id`` owns a sequence of
  keys that rotate independently.
* **Key states** ``prepared / active / retired / revoked`` with
  ``not_before`` / ``not_after`` validity windows.
* **Rotation** — stage a ``prepared`` key, activate it, retire the predecessor
  (no gap in the ability to verify prior signatures within their window).
* **Emergency revocation** — a key or an entire agent can be revoked
  immediately; revoked keys are rejected for BOTH signing and verification and
  never recover (recovery is a policy-controlled re-onboarding, spec §27).

The registry never handles private key bytes directly — it holds opaque
:class:`~cvztte.identity.provider.PrivateKeyHandle` references and delegates all
crypto to the injected :class:`~cvztte.identity.provider.SignatureProvider`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity.provider import PrivateKeyHandle, PublicKey, SignatureProvider


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class KeyState(str, enum.Enum):
    PREPARED = "prepared"  # staged, not yet valid for signing
    ACTIVE = "active"      # the current signing key
    RETIRED = "retired"    # superseded; may still verify within its window
    REVOKED = "revoked"    # compromised/withdrawn; rejected everywhere


@dataclass
class KeyRecord:
    key_id: str
    agent_id: str
    public_key: PublicKey
    state: KeyState
    not_before: datetime
    not_after: datetime | None = None
    private_handle: PrivateKeyHandle | None = None  # None => verify-only
    created_at: datetime = field(default_factory=_utcnow)
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def within_window(self, now: datetime) -> bool:
        if now < self.not_before:
            return False
        if self.not_after is not None and now >= self.not_after:
            return False
        return True

    def public_view(self) -> dict[str, object]:
        """Non-secret projection for audit/registry export."""
        return {
            "key_id": self.key_id,
            "agent_id": self.agent_id,
            "algorithm": self.public_key.algorithm.value,
            "fingerprint": self.public_key.fingerprint,
            "state": self.state.value,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
        }


@dataclass
class AgentRecord:
    agent_id: str
    enabled: bool = True


class KeyRegistry:
    """In-memory identity/key registry (PoC store; DB/HSM in production)."""

    def __init__(self, provider: SignatureProvider) -> None:
        self._provider = provider
        self._agents: dict[str, AgentRecord] = {}
        self._keys: dict[str, KeyRecord] = {}

    @property
    def provider(self) -> SignatureProvider:
        return self._provider

    # ------------------------------------------------------------------ #
    # agents
    # ------------------------------------------------------------------ #
    def register_agent(self, agent_id: str) -> AgentRecord:
        rec = self._agents.get(agent_id)
        if rec is None:
            rec = AgentRecord(agent_id=agent_id)
            self._agents[agent_id] = rec
        return rec

    def _require_agent(self, agent_id: str) -> AgentRecord:
        rec = self._agents.get(agent_id)
        if rec is None:
            raise CVZTTEError(ErrorCode.AGENT_UNKNOWN, "agent not registered")
        if not rec.enabled:
            raise CVZTTEError(ErrorCode.AGENT_DISABLED, "agent disabled")
        return rec

    def disable_agent(self, agent_id: str) -> None:
        rec = self._agents.get(agent_id)
        if rec is None:
            raise CVZTTEError(ErrorCode.AGENT_UNKNOWN, "agent not registered")
        rec.enabled = False

    # ------------------------------------------------------------------ #
    # key lifecycle
    # ------------------------------------------------------------------ #
    def _key_id(self, public_key: PublicKey) -> str:
        # Derive a stable key id from the public fingerprint (not secret).
        return "key_" + public_key.fingerprint.split(":", 1)[1][:32]

    def generate_key(
        self,
        agent_id: str,
        *,
        state: KeyState = KeyState.PREPARED,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
    ) -> KeyRecord:
        """Generate and register a new signing key for an agent."""
        self._require_agent(agent_id)
        if state == KeyState.REVOKED:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "cannot create a revoked key")
        handle, public = self._provider.generate_key()
        key_id = self._key_id(public)
        if key_id in self._keys:
            raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "duplicate key id")
        rec = KeyRecord(
            key_id=key_id,
            agent_id=agent_id,
            public_key=public,
            state=state,
            not_before=not_before or _utcnow(),
            not_after=not_after,
            private_handle=handle,
        )
        self._keys[key_id] = rec
        if state == KeyState.ACTIVE:
            self._retire_other_active(agent_id, keep=key_id)
        return rec

    def import_verification_key(
        self,
        agent_id: str,
        public_pem: bytes,
        *,
        state: KeyState = KeyState.ACTIVE,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
    ) -> KeyRecord:
        """Register a verify-only key (no private handle) for a remote agent."""
        self._require_agent(agent_id)
        public = self._provider.import_public_key(public_pem)
        key_id = self._key_id(public)
        rec = KeyRecord(
            key_id=key_id,
            agent_id=agent_id,
            public_key=public,
            state=state,
            not_before=not_before or _utcnow(),
            not_after=not_after,
            private_handle=None,
        )
        self._keys[key_id] = rec
        return rec

    def _retire_other_active(self, agent_id: str, *, keep: str) -> None:
        for rec in self._keys.values():
            if (
                rec.agent_id == agent_id
                and rec.state == KeyState.ACTIVE
                and rec.key_id != keep
            ):
                rec.state = KeyState.RETIRED

    def activate(self, key_id: str) -> KeyRecord:
        rec = self._require_key(key_id)
        if rec.state == KeyState.REVOKED:
            raise CVZTTEError(ErrorCode.KEY_REVOKED, "cannot activate a revoked key")
        if rec.private_handle is None:
            raise CVZTTEError(
                ErrorCode.KEY_UNKNOWN, "verify-only key cannot become a signing key"
            )
        rec.state = KeyState.ACTIVE
        self._retire_other_active(rec.agent_id, keep=key_id)
        return rec

    def rotate(
        self,
        agent_id: str,
        *,
        not_after: datetime | None = None,
    ) -> KeyRecord:
        """Generate a new key, activate it, retire the previous active key."""
        new_rec = self.generate_key(
            agent_id, state=KeyState.ACTIVE, not_after=not_after
        )
        return new_rec

    def revoke(self, key_id: str, *, reason: str = "") -> KeyRecord:
        """Emergency-revoke a single key (irreversible; spec §27)."""
        rec = self._require_key(key_id)
        rec.state = KeyState.REVOKED
        rec.revoked_at = _utcnow()
        rec.revocation_reason = reason or None
        return rec

    def revoke_agent(self, agent_id: str, *, reason: str = "") -> list[KeyRecord]:
        """Emergency-revoke every key for an agent and disable it (kill switch)."""
        revoked: list[KeyRecord] = []
        for rec in self._keys.values():
            if rec.agent_id == agent_id and rec.state != KeyState.REVOKED:
                rec.state = KeyState.REVOKED
                rec.revoked_at = _utcnow()
                rec.revocation_reason = reason or None
                revoked.append(rec)
        if agent_id in self._agents:
            self._agents[agent_id].enabled = False
        return revoked

    # ------------------------------------------------------------------ #
    # lookups
    # ------------------------------------------------------------------ #
    def _require_key(self, key_id: str) -> KeyRecord:
        rec = self._keys.get(key_id)
        if rec is None:
            raise CVZTTEError(ErrorCode.KEY_UNKNOWN, "unknown key id")
        return rec

    def get_key(self, key_id: str) -> KeyRecord:
        return self._require_key(key_id)

    def active_signing_key(self, agent_id: str, *, now: datetime | None = None) -> KeyRecord:
        """The single ACTIVE, in-window signing key for ``agent_id``."""
        self._require_agent(agent_id)
        now = now or _utcnow()
        for rec in self._keys.values():
            if (
                rec.agent_id == agent_id
                and rec.state == KeyState.ACTIVE
                and rec.private_handle is not None
                and rec.within_window(now)
            ):
                return rec
        raise CVZTTEError(ErrorCode.KEY_UNKNOWN, "no active in-window signing key")

    # ------------------------------------------------------------------ #
    # crypto operations bound to the registry's provider
    # ------------------------------------------------------------------ #
    def sign_as_agent(
        self, agent_id: str, message: bytes, *, now: datetime | None = None
    ) -> tuple[str, bytes]:
        """Sign ``message`` with the agent's active key; return (key_id, sig)."""
        rec = self.active_signing_key(agent_id, now=now)
        assert rec.private_handle is not None  # guaranteed by active_signing_key
        signature = self._provider.sign(rec.private_handle, message)
        return rec.key_id, signature

    def verify_with_key(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Verify a signature, enforcing key state + validity window.

        Fail-closed: revoked/unknown/out-of-window keys and invalid signatures
        all raise :class:`CVZTTEError` (mapped to DENY by the caller).
        """
        now = now or _utcnow()
        rec = self._require_key(key_id)
        if rec.state == KeyState.REVOKED:
            raise CVZTTEError(ErrorCode.KEY_REVOKED, "key is revoked")
        if rec.state == KeyState.PREPARED:
            raise CVZTTEError(ErrorCode.KEY_UNKNOWN, "key not yet activated")
        if not rec.within_window(now):
            raise CVZTTEError(ErrorCode.KEY_UNKNOWN, "key outside validity window")
        if not self._provider.verify(rec.public_key, message, signature):
            raise CVZTTEError(ErrorCode.MLDSA_INVALID, "signature verification failed")
        return True

    def export_public_registry(self) -> list[dict[str, object]]:
        """Non-secret snapshot of all keys (for audit / distribution)."""
        return [rec.public_view() for rec in self._keys.values()]
