"""Deployment-mode effect mapping + admin-only mode control (spec §33, §60.15).

A security decision (ALLOW/DENY) is turned into an *actual outcome* by the
deployment mode. OBSERVE is explicitly **not** security enforcement — it only
reports ``WOULD_ALLOW``/``WOULD_DENY`` and never blocks or executes (§60.15).
WARN permits but flags would-be denials (a rollout step before real
enforcement). ENFORCE blocks denials. QUARANTINE denies everything.

Mode changes are admin-only and audited (§60.15): a non-admin caller is refused
fail-closed, and every accepted change is written to the hash-chained audit log.
"""

from __future__ import annotations

import enum
import threading

from cvztte.audit.log import AuditStage, HashChainedAuditLog
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.onboarding.profile import DeploymentMode


class ModeOutcome(str, enum.Enum):
    WOULD_ALLOW = "WOULD_ALLOW"   # OBSERVE, base ALLOW
    WOULD_DENY = "WOULD_DENY"     # OBSERVE, base DENY
    ALLOW = "ALLOW"               # executed
    WARN_ALLOW = "WARN_ALLOW"     # WARN: permitted but flagged (base DENY)
    DENY = "DENY"                 # blocked


def apply_mode(mode: DeploymentMode, base_allow: bool) -> ModeOutcome:
    """Map a security decision to the mode's actual outcome (§60.15).

    ``base_allow`` is the security verdict (True = would allow, False = deny).
    Returns the outcome; only ENFORCE/QUARANTINE ever block.
    """
    if mode is DeploymentMode.OBSERVE:
        return ModeOutcome.WOULD_ALLOW if base_allow else ModeOutcome.WOULD_DENY
    if mode is DeploymentMode.WARN:
        return ModeOutcome.ALLOW if base_allow else ModeOutcome.WARN_ALLOW
    if mode is DeploymentMode.ENFORCE:
        return ModeOutcome.ALLOW if base_allow else ModeOutcome.DENY
    # QUARANTINE: deny everything, regardless of the base verdict.
    return ModeOutcome.DENY


def is_enforcing(mode: DeploymentMode) -> bool:
    """Only ENFORCE and QUARANTINE actually block actions (§60.15)."""
    return mode in (DeploymentMode.ENFORCE, DeploymentMode.QUARANTINE)


class ModeController:
    """Holds the current deployment mode; changes are admin-only and audited."""

    def __init__(
        self,
        *,
        mode: DeploymentMode = DeploymentMode.OBSERVE,
        audit_log: HashChainedAuditLog | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._mode = mode
        self._audit = audit_log

    @property
    def mode(self) -> DeploymentMode:
        with self._lock:
            return self._mode

    def set_mode(self, new_mode: DeploymentMode, *, actor: str, is_admin: bool) -> None:
        """Admin-only, audited mode change (§60.15). Non-admin is refused fail-closed."""
        if not is_admin:
            raise CVZTTEError(
                ErrorCode.MODE_CHANGE_FORBIDDEN, "mode change requires an administrator"
            )
        if not actor:
            raise CVZTTEError(ErrorCode.MODE_CHANGE_FORBIDDEN, "mode change requires an actor")
        with self._lock:
            old = self._mode
            self._mode = new_mode
            if self._audit is not None:
                self._audit.append(
                    AuditStage.ADMIN,
                    {
                        "action": "mode_change",
                        "actor": actor,
                        "old_mode": old.value,
                        "new_mode": new_mode.value,
                    },
                )

    def apply(self, base_allow: bool) -> ModeOutcome:
        return apply_mode(self.mode, base_allow)
