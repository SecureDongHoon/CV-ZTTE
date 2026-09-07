"""Threshold / multiparty FHE (spec §41, §42, §60.25).

Genuine OpenFHE **N-of-N** interactive decryption: every configured party is
required, no service persists a reconstructed full secret key, and secret shares
never leave a party's own directory (§41). Not a t-of-n threshold — see
``docs/THRESHOLD_FHE.md``.
"""

from __future__ import annotations

from cvztte.cac.threshold.authority import (
    SHARE_FILE,
    AuthorityRole,
    KeyAuthority,
    SubprocessParticipant,
)
from cvztte.cac.threshold.coordinator import (
    DecryptCoordinator,
    Participant,
    ThresholdKeyCeremony,
)
from cvztte.cac.threshold.release import DecryptReleaseRequest, ThresholdReleasePolicy
from cvztte.cac.threshold.service import run_authority_cli

__all__ = [
    "SHARE_FILE",
    "AuthorityRole",
    "KeyAuthority",
    "SubprocessParticipant",
    "Participant",
    "ThresholdKeyCeremony",
    "DecryptCoordinator",
    "DecryptReleaseRequest",
    "ThresholdReleasePolicy",
    "run_authority_cli",
]
