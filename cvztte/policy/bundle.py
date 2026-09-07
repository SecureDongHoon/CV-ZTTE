"""Policy bundle versioning and hash pinning (spec §12, §13).

The active policy is deterministic, versioned, and hash-pinned: the
``policy_hash`` carried in a :class:`SignedActionRequest` MUST match the hash of
the bundle the control plane evaluates. The hash is a domain-separated
commitment over a canonical manifest of the bundle's files, so any change to any
``.rego`` file changes the pin (and mismatched requests are rejected).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode


def compute_bundle_hash(bundle_dir: str | Path, *, version: str) -> str:
    """Domain-separated commitment over (version, sorted file digests)."""
    root = Path(bundle_dir)
    files = sorted(p for p in root.rglob("*.rego") if p.is_file())
    if not files:
        raise CVZTTEError(ErrorCode.OPA_UNAVAILABLE, "policy bundle has no rego files")
    manifest = [
        {
            "path": str(p.relative_to(root)),
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        }
        for p in files
    ]
    return commit(Domain.POLICY, {"version": version, "files": manifest})


@dataclass(frozen=True)
class PolicyBundle:
    version: str
    path: Path
    policy_hash: str


class PolicyBundleRegistry:
    """Registry-controlled active policy bundle with hash pinning (spec §12)."""

    def __init__(self) -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._active: str | None = None

    def register(self, bundle_dir: str | Path, *, version: str, activate: bool = False) -> PolicyBundle:
        policy_hash = compute_bundle_hash(bundle_dir, version=version)
        bundle = PolicyBundle(version=version, path=Path(bundle_dir), policy_hash=policy_hash)
        self._bundles[policy_hash] = bundle
        if activate or self._active is None:
            self._active = policy_hash
        return bundle

    @property
    def active(self) -> PolicyBundle:
        if self._active is None:
            raise CVZTTEError(ErrorCode.OPA_UNAVAILABLE, "no active policy bundle")
        return self._bundles[self._active]

    def activate(self, policy_hash: str) -> PolicyBundle:
        if policy_hash not in self._bundles:
            raise CVZTTEError(ErrorCode.POLICY_HASH_MISMATCH, "unknown policy bundle")
        self._active = policy_hash
        return self._bundles[policy_hash]

    def require_pinned(self, policy_hash: str) -> PolicyBundle:
        """Return the bundle iff ``policy_hash`` matches the active pin."""
        active = self.active
        if policy_hash != active.policy_hash:
            raise CVZTTEError(
                ErrorCode.POLICY_HASH_MISMATCH,
                "request policy_hash does not match active bundle",
            )
        return active
