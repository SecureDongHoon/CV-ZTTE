"""Phase 4 policy bundle hashing + pinning (spec §12, §13)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cvztte.action.model import DataClassification
from cvztte.delegation import AuthorityKind, DelegationRegistry, PolicyAuthority
from cvztte.delegation.model import _utcnow
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.policy import (
    PolicyBundleRegistry,
    compute_bundle_hash,
    grant_from_delegation,
)

REAL_BUNDLE = Path(__file__).resolve().parents[2] / "policy" / "rego"


def _write_bundle(tmp: Path, body: str) -> Path:
    d = tmp / "rego"
    (d / "cvztte").mkdir(parents=True)
    (d / "cvztte" / "authz.rego").write_text(body)
    return d


def test_hash_is_deterministic_and_domain_separated() -> None:
    h1 = compute_bundle_hash(REAL_BUNDLE, version="1")
    h2 = compute_bundle_hash(REAL_BUNDLE, version="1")
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_hash_changes_with_content(tmp_path: Path) -> None:
    b1 = _write_bundle(tmp_path / "a", "package cvztte.authz\nallow := true\n")
    b2 = _write_bundle(tmp_path / "b", "package cvztte.authz\nallow := false\n")
    assert compute_bundle_hash(b1, version="1") != compute_bundle_hash(b2, version="1")


def test_hash_changes_with_version() -> None:
    assert compute_bundle_hash(REAL_BUNDLE, version="1") != compute_bundle_hash(
        REAL_BUNDLE, version="2"
    )


def test_registry_pinning() -> None:
    reg = PolicyBundleRegistry()
    bundle = reg.register(REAL_BUNDLE, version="1.0.0", activate=True)
    assert reg.require_pinned(bundle.policy_hash).version == "1.0.0"
    with pytest.raises(CVZTTEError) as exc:
        reg.require_pinned("sha256:" + "0" * 64)
    assert exc.value.code == ErrorCode.POLICY_HASH_MISMATCH


def test_empty_bundle_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(CVZTTEError) as exc:
        compute_bundle_hash(tmp_path / "empty", version="1")
    assert exc.value.code == ErrorCode.OPA_UNAVAILABLE


def test_grant_from_delegation_derives_gates() -> None:
    reg = DelegationRegistry([PolicyAuthority("admin", AuthorityKind.SECURITY_ADMIN)])
    now = _utcnow()
    dele = reg.issue_root(
        authority_id="admin",
        subject_agent_id="agt_a",
        capabilities={"fs:read", "shell:exec"},
        resource_scopes={"fs:/data"},
        clearance=DataClassification.CONFIDENTIAL,
        not_before=now,
        not_after=now.replace(year=now.year + 1),
    )
    grant = grant_from_delegation(dele)
    assert grant.shell_permitted is True
    assert grant.secret_access_permitted is False
    assert grant.allow_external_network is False
    assert grant.clearance == DataClassification.CONFIDENTIAL
