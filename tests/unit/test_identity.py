"""Phase 2 identity tests (spec §9, §60.2).

Exercises the PRIMARY native-OpenSSL ML-DSA provider end to end (no mocks on
the acceptance path, spec §0 rule 10): sign/verify, mutation rejection, key
isolation, and the full key lifecycle (prepare/activate/rotate/revoke) with
validity windows and emergency revocation.
"""

from __future__ import annotations

import os
import stat
from datetime import timedelta

import pytest

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity import (
    Algorithm,
    DEFAULT_ALGORITHM,
    KeyRegistry,
    KeyState,
    LibOQSFallbackProvider,
    OpenSSLMLDSAProvider,
)
from cvztte.identity.registry import _utcnow


@pytest.fixture(scope="module")
def provider(tmp_path_factory: pytest.TempPathFactory) -> OpenSSLMLDSAProvider:
    keystore = tmp_path_factory.mktemp("keystore")
    return OpenSSLMLDSAProvider(keystore)


# --------------------------------------------------------------------------- #
# provider-level crypto
# --------------------------------------------------------------------------- #
def test_default_algorithm_is_ml_dsa_65(provider: OpenSSLMLDSAProvider) -> None:
    assert DEFAULT_ALGORITHM == Algorithm.ML_DSA_65
    assert provider.algorithm == Algorithm.ML_DSA_65
    meta = provider.provider_metadata()
    assert meta["algorithm"] == "ML-DSA-65"
    assert meta["production_equivalent"] is True
    assert "FIPS" in meta["note"]  # standardization != module validation


def test_sign_verify_roundtrip(provider: OpenSSLMLDSAProvider) -> None:
    handle, public = provider.generate_key()
    msg = b"canonical-signed-bytes"
    sig = provider.sign(handle, msg)
    assert len(sig) > 1000  # ML-DSA-65 signatures are ~3.3 KiB
    assert provider.verify(public, msg, sig) is True


def test_tampered_message_rejected(provider: OpenSSLMLDSAProvider) -> None:
    handle, public = provider.generate_key()
    sig = provider.sign(handle, b"original-bytes")
    assert provider.verify(public, b"original-byteX", sig) is False


def test_tampered_signature_rejected(provider: OpenSSLMLDSAProvider) -> None:
    handle, public = provider.generate_key()
    msg = b"original-bytes"
    sig = bytearray(provider.sign(handle, msg))
    sig[10] ^= 0x01
    assert provider.verify(public, msg, bytes(sig)) is False


def test_signature_of_one_key_not_valid_under_another(
    provider: OpenSSLMLDSAProvider,
) -> None:
    h1, _ = provider.generate_key()
    _, pub2 = provider.generate_key()
    sig = provider.sign(h1, b"msg")
    # Cross-key: key A's signature must not verify under key B (§4 invariants).
    assert provider.verify(pub2, b"msg", sig) is False


def test_private_key_is_isolated(provider: OpenSSLMLDSAProvider) -> None:
    handle, _ = provider.generate_key()
    # repr must not leak the key path.
    assert "<redacted>" in repr(handle)
    assert str(handle.path) not in repr(handle)
    # on-disk private key is 0600.
    mode = stat.S_IMODE(os.stat(handle.path).st_mode)
    assert mode == 0o600


def test_import_roundtrip(provider: OpenSSLMLDSAProvider) -> None:
    handle, public = provider.generate_key()
    imported_pub = provider.import_public_key(public.pem)
    assert imported_pub.fingerprint == public.fingerprint
    sig = provider.sign(handle, b"data")
    assert provider.verify(imported_pub, b"data", sig) is True


def test_import_bad_public_key_rejected(provider: OpenSSLMLDSAProvider) -> None:
    with pytest.raises(CVZTTEError) as exc:
        provider.import_public_key(b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n")
    assert exc.value.code == ErrorCode.MLDSA_INVALID


# --------------------------------------------------------------------------- #
# liboqs fallback must be disabled and visibly non-production
# --------------------------------------------------------------------------- #
def test_liboqs_fallback_disabled_by_default() -> None:
    fb = LibOQSFallbackProvider()
    meta = fb.provider_metadata()
    assert meta["production_equivalent"] is False
    assert meta["enabled"] is False
    with pytest.raises(CVZTTEError) as exc:
        fb.generate_key()
    assert exc.value.code == ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE


# --------------------------------------------------------------------------- #
# registry: agent-identity != key-identity, lifecycle, revocation
# --------------------------------------------------------------------------- #
@pytest.fixture()
def registry(provider: OpenSSLMLDSAProvider) -> KeyRegistry:
    reg = KeyRegistry(provider)
    reg.register_agent("agt_alice")
    return reg


def test_prepared_key_is_not_a_signing_key(registry: KeyRegistry) -> None:
    registry.generate_key("agt_alice", state=KeyState.PREPARED)
    with pytest.raises(CVZTTEError) as exc:
        registry.active_signing_key("agt_alice")
    assert exc.value.code == ErrorCode.KEY_UNKNOWN


def test_sign_and_verify_through_registry(registry: KeyRegistry) -> None:
    registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    key_id, sig = registry.sign_as_agent("agt_alice", b"the-message")
    assert registry.verify_with_key(key_id, b"the-message", sig) is True
    with pytest.raises(CVZTTEError) as exc:
        registry.verify_with_key(key_id, b"other-message", sig)
    assert exc.value.code == ErrorCode.MLDSA_INVALID


def test_rotation_retires_previous_key(registry: KeyRegistry) -> None:
    old = registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    new = registry.rotate("agt_alice")
    # agent identity is stable; key identity changed.
    assert old.agent_id == new.agent_id == "agt_alice"
    assert old.key_id != new.key_id
    assert registry.get_key(old.key_id).state == KeyState.RETIRED
    assert registry.get_key(new.key_id).state == KeyState.ACTIVE
    assert registry.active_signing_key("agt_alice").key_id == new.key_id


def test_retired_key_still_verifies_prior_signatures(registry: KeyRegistry) -> None:
    old = registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    key_id, sig = registry.sign_as_agent("agt_alice", b"m")
    registry.rotate("agt_alice")  # old -> retired
    assert registry.get_key(old.key_id).state == KeyState.RETIRED
    # A signature made while active still verifies while the key is retired.
    assert registry.verify_with_key(key_id, b"m", sig) is True


def test_revoked_key_rejected_for_verify(registry: KeyRegistry) -> None:
    rec = registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    key_id, sig = registry.sign_as_agent("agt_alice", b"m")
    registry.revoke(rec.key_id, reason="compromise")
    with pytest.raises(CVZTTEError) as exc:
        registry.verify_with_key(key_id, b"m", sig)
    assert exc.value.code == ErrorCode.KEY_REVOKED
    # and it is no longer a usable signing key.
    with pytest.raises(CVZTTEError):
        registry.active_signing_key("agt_alice")


def test_emergency_agent_revocation_kill_switch(registry: KeyRegistry) -> None:
    registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    registry.generate_key("agt_alice", state=KeyState.PREPARED)
    revoked = registry.revoke_agent("agt_alice", reason="kill-switch")
    assert len(revoked) == 2
    assert all(r.state == KeyState.REVOKED for r in revoked)
    # agent disabled -> even lookups fail closed.
    with pytest.raises(CVZTTEError) as exc:
        registry.active_signing_key("agt_alice")
    assert exc.value.code == ErrorCode.AGENT_DISABLED


def test_future_key_not_valid_yet(registry: KeyRegistry) -> None:
    future = _utcnow() + timedelta(hours=1)
    registry.generate_key("agt_alice", state=KeyState.ACTIVE, not_before=future)
    with pytest.raises(CVZTTEError):
        registry.active_signing_key("agt_alice")


def test_expired_key_rejected_for_verify(registry: KeyRegistry) -> None:
    now = _utcnow()
    rec = registry.generate_key(
        "agt_alice",
        state=KeyState.ACTIVE,
        not_before=now - timedelta(hours=2),
        not_after=now - timedelta(hours=1),
    )
    assert rec.private_handle is not None
    # Sign directly via the provider (bypassing the active-window signing path);
    # verification must still reject because the key's validity window elapsed.
    sig = registry.provider.sign(rec.private_handle, b"m")
    with pytest.raises(CVZTTEError):
        registry.verify_with_key(rec.key_id, b"m", sig)


def test_unknown_agent_and_key(registry: KeyRegistry) -> None:
    with pytest.raises(CVZTTEError) as e1:
        registry.active_signing_key("agt_ghost")
    assert e1.value.code == ErrorCode.AGENT_UNKNOWN
    with pytest.raises(CVZTTEError) as e2:
        registry.get_key("key_does_not_exist")
    assert e2.value.code == ErrorCode.KEY_UNKNOWN


def test_public_registry_export_has_no_secrets(registry: KeyRegistry) -> None:
    registry.generate_key("agt_alice", state=KeyState.ACTIVE)
    export = registry.export_public_registry()
    assert export
    for row in export:
        assert set(row).isdisjoint({"private_handle", "path"})
        assert row["fingerprint"].startswith("sha256:")
