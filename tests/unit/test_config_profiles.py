"""Deployment profiles + fail-closed backpressure (spec §52, §53, §60.32)."""

from __future__ import annotations

import threading

import pytest

from cvztte.cac.context import SecurityProfile
from cvztte.config import (
    BoundedAdmission,
    DeploymentProfile,
    ProfileName,
    ResourceLimits,
    get_profile,
)
from cvztte.config.profiles import ProfileName as PN
from cvztte.errors import CVZTTEError, ErrorCode


# --- profiles ----------------------------------------------------------------


def test_three_profiles_resolve_by_name():
    assert get_profile("demo").name is ProfileName.DEMO
    assert get_profile("secure-lab").name is ProfileName.SECURE_LAB
    assert get_profile(ProfileName.ENTERPRISE_REFERENCE).name is ProfileName.ENTERPRISE_REFERENCE


def test_demo_is_labelled_weaker():
    demo = get_profile("demo")
    assert demo.security_profile is SecurityProfile.DEMO
    assert "clearly labelled" in demo.description.lower() or "weaker" in demo.description.lower()


def test_secure_lab_uses_128bit_and_separate_hosts():
    lab = get_profile("secure-lab")
    assert lab.security_profile is SecurityProfile.SECURE_LAB
    assert lab.requires_separate_hosts is True


def test_enterprise_reference_is_never_production_certified():
    ent = get_profile("enterprise-reference")
    assert ent.production_certified is False
    assert ent.requires_mtls is True
    assert ent.key_custody == "hsm-kms-tee"
    # It is a configuration skeleton — enumerates infra the reference build lacks.
    assert len(ent.infra_requirements) >= 10
    assert all(not r.satisfied_by_reference_build for r in ent.infra_requirements)


def test_enterprise_reference_cannot_be_marked_production_certified():
    # The invariant is enforced at construction (§53): never certified.
    with pytest.raises(ValueError):
        DeploymentProfile(
            name=PN.ENTERPRISE_REFERENCE, description="x",
            security_profile=SecurityProfile.SECURE_LAB,
            resource_limits=ResourceLimits(), production_certified=True,
        )


def test_resource_limits_are_frozen():
    limits = ResourceLimits(max_ciphertext_bytes=1024)
    with pytest.raises(Exception):
        limits.max_ciphertext_bytes = 2048  # type: ignore[misc]


# --- backpressure ------------------------------------------------------------


def test_admission_permits_up_to_capacity_then_sheds_fail_closed():
    ba = BoundedAdmission(name="prover", capacity=2)
    with ba.admit():
        with ba.admit():
            assert ba.inflight == 2
            with pytest.raises(CVZTTEError) as exc:
                with ba.admit():
                    pass
            assert exc.value.code is ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE
    assert ba.inflight == 0
    assert ba.shed_count == 1
    assert ba.admitted_count == 2


def test_admission_releases_on_exception():
    ba = BoundedAdmission(name="fhe", capacity=1)
    with pytest.raises(RuntimeError):
        with ba.admit():
            raise RuntimeError("boom")
    # The slot was released despite the error — the next admit succeeds.
    with ba.admit():
        assert ba.inflight == 1


def test_admission_is_thread_safe_bounded():
    ba = BoundedAdmission(name="fhe", capacity=3)
    peak = 0
    lock = threading.Lock()
    start = threading.Event()

    def worker():
        nonlocal peak
        start.wait()
        try:
            with ba.admit():
                with lock:
                    peak = max(peak, ba.inflight)
        except CVZTTEError:
            pass

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()
    assert peak <= 3
    assert ba.inflight == 0


def test_capacity_must_be_positive():
    with pytest.raises(ValueError):
        BoundedAdmission(name="x", capacity=0)
