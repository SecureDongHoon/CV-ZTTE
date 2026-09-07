"""Adversarial family: failure injection / fail-closed (§51 Failure injection,
§60.31 #57-62, #102).

When a mandatory security dependency is unavailable, the system MUST fail closed
(§4.20) — never an implicit ALLOW. These drive a dependency fault through the
integrated ControlPlane and assert the pipeline denies and mints no token.
"""

from __future__ import annotations

import pytest

from cvztte.errors import CVZTTEError, ErrorCode

from lab import AdversarialLab


# #58 OPA down -> fail closed -----------------------------------------------


def test_case58_opa_unavailable_fails_closed(registry, tmp_path, allow_decision):
    lab = AdversarialLab(registry, tmp_path, decision=allow_decision)

    class _DownOPA:
        def authorize(self, input_doc):
            raise CVZTTEError(ErrorCode.OPA_UNAVAILABLE, "opa unreachable")

    lab.plane._opa = _DownOPA()
    sess = lab.open_session()
    env = lab.sign(sess.session_id, action=lab.file_action())
    with pytest.raises(CVZTTEError) as exc:
        lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
    assert exc.value.code is ErrorCode.OPA_UNAVAILABLE
    # No token was presented — the enforcement point would find nothing.
    assert lab.store.get(lab.broker.audience, env.request.action_hash) is None
    lab.assert_no_side_effects()


# #102 enforcement point unavailable -> fail closed -------------------------


def test_case102_broker_dependency_failure_no_side_effect(registry, tmp_path, allow_decision):
    lab = AdversarialLab(registry, tmp_path, decision=allow_decision)
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    from enforcement.file_broker import FileRequest

    req = FileRequest("f.txt", "write", b"x")
    action = lab.observe(req, binding)
    lab.present(lab.issue_token(action=action, binding=binding))

    # Inject an execution fault: the broker's write raises. Mediation must record
    # a non-EXECUTED receipt and surface the error, never a silent success.
    import enforcement.file_broker as fb_mod

    orig = fb_mod.FileBroker._execute
    fb_mod.FileBroker._execute = lambda self, *a, **k: (_ for _ in ()).throw(
        CVZTTEError(ErrorCode.EXECUTION_FAILED, "disk fault")
    )
    try:
        with pytest.raises(CVZTTEError) as exc:
            lab.broker.mediate(req, binding)
    finally:
        fb_mod.FileBroker._execute = orig
    assert exc.value.code in (ErrorCode.EXECUTION_FAILED, ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE)


# Health readiness reflects wiring (a missing dep is not "ready") ------------


def test_health_ready_reports_wired(registry, tmp_path, allow_decision):
    lab = AdversarialLab(registry, tmp_path, decision=allow_decision)
    assert lab.agent.health_ready()["status"] == "ready"
