"""Pre-activation conformance harness (spec §33, §60.14).

Before an agent may reach ``ENFORCED`` the platform MUST *automatically verify*
that mandatory enforcement actually works for it (§60.14). This harness wires a
real enforcement point (a :class:`FileBroker` over a throwaway workspace) to the
real Decision Token authority/validator/epoch source and containment engine, and
runs the §33/§60.14 conformance checks against that live wiring — no mocks on the
acceptance path:

* **direct bypass blocked** — an un-mediated / un-tokened request is denied;
* **mediated happy path** — an approved, exact-bound token executes;
* **mediated deny** — a DENY token does not execute;
* **token exact binding** — a token minted for action A cannot execute action B
  (invariant §4.11);
* **adapter context** — if a semantic adapter is declared it is recorded (an
  absent adapter is the allowed unknown-framework fallback, not a failure, §33);
* **kill switch** — an administrative kill invalidates in-flight authority (the
  capability epoch advances and the presented token is rejected as stale).

Any failed mandatory check ⇒ activation is blocked fail-closed (§60.14). The
harness never weakens a control to make a check pass.
"""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from cvztte.adapters.base import AdapterBinding
from cvztte.audit.log import HashChainedAuditLog
from cvztte.audit.sink import AuditReceiptSink
from cvztte.containment.engine import ContainmentEngine
from cvztte.decision.authority import DecisionTokenAuthority
from cvztte.decision.model import ContainmentState, EpochSet, TokenChecks, TokenDecision
from cvztte.decision.validator import (
    DecisionTokenValidator,
    EpochSource,
    PresentedTokenStore,
)
from cvztte.errors import CVZTTEError
from cvztte.onboarding.profile import AgentRuntimeProfile
from enforcement.file_broker import FileBroker, FileRequest


class ConformanceCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    passed: bool
    detail: str = ""


class ConformanceReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    runtime_id: str
    checks: list[ConformanceCheck]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def failures(self) -> list[str]:
        return [c.name for c in self.checks if not c.passed]


class ConformanceHarness:
    """Runs the §60.14 pre-activation conformance checks against live enforcement."""

    def __init__(self, profile: AgentRuntimeProfile) -> None:
        self._profile = profile

    def run(self) -> ConformanceReport:
        checks: list[ConformanceCheck] = []
        # Isolated throwaway workspace + fresh gateway-only key per run.
        with tempfile.TemporaryDirectory(prefix="cvztte-conformance-") as tmp:
            key = secrets.token_bytes(32)
            binding = AdapterBinding(
                agent_id=self._profile.agent_id,
                runtime_id=self._profile.runtime_id,
                session_id="ses_conformance",
            )
            checks.append(self._check_bypass_blocked(tmp, key))
            checks.append(self._check_happy_path(tmp, key, binding))
            checks.append(self._check_mediated_deny(tmp, key, binding))
            checks.append(self._check_exact_binding(tmp, key, binding))
            checks.append(self._check_adapter_context())
            checks.append(self._check_kill_switch(tmp, key, binding))
        return ConformanceReport(
            agent_id=self._profile.agent_id,
            runtime_id=self._profile.runtime_id,
            checks=checks,
        )

    # -- wiring helpers ------------------------------------------------------

    def _wiring(self, workspace: str, key: bytes, *, epochs: EpochSet | None = None):
        epochs = epochs or EpochSet()
        source = EpochSource(epochs)
        store = PresentedTokenStore()
        authority = DecisionTokenAuthority(key)
        validator = DecisionTokenValidator(mac_key=key, epoch_source=source, store=store)
        sink = AuditReceiptSink(HashChainedAuditLog())
        broker = FileBroker(workspace, validator, sink)
        return authority, store, source, broker

    def _present(self, authority, store, broker, binding, req, *, epochs, **kw):
        action = broker.observe(req, binding)
        signed = authority.issue(
            action=action,
            binding=binding,
            audience=broker.audience,
            policy_hash=self._profile.policy_hash,
            epochs=epochs,
            checks=TokenChecks(
                mldsa=True, opa=True, gnark=True, behavior=True, judge="SAFE", ezkl=True
            ),
            **kw,
        )
        store.present(signed)
        return signed

    # -- checks --------------------------------------------------------------

    def _check_bypass_blocked(self, ws: str, key: bytes) -> ConformanceCheck:
        # A request that reaches the broker with no token must be denied.
        _, _, _, broker = self._wiring(ws, key)
        binding = AdapterBinding(
            agent_id=self._profile.agent_id, runtime_id=self._profile.runtime_id,
            session_id="ses_conformance",
        )
        try:
            broker.mediate(FileRequest("bypass.txt", "write", b"x"), binding)
        except CVZTTEError as exc:
            return ConformanceCheck(
                name="direct_bypass_blocked", passed=True, detail=exc.code.value
            )
        return ConformanceCheck(
            name="direct_bypass_blocked", passed=False,
            detail="un-tokened request was NOT denied",
        )

    def _check_happy_path(self, ws: str, key: bytes, binding) -> ConformanceCheck:
        authority, store, _, broker = self._wiring(ws, key)
        req = FileRequest("ok.txt", "write", b"hello")
        self._present(authority, store, broker, binding, req, epochs=EpochSet())
        try:
            out = broker.mediate(req, binding)
        except CVZTTEError as exc:
            return ConformanceCheck(
                name="mediated_happy_path", passed=False, detail=exc.code.value
            )
        ok = out.receipt.outcome == "EXECUTED"
        return ConformanceCheck(
            name="mediated_happy_path", passed=ok, detail=out.receipt.outcome
        )

    def _check_mediated_deny(self, ws: str, key: bytes, binding) -> ConformanceCheck:
        authority, store, _, broker = self._wiring(ws, key)
        req = FileRequest("deny.txt", "write", b"x")
        self._present(
            authority, store, broker, binding, req,
            epochs=EpochSet(), decision=TokenDecision.DENY,
        )
        try:
            broker.mediate(req, binding)
        except CVZTTEError as exc:
            return ConformanceCheck(
                name="mediated_deny", passed=True, detail=exc.code.value
            )
        return ConformanceCheck(
            name="mediated_deny", passed=False, detail="DENY token executed",
        )

    def _check_exact_binding(self, ws: str, key: bytes, binding) -> ConformanceCheck:
        # §4.11: a token minted for action A must not authorize action B.
        authority, store, _, broker = self._wiring(ws, key)
        req_a = FileRequest("a.txt", "write", b"x")
        self._present(authority, store, broker, binding, req_a, epochs=EpochSet())
        req_b = FileRequest("b.txt", "write", b"x")
        try:
            broker.mediate(req_b, binding)
        except CVZTTEError as exc:
            passed = not (Path(ws) / "b.txt").exists()
            return ConformanceCheck(
                name="decision_token_exact_binding", passed=passed, detail=exc.code.value
            )
        return ConformanceCheck(
            name="decision_token_exact_binding", passed=False,
            detail="token for A executed action B",
        )

    def _check_adapter_context(self) -> ConformanceCheck:
        # An installed adapter must be declared; absent adapter is the allowed
        # unknown-framework fallback (boundary-only context), not a failure (§33).
        adapter = self._profile.semantic_adapter
        if adapter:
            return ConformanceCheck(
                name="adapter_context", passed=True, detail=f"adapter={adapter}"
            )
        return ConformanceCheck(
            name="adapter_context", passed=True,
            detail="no adapter (unknown-framework fallback: boundary-only)",
        )

    def _check_kill_switch(self, ws: str, key: bytes, binding) -> ConformanceCheck:
        # An administrative kill must invalidate in-flight authority: the
        # capability epoch advances and the presented token is rejected as stale.
        epochs = EpochSet()
        authority, store, source, broker = self._wiring(ws, key, epochs=epochs)
        engine = ContainmentEngine(epoch_source=source)
        req = FileRequest("kill.txt", "write", b"x")
        self._present(authority, store, broker, binding, req, epochs=epochs)
        subject = f"{binding.agent_id}|{binding.runtime_id}|{binding.session_id}"
        engine.kill_switch(
            subject=subject, agent_id=binding.agent_id,
            runtime_id=binding.runtime_id,
            target_state=ContainmentState.QUARANTINED,
            reason_codes=["CONFORMANCE_KILL_TEST"],
        )
        killed = engine.state(subject) is ContainmentState.QUARANTINED
        try:
            broker.mediate(req, binding)
        except CVZTTEError as exc:
            passed = killed and not (Path(ws) / "kill.txt").exists()
            return ConformanceCheck(
                name="kill_switch", passed=passed, detail=exc.code.value
            )
        return ConformanceCheck(
            name="kill_switch", passed=False,
            detail="token still executed after kill switch",
        )
