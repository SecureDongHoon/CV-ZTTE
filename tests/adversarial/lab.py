"""Shared harness for the adversarial / failure suite (spec §51, §60.31).

Every DENY case in this suite MUST assert two invariants (§51, §60.31 tail):

* **protected side-effect count = 0** — nothing the attacker tried to do
  actually happened (no file written/deleted, no egress, no secret read);
* **unauthorized plaintext-release count = 0** — no confidential plaintext was
  released.

The :class:`AdversarialLab` wires the real integrated stack — ML-DSA identity, a
real ``DecisionTokenAuthority`` + validator over a shared ``EpochSource``, a real
``ContainmentEngine``, and a real ``FileBroker`` enforcement point — behind the
Phase 17 ``ControlPlane``. Attacks are driven through the same pipeline a real
agent would use, so a defeated attack is provably fail-closed end to end.

OPA has no fake in the tree, so policy is injected as a directly-constructed
``PolicyDecision`` behind a tiny ``authorize()`` shim (the established pattern);
the adversarial cases here target identity / integrity / freshness / token
binding / containment / enforcement, which do not depend on the OPA binary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.audit import AuditReceiptSink, HashChainedAuditLog
from cvztte.containment.engine import ContainmentEngine
from cvztte.control_plane import (
    AdminAuthorizer,
    AdminPlane,
    AgentPlane,
    ControlPlane,
)
from cvztte.decision.authority import DecisionTokenAuthority
from cvztte.decision.model import TokenChecks, TokenDecision
from cvztte.decision.validator import (
    DecisionTokenValidator,
    EpochSource,
    PresentedTokenStore,
)
from cvztte.identity import KeyState
from cvztte.policy.model import PolicyDecision, RiskTier
from cvztte.policy.opa_input import Grant
from cvztte.request import RequestBuilder
from cvztte.session.model import SessionStore
from enforcement.file_broker import FileBroker, FileRequest

KEY = b"advkey-adversarial-suite-32bytes"  # exactly 32 bytes
assert len(KEY) == 32
POLICY_HASH = "sha256:" + "0" * 64
ADMIN = "admin_root"
AGENT = "agt_alice"
RUNTIME = "runtime_1"


class RefValidator:
    """Echoing ALLOW validator (test-only) so broker-internal controls are the
    thing under test. Its constraints exactly match the observed action, so the
    exact-match binding check passes and execution reaches the broker's own DLP /
    allowlist / anti-laundering defenses."""

    def __init__(self, *, effect=None) -> None:
        from enforcement.common import DecisionEffect

        self._effect = effect or DecisionEffect.ALLOW
        self._n = 0

    def authorize(self, *, action, action_hash, binding, audience):
        from enforcement.common import AuthorizedDecision

        self._n += 1
        return AuthorizedDecision(
            decision_id=f"dec_{self._n}", effect=self._effect, action_hash=action_hash,
            target_constraint=action.target, operation_constraint=action.operation,
            payload_hash=action.payload_ref.hash if action.payload_ref else None,
            risk_level=1, audience=audience,
        )


class _FakeOPA:
    """Injects a fixed PolicyDecision (adversarial cases don't test OPA itself)."""

    def __init__(self, decision: PolicyDecision) -> None:
        self._decision = decision

    def authorize(self, input_doc: dict) -> PolicyDecision:
        return self._decision


@dataclass
class SideEffectLedger:
    """Counts real protected side-effects that actually occurred in the workspace."""

    workspace: Path
    baseline: set[Path] = field(default_factory=set)
    plaintext_releases: int = 0

    def snapshot(self) -> None:
        self.baseline = set(self.workspace.rglob("*"))

    @property
    def side_effect_count(self) -> int:
        """Files created/removed since the last snapshot (a write or delete)."""
        now = set(self.workspace.rglob("*"))
        return len(now.symmetric_difference(self.baseline))


class AdversarialLab:
    """The integrated stack an attack is driven through, with invariant counters."""

    def __init__(self, registry, workspace: Path, *, decision: PolicyDecision,
                 policy_hash: str = "") -> None:
        registry.generate_key(AGENT, state=KeyState.ACTIVE)
        self.registry = registry
        self.builder = RequestBuilder(registry)
        self.workspace = workspace
        self.source = EpochSource()
        self.authority = DecisionTokenAuthority(KEY)
        self.store = PresentedTokenStore()
        self.sessions = SessionStore()
        self.containment = ContainmentEngine(epoch_source=self.source)
        self.plane = ControlPlane(
            key_registry=registry, session_store=self.sessions,
            opa_client=_FakeOPA(decision), authority=self.authority,
            presented_store=self.store, containment=self.containment,
            require_approval_from_tier=RiskTier.L4, policy_hash=policy_hash,
        )
        self.agent = AgentPlane(self.plane)
        self.admin = AdminPlane(
            self.plane, authorizer=AdminAuthorizer({ADMIN}),
            key_registry=registry, containment=self.containment,
        )
        # A real enforcement point that re-validates the presented token.
        self.validator = DecisionTokenValidator(
            mac_key=KEY, epoch_source=self.source, store=self.store
        )
        self.broker = FileBroker(
            str(workspace), self.validator, AuditReceiptSink(HashChainedAuditLog())
        )
        self.ledger = SideEffectLedger(workspace)
        self.ledger.snapshot()

    # -- convenience builders ----------------------------------------------

    def open_session(self):
        return self.plane.create_session(agent_id=AGENT, runtime_id=RUNTIME)

    def file_action(self, target: str = "fs:/data/report.csv", operation: str = "read",
                    classification: DataClassification = DataClassification.INTERNAL):
        return AgentAction(
            action_type=ActionType.FILE_READ if operation == "read" else ActionType.FILE_WRITE,
            target=target, operation=operation, data_classification=classification,
        )

    def sign(self, session_id: str, *, action: AgentAction, policy_hash: str = POLICY_HASH,
             delegation_id: str = "dlg_1", ttl_seconds: int = 30, now=None):
        return self.builder.build_and_sign(
            agent_id=AGENT, runtime_id=RUNTIME, session_id=session_id,
            delegation_id=delegation_id, policy_hash=policy_hash, action=action,
            ttl_seconds=ttl_seconds, now=now,
        )

    def grant(self) -> Grant:
        return Grant(
            capabilities={"fs:read", "fs:write"}, resource_scopes={"fs:/"},
            clearance=DataClassification.CONFIDENTIAL,
        )

    def binding(self, session_id: str, *, agent_id: str = AGENT, runtime_id: str = RUNTIME):
        return AdapterBinding(
            agent_id=agent_id, runtime_id=runtime_id, session_id=session_id,
            delegation_id="dlg_1",
        )

    # -- direct token minting (for token-binding attacks) -------------------

    def observe(self, file_req: FileRequest, binding: AdapterBinding):
        """The exact canonical action the broker will re-observe at mediate time."""
        return self.broker.observe(file_req, binding)

    def issue_token(self, *, action, binding, audience=None, decision=TokenDecision.ALLOW,
                    epochs=None, ttl_seconds=None, now=None):
        return self.authority.issue(
            action=action, binding=binding, audience=audience or self.broker.audience,
            policy_hash=POLICY_HASH, epochs=epochs or self.source.current(),
            decision=decision, checks=TokenChecks(mldsa=True, opa=True),
            ttl_seconds=ttl_seconds, now=now,
        )

    def present(self, signed) -> None:
        self.store.present(signed)

    # -- invariant assertions ----------------------------------------------

    def assert_no_side_effects(self) -> None:
        assert self.ledger.side_effect_count == 0, "protected side-effect leaked"
        assert self.ledger.plaintext_releases == 0, "unauthorized plaintext release"


def make_allow_decision() -> PolicyDecision:
    return PolicyDecision(allow=True, reason_code="ALLOW_OK", risk_level=1)
