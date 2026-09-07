"""Runnable end-to-end demonstration (spec §49 apps/agent-demo, §58 Demo A/E).

Drives two real paths through the integrated stack — the same code the test
suite exercises in ``tests/e2e/test_full_path.py`` — but narrated for a human:

1. **ALLOW path**: a registered agent opens a session, the file broker observes
   the real write, the request is signed with native ML-DSA, the control plane
   evaluates it to ALLOW and mints a short-lived execution-bound Decision Token,
   and the broker independently re-observes + re-validates and executes it. The
   file is written and the hash-chained audit log verifies.

2. **QUARANTINE path**: an admin quarantines the subject (bumping the shared
   capability epoch); a fresh consequential action is then denied with
   ``CONTAINMENT_QUARANTINED`` and **nothing** is executed.

Real components: `OpenSSLMLDSAProvider` identity, `DecisionTokenAuthority` +
`DecisionTokenValidator` over one shared `EpochSource`, `ContainmentEngine`, and
the real `FileBroker` enforcement point with a hash-chained audit log. The OPA
decision is injected here with a fixed ALLOW shim so the demo is deterministic
and offline; the **real** OPA path runs in `apps/gateway` and
`tests/integration/test_opa.py`.

Run:  ``python apps/agent-demo/demo.py``  (after ``source env.sh``)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cvztte.action.model import ActionType, AgentAction, DataClassification  # noqa: E402
from cvztte.adapters.base import AdapterBinding  # noqa: E402
from cvztte.audit import AuditReceiptSink, HashChainedAuditLog  # noqa: E402
from cvztte.containment.engine import ContainmentEngine  # noqa: E402
from cvztte.control_plane import (  # noqa: E402
    AdminAuthorizer,
    AdminPlane,
    AgentPlane,
    ControlPlane,
    DecisionStatus,
)
from cvztte.decision.authority import DecisionTokenAuthority  # noqa: E402
from cvztte.decision.validator import (  # noqa: E402
    DecisionTokenValidator,
    EpochSource,
    PresentedTokenStore,
)
from cvztte.errors import CVZTTEError  # noqa: E402
from cvztte.identity import KeyRegistry, KeyState, OpenSSLMLDSAProvider  # noqa: E402
from cvztte.policy.model import PolicyDecision, RiskTier  # noqa: E402
from cvztte.policy.opa_input import Grant  # noqa: E402
from cvztte.request import RequestBuilder  # noqa: E402
from cvztte.session.model import SessionStore  # noqa: E402
from enforcement.file_broker import FileBroker, FileRequest  # noqa: E402

KEY = b"demo-gateway-only-mac-key-32bytes"[:32]
assert len(KEY) == 32
AGENT = "agt_alice"
RUNTIME = "runtime_1"
ADMIN = "admin_root"


class _FixedOPA:
    """Deterministic ALLOW decision (the real OPA path runs in apps/gateway)."""

    def authorize(self, _input: dict) -> PolicyDecision:
        return PolicyDecision(allow=True, reason_code="ALLOW_OK", risk_level=1)


def _build(workspace: Path):
    provider = OpenSSLMLDSAProvider(workspace / "keystore")
    registry = KeyRegistry(provider)
    registry.register_agent(AGENT)
    registry.generate_key(AGENT, state=KeyState.ACTIVE)

    source = EpochSource()
    authority = DecisionTokenAuthority(KEY)
    presented = PresentedTokenStore()
    containment = ContainmentEngine(epoch_source=source)
    plane = ControlPlane(
        key_registry=registry, session_store=SessionStore(), opa_client=_FixedOPA(),
        authority=authority, presented_store=presented, containment=containment,
        require_approval_from_tier=RiskTier.L4,
    )
    agent = AgentPlane(plane)
    admin = AdminPlane(plane, authorizer=AdminAuthorizer({ADMIN}),
                       key_registry=registry, containment=containment)
    validator = DecisionTokenValidator(mac_key=KEY, epoch_source=source, store=presented)
    workspace_fs = workspace / "fs"
    workspace_fs.mkdir(parents=True, exist_ok=True)
    broker = FileBroker(str(workspace_fs), validator,
                        AuditReceiptSink(HashChainedAuditLog()))
    builder = RequestBuilder(registry)
    return plane, agent, admin, broker, builder, workspace_fs


def _grant() -> Grant:
    return Grant(capabilities={"fs:read", "fs:write"}, resource_scopes={"fs:/"},
                 clearance=DataClassification.CONFIDENTIAL)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cvztte-demo-") as tmp:
        workspace = Path(tmp)
        plane, agent, admin, broker, builder, fs_root = _build(workspace)

        print("== CV-ZTTE agent demo (reference, not production-certified) ==\n")

        # --- Scenario A: legitimate ALLOW path (Demo A) --------------------
        print("[A] Legitimate agent writes a file through the enforced path")
        sess = plane.create_session(agent_id=AGENT, runtime_id=RUNTIME)
        binding = AdapterBinding(agent_id=AGENT, runtime_id=RUNTIME,
                                 session_id=sess.session_id, delegation_id="dlg_1")
        req = FileRequest("report.txt", "write", b"quarterly numbers")
        action = broker.observe(req, binding)  # the broker's own canonical view
        env = builder.build_and_sign(
            agent_id=AGENT, runtime_id=RUNTIME, session_id=sess.session_id,
            delegation_id="dlg_1", policy_hash="sha256:" + "0" * 64,
            action=action, ttl_seconds=30,
        )
        result = agent.evaluate(env, grant=_grant(), audience=broker.audience)
        print(f"    control plane decision: {result.status.name} "
              f"(token minted: {result.token is not None})")
        assert result.status is DecisionStatus.ALLOW and result.token is not None

        outcome = broker.mediate(req, binding)  # independent re-observe + execute
        written = (fs_root / "report.txt").read_bytes()
        print(f"    enforcement outcome: {outcome.receipt.outcome}; "
              f"file contents = {written!r}")
        print(f"    audit chain verifies: {broker._receipts._log.verify()}\n")

        # --- Scenario B: quarantine blocks everything (Demo E) -------------
        print("[E] Admin quarantines the subject; a fresh action is blocked")
        subject = f"{AGENT}|{RUNTIME}|{sess.session_id}"
        admin.quarantine(ADMIN, subject=subject, agent_id=AGENT, runtime_id=RUNTIME)
        blocked_action = AgentAction(
            action_type=ActionType.FILE_WRITE, target="fs:/blocked.txt",
            operation="write", data_classification=DataClassification.INTERNAL,
        )
        env2 = builder.build_and_sign(
            agent_id=AGENT, runtime_id=RUNTIME, session_id=sess.session_id,
            delegation_id="dlg_1", policy_hash="sha256:" + "0" * 64,
            action=blocked_action, ttl_seconds=30,
        )
        try:
            agent.evaluate(env2, grant=_grant(), audience=broker.audience)
            print("    ERROR: quarantined action was NOT blocked")
            return 1
        except CVZTTEError as exc:
            print(f"    control plane denied with: {exc.code.value}")
        existed_before = (fs_root / "blocked.txt").exists()
        print(f"    protected side effect occurred: {existed_before}  "
              f"(expected: False)\n")
        if existed_before:
            return 1

        print("Demo complete: ALLOW path executed + audited; quarantine "
              "fail-closed with zero side effects.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
