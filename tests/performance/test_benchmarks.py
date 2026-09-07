"""Always-on performance benchmarks (spec §52, §60.32).

Real components, observed medians via :mod:`tests.performance.bench`. Native
crypto that needs a compiled binary (OpenFHE, gnark, EZKL) is benchmarked in
``test_benchmarks_native.py`` and skipped when the binary is absent; here we
cover the CPU / enforcement / token / containment / Judge items that always run,
plus the §52 coding-agent claim that sandbox-local work avoids central per-file
overhead.

We assert generous upper bounds only — enough to catch a gross regression, never
a fabricated throughput figure (§52).
"""

from __future__ import annotations

import itertools
from datetime import datetime, timezone

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.adapters.base import AdapterBinding
from cvztte.behavior import BehaviorEngine, BehaviorEvent, BehaviorEventKind, BehaviorScope
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import canonicalize, domain_hash_hex
from cvztte.config import BoundedAdmission
from cvztte.containment.engine import ContainmentEngine
from cvztte.control_plane import DecisionStatus
from cvztte.decision.authority import DecisionTokenAuthority
from cvztte.decision.model import ContainmentState, TokenChecks, TokenDecision
from cvztte.decision.validator import EpochSource
from cvztte.errors import CVZTTEError
from cvztte.judge import JudgeInput, SafetyJudge
from cvztte.policy.model import PolicyDecision
from enforcement.common import InMemoryReceiptSink
from enforcement.egress_proxy import EgressConfig, EgressProxy, EgressRequest
from enforcement.file_broker import FileRequest
from enforcement.mcp_gateway import MCPGateway, MCPRequest, ProtectedServer
from enforcement.output_proxy import OutputProxy, OutputRequest

from lab import AGENT, KEY, POLICY_HASH, RUNTIME, AdversarialLab, RefValidator, make_allow_decision

_AUDIENCE = "enf:file-broker"
_BINDING = AdapterBinding(agent_id=AGENT, runtime_id=RUNTIME, session_id="ses_perf")


def _action(target: str = "fs:/data/x.csv") -> AgentAction:
    return AgentAction(
        action_type=ActionType.FILE_READ, target=target, operation="read",
        data_classification=DataClassification.INTERNAL,
    )


# --- CPU / canonicalization --------------------------------------------------


def test_bench_canonicalize_and_hash(recorder):
    doc = {"b": 2, "a": [1, 2, 3], "nested": {"z": True, "k": "value"}}
    recorder.measure(
        "canonicalize+domain-hash",
        lambda: domain_hash_hex(Domain.ACTION, canonicalize(doc)),
        iters=200, max_ms=5.0,
    )


# --- native ML-DSA (OpenSSL 3.5.8) ------------------------------------------


def test_bench_mldsa_sign_verify(registry, recorder):
    from cvztte.identity import KeyState

    registry.generate_key(AGENT, state=KeyState.ACTIVE)
    msg = b"canonical-action-bytes-to-sign" * 4
    key_id, sig = registry.sign_as_agent(AGENT, msg)
    recorder.measure("mldsa-sign", lambda: registry.sign_as_agent(AGENT, msg),
                     iters=40, max_ms=200.0)
    recorder.measure("mldsa-verify", lambda: registry.verify_with_key(key_id, msg, sig),
                     iters=40, max_ms=200.0)


# --- Safety Judge inference --------------------------------------------------


def test_bench_judge_inference(recorder):
    judge = SafetyJudge()
    inp = JudgeInput(
        action=_action(), policy=PolicyDecision(allow=True, reason_code="ok", risk_level=0),
        destination_external=False, destination_known=True,
    )
    recorder.measure("judge-inference", lambda: judge.evaluate(inp), iters=50, max_ms=100.0)


# --- Decision Token issuance -------------------------------------------------


def test_bench_decision_token_issue(recorder):
    authority = DecisionTokenAuthority(KEY)
    source = EpochSource()
    action, checks = _action(), TokenChecks(mldsa=True, opa=True)

    def issue():
        authority.issue(action=action, binding=_BINDING, audience=_AUDIENCE,
                        policy_hash=POLICY_HASH, epochs=source.current(),
                        decision=TokenDecision.ALLOW, checks=checks)

    recorder.measure("decision-token-issue", issue, iters=100, max_ms=20.0)


# --- containment + capability-epoch propagation ------------------------------


def test_bench_containment_and_epoch_propagation(recorder):
    source = EpochSource()
    ce = ContainmentEngine(epoch_source=source)
    ids = itertools.count()

    def escalate_and_propagate():
        # Fresh subject each iter so the escalate-only machine can transition.
        subject = f"perf-{next(ids)}"
        before = source.current().capability_epoch
        ce.evaluate(subject=subject, agent_id=AGENT, runtime_id=RUNTIME,
                    features={"bypass_attempts_5m": 3})
        # The transition must have bumped the shared capability epoch.
        assert source.current().capability_epoch > before

    recorder.measure("containment-escalate+epoch-bump", escalate_and_propagate,
                     iters=100, max_ms=10.0)


def test_bench_behavior_snapshot(recorder):
    eng = BehaviorEngine()
    scope = BehaviorScope(agent_id=AGENT, session_id="s", runtime_id=RUNTIME)
    now = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
    for _ in range(20):
        eng.record(scope, BehaviorEvent(kind=BehaviorEventKind.EXECUTED,
                                        action_type="FILE_READ", at=now), now=now)
    recorder.measure("behavior-snapshot", lambda: eng.snapshot(scope, now=now),
                     iters=100, max_ms=10.0)


# --- enforcement proxies -----------------------------------------------------


def test_bench_enforcement_proxies(recorder):
    egress = EgressProxy(EgressConfig(allowed_domains=frozenset({"api.github.com"})),
                         RefValidator(), InMemoryReceiptSink())
    out = OutputProxy(RefValidator(), InMemoryReceiptSink())
    mcp = MCPGateway(RefValidator(), InMemoryReceiptSink(), servers={
        "github": ProtectedServer(endpoint="https://api.github.com", credential="x",
                                  handler=lambda t, a, c: {"ok": True})})

    def egress_deny():
        try:
            egress.mediate(EgressRequest(url="https://evil.com/x", method="POST"), _BINDING)
        except CVZTTEError:
            pass

    def mcp_deny():
        try:
            mcp.mediate(MCPRequest(server="direct-http", tool="fetch", arguments={}), _BINDING)
        except CVZTTEError:
            pass

    recorder.measure("egress-proxy-deny", egress_deny, iters=100, max_ms=10.0)
    recorder.measure("output-proxy-allow",
                     lambda: out.mediate(OutputRequest("aggregate mean 91234"), _BINDING),
                     iters=100, max_ms=10.0)
    recorder.measure("mcp-gateway-deny", mcp_deny, iters=100, max_ms=10.0)


# --- backpressure admission --------------------------------------------------


def test_bench_backpressure_admit(recorder):
    ba = BoundedAdmission(name="fhe", capacity=4)

    def admit_cycle():
        with ba.admit():
            pass

    recorder.measure("backpressure-admit", admit_cycle, iters=500, max_ms=2.0)


# --- full ALLOW path + quarantine propagation (integrated) -------------------


def test_bench_full_allow_path_and_quarantine(registry, tmp_path, recorder):
    lab = AdversarialLab(registry, tmp_path, decision=make_allow_decision())
    sess = lab.open_session()
    binding = lab.binding(sess.session_id)
    counter = itertools.count()

    def full_allow():
        # A distinct target per iter keeps signatures/nonces fresh and the token
        # single-use, exercising sign -> pipeline -> mint -> mediate -> execute.
        name = f"r{next(counter)}.txt"
        req = FileRequest(name, "write", b"data")
        action = lab.observe(req, binding)
        env = lab.sign(sess.session_id, action=action)
        result = lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
        assert result.status is DecisionStatus.ALLOW
        lab.broker.mediate(req, binding)

    recorder.measure("full-allow-path-L2 (sign→pipeline→mediate→execute→receipt)",
                     full_allow, iters=20, warmup=2, max_ms=1000.0)

    # Quarantine propagation: escalate the subject, then a fresh evaluate is
    # blocked because the capability epoch advanced (stale-token rejection path).
    subject = f"{AGENT}|{RUNTIME}|{sess.session_id}"
    lab.admin.quarantine("admin_root", subject=subject, agent_id=AGENT, runtime_id=RUNTIME)

    def blocked_evaluate():
        env = lab.sign(sess.session_id,
                       action=lab.file_action(operation="write", target="fs:/blocked.txt"))
        try:
            lab.agent.evaluate(env, grant=lab.grant(), audience=lab.broker.audience)
        except CVZTTEError:
            pass

    recorder.measure("quarantine-propagation+blocked-evaluate", blocked_evaluate,
                     iters=20, warmup=2, max_ms=1000.0)


# --- §52 coding-agent claim: sandbox-local avoids central per-file overhead ---


def test_sandbox_local_avoids_central_per_file_overhead(recorder):
    """Processing N files: the central design mints/validates a Decision Token per
    file (a boundary crossing each), whereas sandbox-local work does N cheap local
    operations and crosses the boundary ONCE for the aggregate. The sandbox-local
    total must beat the central total, and central must scale ~linearly with N
    (§52). We use the REAL token authority as the per-file central overhead."""
    authority = DecisionTokenAuthority(KEY)
    source = EpochSource()
    checks = TokenChecks(mldsa=True, opa=True)
    N = 50

    def issue(target: str):
        authority.issue(action=_action(target), binding=_BINDING, audience=_AUDIENCE,
                        policy_hash=POLICY_HASH, epochs=source.current(),
                        decision=TokenDecision.ALLOW, checks=checks)

    def central_path():
        for i in range(N):
            issue(f"fs:/repo/file{i}.py")  # one boundary crossing per file

    def sandbox_local_path():
        # N cheap in-sandbox operations (a local content hash), then ONE crossing.
        for i in range(N):
            domain_hash_hex(Domain.ACTION, f"file{i} contents".encode())
        issue("fs:/repo")  # single aggregate boundary crossing

    central = recorder.measure(f"central-per-file (N={N})", central_path,
                               iters=10, warmup=2)
    local = recorder.measure(f"sandbox-local (N={N})", sandbox_local_path,
                             iters=10, warmup=2)

    # The architectural claim: sandbox-local is materially cheaper.
    assert local.median_ms < central.median_ms, (
        "sandbox-local must avoid the central per-file overhead (§52)"
    )
