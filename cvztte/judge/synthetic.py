"""Synthetic + adversarial training data for the Safety Judge (spec §29, §60.8).

Training data MUST include synthetic normal behavior, prompt-injection-induced
dangerous actions, exfiltration sequences, bulk access, credential access,
privilege escalation, suspicious external destinations, and benign
administrative exceptions (§60.8). This module both *samples* such scenarios and
provides the deterministic rule labeler that encodes the ground-truth security
judgment the MLP learns to approximate.

The labeler depends only on signals that are also present in the feature vector
(:mod:`cvztte.judge.features`), so the learned model can in principle reproduce
it — and the label ordering is fail-closed: doubtful cases are labeled REVIEW,
clearly hostile cases UNSAFE, never SAFE-by-default.
"""

from __future__ import annotations

import random

from cvztte.action.model import ActionType, AgentAction, DataClassification
from cvztte.containment.model import severity
from cvztte.decision.model import ContainmentState
from cvztte.judge.features import JudgeInput
from cvztte.judge.model import JudgeVerdict
from cvztte.policy.model import PolicyDecision

_RESTRICTED = severity(ContainmentState.RESTRICTED)
_SUSPICIOUS = severity(ContainmentState.SUSPICIOUS)


def label(inp: JudgeInput) -> JudgeVerdict:
    """Ground-truth verdict rule (fail-closed toward the more restrictive class)."""
    at = inp.action.action_type
    is_write = at in {
        ActionType.FILE_WRITE, ActionType.FILE_DELETE, ActionType.MEMORY_WRITE,
        ActionType.DB_OPERATION, ActionType.CLOUD_CONTROL_ACTION,
    }
    is_external = at in {
        ActionType.NETWORK_REQUEST, ActionType.API_REQUEST, ActionType.EXTERNAL_MESSAGE,
    } or inp.destination_external
    is_secret = at is ActionType.SECRET_ACCESS
    is_code_shell = at in {
        ActionType.SHELL_EXEC, ActionType.PROCESS_EXEC, ActionType.CODE_EXECUTION,
    }
    contain = severity(inp.containment_state)

    # --- UNSAFE: active abuse / compromise indicators ---
    if inp.bypass_attempts >= 1:
        return JudgeVerdict.UNSAFE
    if inp.privilege_escalation_attempts >= 1:
        return JudgeVerdict.UNSAFE
    if contain >= _RESTRICTED and (is_write or is_external or is_secret):
        return JudgeVerdict.UNSAFE
    if is_secret and inp.destination_external:
        return JudgeVerdict.UNSAFE  # credential exfiltration
    if is_secret and not inp.has_delegation:
        return JudgeVerdict.UNSAFE
    if inp.sensitive_reads_last_5m >= 5 and (
        inp.external_bytes >= 1_000_000 or inp.new_external_destination >= 2
    ):
        return JudgeVerdict.UNSAFE  # exfiltration sequence
    if inp.destructive_action_count >= 3:
        return JudgeVerdict.UNSAFE
    if is_code_shell and is_external:
        return JudgeVerdict.UNSAFE

    # --- REVIEW: elevated but not conclusively hostile ---
    if inp.policy.require_human_approval:
        return JudgeVerdict.REVIEW
    if contain >= _SUSPICIOUS:
        return JudgeVerdict.REVIEW
    if inp.policy.risk_level >= 3 and (is_write or is_external):
        return JudgeVerdict.REVIEW
    if inp.destination_external and not inp.destination_known:
        return JudgeVerdict.REVIEW
    if is_secret:
        return JudgeVerdict.REVIEW
    if inp.actions_last_60s >= 40:
        return JudgeVerdict.REVIEW  # bulk / high-rate access
    if is_code_shell:
        return JudgeVerdict.REVIEW

    return JudgeVerdict.SAFE


_ALL_ACTIONS = [
    ActionType.FILE_READ, ActionType.FILE_WRITE, ActionType.FILE_DELETE,
    ActionType.MEMORY_READ, ActionType.MEMORY_WRITE, ActionType.DB_OPERATION,
    ActionType.NETWORK_REQUEST, ActionType.API_REQUEST, ActionType.EXTERNAL_MESSAGE,
    ActionType.AGENT_MESSAGE, ActionType.SECRET_ACCESS, ActionType.USER_OUTPUT,
    ActionType.SHELL_EXEC, ActionType.PROCESS_EXEC, ActionType.CODE_EXECUTION,
    ActionType.CLOUD_CONTROL_ACTION, ActionType.TOOL_CALL, ActionType.MCP_CALL,
]
_CLASSES = list(DataClassification)
_STATES = list(ContainmentState)


def _random_input(rng: random.Random, *, adversarial: bool) -> JudgeInput:
    action = AgentAction(
        action_type=rng.choice(_ALL_ACTIONS),
        target="res_" + str(rng.randint(0, 999)),
        operation=rng.choice(["read", "write", "POST", "GET", "exec", None]),
        data_classification=rng.choice(_CLASSES),
    )
    # Adversarial samples bias toward high-risk signals so the classes stay balanced.
    hi = adversarial
    policy = PolicyDecision(
        allow=True,
        reason_code="synthetic",
        risk_level=rng.randint(2, 4) if hi else rng.randint(0, 3),
        require_human_approval=rng.random() < (0.35 if hi else 0.08),
        require_ezkl=rng.random() < 0.3,
    )
    return JudgeInput(
        action=action,
        policy=policy,
        containment_state=rng.choice(_STATES) if hi else ContainmentState.NORMAL,
        destination_external=rng.random() < (0.6 if hi else 0.25),
        destination_known=rng.random() < (0.4 if hi else 0.85),
        has_delegation=rng.random() > (0.25 if hi else 0.03),
        actions_last_10s=rng.randint(0, 25) if hi else rng.randint(0, 8),
        actions_last_60s=rng.randint(0, 80) if hi else rng.randint(0, 30),
        sensitive_reads_last_5m=rng.randint(0, 15) if hi else rng.randint(0, 4),
        external_bytes=rng.choice([0, 1_000, 50_000, 2_000_000, 20_000_000]) if hi else rng.choice([0, 100, 5_000]),
        secret_access_count=rng.randint(0, 6) if hi else rng.randint(0, 1),
        policy_denials=rng.randint(0, 12) if hi else rng.randint(0, 2),
        privilege_escalation_attempts=rng.randint(0, 2) if hi else 0,
        new_external_destination=rng.randint(0, 5) if hi else rng.randint(0, 1),
        destructive_action_count=rng.randint(0, 5) if hi else rng.randint(0, 1),
        agent_message_fanout=rng.randint(0, 15) if hi else rng.randint(0, 3),
        bypass_attempts=rng.randint(0, 2) if hi else 0,
    )


def generate_dataset(n: int = 8000, seed: int = 1337) -> tuple[list[JudgeInput], list[int]]:
    """Deterministic labeled dataset. Half normal, half adversarial-biased."""
    rng = random.Random(seed)
    inputs: list[JudgeInput] = []
    labels: list[int] = []
    from cvztte.judge.model import VERDICT_BY_INDEX

    index_of = {v: i for i, v in enumerate(VERDICT_BY_INDEX)}
    for i in range(n):
        inp = _random_input(rng, adversarial=(i % 2 == 0))
        inputs.append(inp)
        labels.append(index_of[label(inp)])
    return inputs, labels
