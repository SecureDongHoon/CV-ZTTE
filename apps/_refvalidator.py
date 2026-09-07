"""Reference ALLOW validator shared by the broker runner demos (apps/*).

The enforcement brokers apply TWO independent layers: (1) a Decision-Token check
(authenticity / binding / epoch / single-use), and (2) the broker's OWN boundary
controls (path-traversal defense, egress allowlist + byte limits, output DLP,
process allowlist, ...). The token layer is demonstrated end to end in
``apps/agent-demo`` and ``apps/gateway`` with the real ``DecisionTokenValidator``.

These small runner demos focus on layer (2). To reach it deterministically and
offline, they inject this reference validator that echoes an ALLOW whose
constraints exactly match the observed action — the same established pattern used
by ``tests/integration/test_enforcement.py``. It is a demo shim, not part of the
security TCB, and must never be used in a real deployment.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from enforcement.common import AuthorizedDecision, DecisionEffect  # noqa: E402


class ReferenceAllowValidator:
    """Echoes an ALLOW whose constraints match the observed action (demo only)."""

    def __init__(self) -> None:
        self._n = 0

    def authorize(self, *, action, action_hash, binding, audience):
        self._n += 1
        return AuthorizedDecision(
            decision_id=f"demo_{self._n}",
            effect=DecisionEffect.ALLOW,
            action_hash=action_hash,
            target_constraint=action.target,
            operation_constraint=action.operation,
            payload_hash=action.payload_ref.hash if action.payload_ref else None,
            risk_level=1,
            audience=audience,
        )
