"""OPA client — authoritative deterministic policy evaluation (spec §13).

Evaluates the pinned Rego bundle via the ``opa eval`` CLI over a JSON input and
returns a :class:`PolicyDecision`. Fail-closed rules:

* OPA missing / eval error / malformed output => ``OPA_UNAVAILABLE`` (never an
  implicit ALLOW).
* An undefined ``decision`` (input did not match any rule) => ``OPA_UNAVAILABLE``.
* ``authorize`` raises ``OPA_DENY`` on a hard DENY; hard DENY is final and
  cannot be re-enabled by downstream risk logic (spec §13).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.policy.model import PolicyDecision

DEFAULT_QUERY = "data.cvztte.authz.decision"


def _resolve_opa() -> str:
    found = shutil.which("opa")
    if found:
        return found
    raise CVZTTEError(ErrorCode.OPA_UNAVAILABLE, "opa binary not found")


class OPAClient:
    def __init__(
        self,
        bundle_dir: str | Path,
        *,
        query: str = DEFAULT_QUERY,
        opa_bin: str | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self._bundle = Path(bundle_dir)
        if not self._bundle.exists():
            raise CVZTTEError(ErrorCode.OPA_UNAVAILABLE, "policy bundle path missing")
        self._query = query
        self._opa = opa_bin or _resolve_opa()
        self._timeout = timeout_seconds

    def evaluate(self, input_doc: dict[str, Any]) -> PolicyDecision:
        """Evaluate the policy; return the decision or fail closed."""
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    self._opa, "eval", "-f", "json", "-I",
                    "-d", str(self._bundle), self._query,
                ],
                input=json.dumps(input_doc).encode("utf-8"),
                capture_output=True,
                check=False,
                timeout=self._timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CVZTTEError(
                ErrorCode.OPA_UNAVAILABLE, "opa evaluation failed", detail=str(exc)
            ) from exc

        if proc.returncode != 0:
            raise CVZTTEError(
                ErrorCode.OPA_UNAVAILABLE,
                "opa returned an error",
                detail=proc.stderr.decode(errors="replace"),
            )
        try:
            parsed = json.loads(proc.stdout.decode("utf-8"))
            value = parsed["result"][0]["expressions"][0]["value"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            # Undefined decision or unparseable output => fail closed.
            raise CVZTTEError(
                ErrorCode.OPA_UNAVAILABLE, "opa produced no decision", detail=str(exc)
            ) from exc
        try:
            return PolicyDecision.model_validate(value)
        except Exception as exc:  # noqa: BLE001 - schema drift => fail closed
            raise CVZTTEError(
                ErrorCode.OPA_UNAVAILABLE, "opa decision failed schema", detail=str(exc)
            ) from exc

    def authorize(self, input_doc: dict[str, Any]) -> PolicyDecision:
        """Evaluate and enforce hard DENY (raises ``OPA_DENY``)."""
        decision = self.evaluate(input_doc)
        if not decision.allow:
            raise CVZTTEError(
                ErrorCode.OPA_DENY,
                "policy denied action",
                detail={"reason_code": decision.reason_code, "risk_level": decision.risk_level},
            )
        return decision
