"""Runnable Output Proxy (DLP) demo (spec §49 apps/output-proxy, §19).

Exercises the real :class:`OutputProxy` DLP over final user output: DENY on
synthetic-credential patterns and SECRET classification, REDACT on a PII sample
and CONFIDENTIAL, ALLOW otherwise. These run IN ADDITION to the Decision Token
(see ``apps/_refvalidator``).

Run:  ``python apps/output-proxy/run.py``  (after ``source env.sh``)
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "apps"))

from _refvalidator import ReferenceAllowValidator  # noqa: E402
from cvztte.action.model import DataClassification  # noqa: E402
from cvztte.adapters.base import AdapterBinding  # noqa: E402
from cvztte.audit import AuditReceiptSink, HashChainedAuditLog  # noqa: E402
from cvztte.errors import CVZTTEError  # noqa: E402
from enforcement.output_proxy import OutputProxy, OutputRequest  # noqa: E402

BINDING = AdapterBinding(agent_id="agt_alice", runtime_id="runtime_1",
                         session_id="sess_1", delegation_id="dlg_1")


def _try(proxy: OutputProxy, label: str, request: OutputRequest) -> None:
    try:
        out = proxy.mediate(request, BINDING)
        print(f"  {out.receipt.outcome:8} {label}")
    except CVZTTEError as exc:
        print(f"  DENIED   {label}  -> {exc.code.value}")


def main() -> int:
    proxy = OutputProxy(ReferenceAllowValidator(),
                        AuditReceiptSink(HashChainedAuditLog()))
    print("== CV-ZTTE output proxy demo (DLP) ==")
    _try(proxy, "benign text", OutputRequest("the build succeeded"))
    _try(proxy, "PII (email) -> redacted",
         OutputRequest("contact me at alice@example.com please"))
    _try(proxy, "synthetic AWS key -> denied",
         OutputRequest("here is my key AKIAABCDEFGHIJKLMNOP"))
    _try(proxy, "SECRET classification -> denied",
         OutputRequest("internal note", DataClassification.SECRET))
    _try(proxy, "CONFIDENTIAL -> redacted",
         OutputRequest("board summary", DataClassification.CONFIDENTIAL))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
