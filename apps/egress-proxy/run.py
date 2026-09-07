"""Runnable Network Egress Proxy demo (spec §49 apps/egress-proxy, §18).

Exercises the real :class:`EgressProxy` boundary controls: domain allowlist,
internal/external distinction, and byte limit — enforced IN ADDITION to the
Decision Token (see ``apps/_refvalidator`` for how the token layer is
demonstrated separately). No live network connection is made; the proxy
validates and records the normalized request when no sender is injected.

Run:  ``python apps/egress-proxy/run.py``  (after ``source env.sh``)
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
from enforcement.egress_proxy import EgressConfig, EgressProxy, EgressRequest  # noqa: E402

BINDING = AdapterBinding(agent_id="agt_alice", runtime_id="runtime_1",
                         session_id="sess_1", delegation_id="dlg_1")


def _proxy() -> EgressProxy:
    cfg = EgressConfig(
        allowed_domains=frozenset({"api.ok.example"}),
        internal_domain_suffixes=frozenset({"internal.local"}),
        max_bytes=16,
    )
    return EgressProxy(cfg, ReferenceAllowValidator(),
                       AuditReceiptSink(HashChainedAuditLog()))


def _try(proxy: EgressProxy, label: str, request: EgressRequest) -> None:
    try:
        proxy.mediate(request, BINDING)
        print(f"  ALLOW  {label}")
    except CVZTTEError as exc:
        print(f"  DENY   {label}  -> {exc.code.value}")


def main() -> int:
    proxy = _proxy()
    print("== CV-ZTTE egress proxy demo (boundary controls) ==")
    _try(proxy, "allowlisted GET", EgressRequest("https://api.ok.example/v1"))
    _try(proxy, "non-allowlisted domain", EgressRequest("https://evil.example/x"))
    _try(proxy, "internal host", EgressRequest("http://10.0.0.5/health"))
    _try(proxy, "over byte limit",
         EgressRequest("https://api.ok.example/", method="POST",
                       body=b"this body is definitely too long"))
    _try(proxy, "SECRET egress to external",
         EgressRequest("https://api.ok.example/v1", method="POST", body=b"x",
                       data_classification=DataClassification.SECRET))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
