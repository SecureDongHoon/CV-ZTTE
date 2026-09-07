"""Runnable protected-tool demo (spec §49 apps/protected-tool, §16/§17).

A "protected tool" is a resource that can only be acted on through a mandatory
mediation point — here the real :class:`FileBroker`. This demo shows:

1. a **mediated** write + read succeed (with a valid decision, the broker
   re-observes the real operation and executes it);
2. a **path-traversal escape** is refused (``FILE_PATH_ESCAPE``);
3. a **direct bypass with no Decision Token** is refused by the real
   :class:`DecisionTokenValidator` (``DECISION_TOKEN_INVALID``) — no token, no
   effect.

Run:  ``python apps/protected-tool/run.py``  (after ``source env.sh``)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "apps"))

from _refvalidator import ReferenceAllowValidator  # noqa: E402
from cvztte.adapters.base import AdapterBinding  # noqa: E402
from cvztte.audit import AuditReceiptSink, HashChainedAuditLog  # noqa: E402
from cvztte.decision.validator import (  # noqa: E402
    DecisionTokenValidator,
    EpochSource,
    PresentedTokenStore,
)
from cvztte.errors import CVZTTEError  # noqa: E402
from enforcement.file_broker import FileBroker, FileRequest  # noqa: E402

KEY = b"demo-gateway-only-mac-key-32bytes"[:32]
BINDING = AdapterBinding(agent_id="agt_alice", runtime_id="runtime_1",
                         session_id="sess_1", delegation_id="dlg_1")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cvztte-tool-") as tmp:
        root = Path(tmp) / "protected"
        root.mkdir()
        print("== CV-ZTTE protected-tool demo (mandatory mediation) ==")

        # (1) mediated success via a valid decision.
        broker = FileBroker(str(root), ReferenceAllowValidator(),
                            AuditReceiptSink(HashChainedAuditLog()))
        broker.mediate(FileRequest("notes.txt", "write", b"hello"), BINDING)
        out = broker.mediate(FileRequest("notes.txt", "read"), BINDING)
        contents = (root / "notes.txt").read_bytes()
        print(f"  mediated write+read -> {out.receipt.outcome}, bytes={contents!r}")

        # (2) path-traversal escape is refused.
        try:
            broker.mediate(FileRequest("../../etc/passwd", "read"), BINDING)
            print("  ERROR: traversal was not blocked")
            return 1
        except CVZTTEError as exc:
            print(f"  traversal escape        -> DENY {exc.code.value}")

        # (3) direct bypass with NO Decision Token, via the real validator.
        real = DecisionTokenValidator(mac_key=KEY, epoch_source=EpochSource(),
                                      store=PresentedTokenStore())
        guarded = FileBroker(str(root), real, AuditReceiptSink(HashChainedAuditLog()))
        try:
            guarded.mediate(FileRequest("notes.txt", "read"), BINDING)
            print("  ERROR: tokenless access was not blocked")
            return 1
        except CVZTTEError as exc:
            print(f"  bypass (no token)       -> DENY {exc.code.value}")

        print("Protected tool reachable only through mediation; bypass fails closed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
