"""Runnable reference Control-Plane gateway (spec §49 apps/gateway, §60.29).

This is the HTTP entrypoint that Phase 17 implemented as a library
(`cvztte.control_plane.http_api`); here it is wired to the **real** components and
served as a process:

* real native-OpenSSL ML-DSA identity (`KeyRegistry` + `OpenSSLMLDSAProvider`);
* real OPA policy over the pinned `policy/rego` bundle (fail-closed if the `opa`
  binary or bundle is missing — `OPA_UNAVAILABLE`, never an implicit ALLOW);
* the real `ControlPlane` / `AgentPlane` / `AdminPlane` with a shared
  `EpochSource` and a gateway-only Decision-Token MAC key;
* the separated admin plane (admin routes require the `X-CVZTTE-Admin` header).

This is a **reference** server: single process, in-memory stores, HTTP (no TLS),
and the demo Decision-Token MAC key is generated at boot (or read from
`CVZTTE_TOKEN_KEY`). Production terminates TLS, authenticates the admin plane
properly, uses an HSM/KMS-held MAC key, and durable stores — see
`docs/DEPLOYMENT.md` and `docs/FINAL_SECURITY_REVIEW.md` (§29 production gaps).

Run:  ``python apps/gateway/server.py``  (after ``source env.sh``)
Env:  CVZTTE_HOST, CVZTTE_PORT, CVZTTE_KEYSTORE, CVZTTE_POLICY_BUNDLE,
      CVZTTE_ADMINS (comma-separated), CVZTTE_TOKEN_KEY (32 bytes).
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

# Make the repo root importable when run as a plain script.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cvztte.containment.engine import ContainmentEngine  # noqa: E402
from cvztte.control_plane import (  # noqa: E402
    AdminAuthorizer,
    AdminPlane,
    AgentPlane,
    ControlPlane,
)
from cvztte.control_plane.http_api import ControlPlaneAPI, make_server  # noqa: E402
from cvztte.decision.authority import DecisionTokenAuthority  # noqa: E402
from cvztte.decision.validator import EpochSource, PresentedTokenStore  # noqa: E402
from cvztte.identity import KeyRegistry, OpenSSLMLDSAProvider  # noqa: E402
from cvztte.policy.model import RiskTier  # noqa: E402
from cvztte.policy.opa_client import OPAClient  # noqa: E402
from cvztte.session.model import SessionStore  # noqa: E402


def _token_key() -> bytes:
    env = os.environ.get("CVZTTE_TOKEN_KEY")
    if env:
        key = env.encode("utf-8")
        if len(key) != 32:
            raise SystemExit("CVZTTE_TOKEN_KEY must be exactly 32 bytes")
        return key
    # Reference default: an ephemeral per-boot gateway-only MAC key.
    return secrets.token_bytes(32)


def build_api(
    *,
    keystore: Path,
    policy_bundle: Path,
    admins: set[str],
    token_key: bytes,
) -> ControlPlaneAPI:
    """Wire the real control plane and return the HTTP route table."""
    provider = OpenSSLMLDSAProvider(keystore)
    registry = KeyRegistry(provider)

    source = EpochSource()
    authority = DecisionTokenAuthority(token_key)
    presented = PresentedTokenStore()
    containment = ContainmentEngine(epoch_source=source)

    plane = ControlPlane(
        key_registry=registry,
        session_store=SessionStore(),
        opa_client=OPAClient(policy_bundle),
        authority=authority,
        presented_store=presented,
        containment=containment,
        require_approval_from_tier=RiskTier.L4,
    )
    agent = AgentPlane(plane)
    admin = AdminPlane(
        plane,
        authorizer=AdminAuthorizer(admins),
        key_registry=registry,
        containment=containment,
    )
    return ControlPlaneAPI(agent=agent, admin=admin, plane=plane)


def main() -> None:
    host = os.environ.get("CVZTTE_HOST", "127.0.0.1")
    port = int(os.environ.get("CVZTTE_PORT", "8080"))
    keystore = Path(os.environ.get("CVZTTE_KEYSTORE", _REPO_ROOT / ".gateway-keystore"))
    bundle = Path(os.environ.get("CVZTTE_POLICY_BUNDLE", _REPO_ROOT / "policy" / "rego"))
    admins = {a for a in os.environ.get("CVZTTE_ADMINS", "admin_root").split(",") if a}

    keystore.mkdir(parents=True, exist_ok=True)
    api = build_api(
        keystore=keystore, policy_bundle=bundle, admins=admins, token_key=_token_key()
    )
    server = make_server(api, host=host, port=port)
    bound_host, bound_port = server.server_address[:2]
    print(f"CV-ZTTE gateway (reference, not production-certified) on "
          f"http://{bound_host}:{bound_port}")
    print(f"  policy bundle: {bundle}")
    print(f"  admin principals: {sorted(admins)}  (header: X-CVZTTE-Admin)")
    print("  GET /health/live  GET /health/ready  POST /v3/sessions  "
          "POST /v3/actions/evaluate  ...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
