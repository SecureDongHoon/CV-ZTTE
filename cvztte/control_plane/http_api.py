"""HTTP surface for the Control Plane API (spec §60.29).

A dependency-free (stdlib ``http.server``) JSON router that maps the §60.29 route
equivalents onto the :class:`AgentPlane` / :class:`AdminPlane`. The two planes
are kept **separated** at the transport too: admin routes require the
``X-CVZTTE-Admin`` principal header and are gated by the plane's
:class:`AdminAuthorizer`; an agent request can never reach an admin operation.

Everything fails closed (§4.20, §50): a :class:`CVZTTEError` maps to a stable
HTTP status + ``{error_code,error}`` (never leaking internals), an unknown route
is ``404 SCHEMA_INVALID``, a malformed body is ``400 SCHEMA_INVALID``, and any
unexpected exception becomes a generic ``500`` with no detail. This is a
reference server (single process, in-memory stores); production terminates TLS,
authenticates the admin plane properly, and uses durable stores.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote

from cvztte.control_plane.plane import ControlPlane
from cvztte.control_plane.planes import AdminPlane, AgentPlane
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.policy.opa_input import Grant
from cvztte.request.model import SignedEnvelope

#: Max request body (fail-closed against oversized payloads, §60.30).
MAX_BODY_BYTES = 1 * 1024 * 1024

#: ErrorCode -> HTTP status. Anything not listed is a 403 (fail-closed deny).
_STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.SCHEMA_INVALID: 400,
    ErrorCode.DUPLICATE_JSON_KEY: 400,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.ACTION_HASH_MISMATCH: 400,
    ErrorCode.AGENT_UNKNOWN: 404,
    ErrorCode.KEY_UNKNOWN: 404,
    ErrorCode.SESSION_UNKNOWN: 404,
    ErrorCode.OPA_UNAVAILABLE: 503,
    ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE: 503,
    ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE: 503,
}


def status_for(code: ErrorCode) -> int:
    return _STATUS_BY_CODE.get(code, 403)


def _grant_from_body(doc: dict[str, Any]) -> Grant:
    from cvztte.action.model import DataClassification

    return Grant(
        capabilities=set(doc.get("capabilities", [])),
        resource_scopes=set(doc.get("resource_scopes", [])),
        clearance=DataClassification(doc.get("clearance", "INTERNAL")),
        allow_external_network=bool(doc.get("allow_external_network", False)),
        network_allowlist=set(doc.get("network_allowlist", [])),
        shell_permitted=bool(doc.get("shell_permitted", False)),
        secret_access_permitted=bool(doc.get("secret_access_permitted", False)),
        max_db_rows=int(doc.get("max_db_rows", 0)),
        max_external_bytes=int(doc.get("max_external_bytes", 0)),
    )


class ControlPlaneAPI:
    """Route table over the agent/admin planes; the HTTP handler delegates here."""

    def __init__(self, *, agent: AgentPlane, admin: AdminPlane, plane: ControlPlane) -> None:
        self._agent = agent
        self._admin = admin
        self._plane = plane

    # -- dispatch -----------------------------------------------------------

    def dispatch(
        self, method: str, path: str, body: dict[str, Any], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        """Return (status, json_body). Raises only via mapped CVZTTEError."""
        path = unquote(path.split("?", 1)[0])
        # Health (no auth).
        if method == "GET" and path == "/health/live":
            return 200, self._agent.health_live()
        if method == "GET" and path == "/health/ready":
            ready = self._agent.health_ready()
            return (200 if ready["status"] == "ready" else 503), ready

        # Agent plane.
        if method == "POST" and path == "/v3/sessions":
            sess = self._agent.create_session(
                agent_id=body["agent_id"], runtime_id=body["runtime_id"],
                ttl_seconds=body.get("ttl_seconds"),
            )
            return 201, {"session_id": sess.session_id, "agent_id": sess.agent_id,
                         "runtime_id": sess.runtime_id, "expires_at": sess.expires_at.isoformat()}

        if method == "POST" and path == "/v3/actions/evaluate":
            envelope = SignedEnvelope.model_validate(body["envelope"])
            grant = _grant_from_body(body.get("grant", {}))
            result = self._agent.evaluate(
                envelope, grant=grant, audience=body["audience"],
                destination_domain=body.get("destination_domain"),
                row_count=body.get("row_count"), byte_count=body.get("byte_count"),
            )
            return 200, result.public_view()

        if method == "POST" and path == "/v3/actions/evaluate-execute":
            # Requires a broker resolver (native enforcement point); fail closed.
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "evaluate-execute requires a configured enforcement broker",
            )

        m = re.fullmatch(r"/v3/decisions/([\w-]+)", path)
        if method == "GET" and m:
            return 200, self._plane.get_decision(m.group(1)).public_view()

        m = re.fullmatch(r"/v3/agents/([\w|-]+)/containment", path)
        if method == "GET" and m:
            return 200, self._agent.containment_status(m.group(1))

        # Admin plane (principal required).
        m = re.fullmatch(r"/v3/approvals/([\w-]+)", path)
        if method == "POST" and m:
            principal = self._require_admin_header(headers)
            result = self._admin.approve(principal, m.group(1))
            return 200, result.public_view()

        m = re.fullmatch(r"/v3/agents/([\w|-]+)/quarantine", path)
        if method == "POST" and m:
            principal = self._require_admin_header(headers)
            return 200, self._admin.quarantine(
                principal, subject=m.group(1), agent_id=body["agent_id"],
                runtime_id=body.get("runtime_id"),
                reason_codes=body.get("reason_codes"),
                target=ContainmentState(body.get("target", "QUARANTINED")),
            )

        m = re.fullmatch(r"/v3/agents/([\w|-]+)/containment/reset", path)
        if method == "POST" and m:
            from cvztte.containment.engine import RecoveryMethod

            principal = self._require_admin_header(headers)
            return 200, self._admin.reset_containment(
                principal, subject=m.group(1), agent_id=body["agent_id"],
                method=RecoveryMethod(body["method"]), runtime_id=body.get("runtime_id"),
            )

        # Unknown route: fail closed with 404 (never an implicit ALLOW).
        return 404, {"error_code": ErrorCode.SCHEMA_INVALID.value, "error": "unknown route"}

    @staticmethod
    def _require_admin_header(headers: dict[str, str]) -> str:
        principal = headers.get("x-cvztte-admin", "")
        if not principal:
            raise CVZTTEError(
                ErrorCode.ENFORCEMENT_DENIED, "admin principal header required"
            )
        return principal


def _make_handler(api: ControlPlaneAPI) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:  # silence default stderr logging
            return

        def _respond(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > MAX_BODY_BYTES:
                raise CVZTTEError(ErrorCode.PAYLOAD_TOO_LARGE, "request body too large")
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                doc = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "malformed JSON body") from exc
            if not isinstance(doc, dict):
                raise CVZTTEError(ErrorCode.SCHEMA_INVALID, "body must be a JSON object")
            return doc

        def _handle(self, method: str) -> None:
            headers = {k.lower(): v for k, v in self.headers.items()}
            try:
                body = self._read_body() if method == "POST" else {}
                status, payload = api.dispatch(method, self.path, body, headers)
                self._respond(status, payload)
            except CVZTTEError as exc:
                self._respond(status_for(exc.code), exc.public_dict())
            except KeyError as exc:
                # Missing required field => schema error (never leak which internals).
                self._respond(400, {"error_code": ErrorCode.SCHEMA_INVALID.value,
                                    "error": f"missing field: {exc.args[0]}"})
            except Exception:  # noqa: BLE001 - fail closed, never leak internals
                self._respond(500, {"error_code": "INTERNAL", "error": "internal error"})

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

    return Handler


def make_server(
    api: ControlPlaneAPI, *, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    """Build (do not start) a threaded HTTP server bound to host:port."""
    return ThreadingHTTPServer((host, port), _make_handler(api))
