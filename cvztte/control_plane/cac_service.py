"""CAC surface of the Control Plane (spec §35-§47, §60.29 CAC endpoints).

Composes the already-tested CAC primitives into the encrypt / compute /
decrypt-request / result endpoints, wiring in the three cross-cutting controls
Phase 17 must integrate:

* the **permission guard** at the *current containment state* (§42, §47) — every
  operation is gated by READ_PLAINTEXT / COMPUTE_ON_CIPHERTEXT / DECRYPT_RESULT
  after containment decay, and compute never implies decrypt;
* **data lineage** (§60.24) — every ciphertext, result, decrypt request, and
  release is recorded (hashes/IDs only) so a released value is fully traceable;
* **Confidential Query Governance** (§45) + the **release gate** (§60.26) at
  decrypt time — inference-leakage limits and result-substitution/approval
  checks, fail-closed.

This service performs **no** identity/policy/token authorization itself — the
:class:`~cvztte.control_plane.plane.ControlPlane` runs that pipeline first (§35,
§40). It never persists a secret key or plaintext beyond the released,
governed result value.
"""

from __future__ import annotations

import enum
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cvztte.action.model import DataClassification
from cvztte.cac.broker import FHEBrokerClient
from cvztte.cac.envelope import CiphertextEnvelope, ResultEnvelope
from cvztte.cac.guard import require_compute, require_read_plaintext
from cvztte.cac.permissions import CACPermission
from cvztte.cac.program import ProgramId
from cvztte.cac.threshold.release import DecryptReleaseRequest, ThresholdReleasePolicy
from cvztte.confidential_query.governance import QueryGovernor
from cvztte.confidential_query.models import QueryRequest
from cvztte.control_plane.approval import ApprovalStore
from cvztte.decision.model import ContainmentState
from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.lineage.graph import LineageGraph


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DecryptStatus(str, enum.Enum):
    RELEASED = "RELEASED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


class CACService:
    """Confidential Analytics & Compute surface (§60.29 CAC endpoints)."""

    def __init__(
        self,
        *,
        broker: FHEBrokerClient | None,
        lineage: LineageGraph | None = None,
        governor: QueryGovernor | None = None,
        release_policy: ThresholdReleasePolicy | None = None,
        approvals: ApprovalStore | None = None,
    ) -> None:
        self._broker = broker
        self._lineage = lineage or LineageGraph()
        self._governor = governor or QueryGovernor()
        self._release = release_policy or ThresholdReleasePolicy()
        self._approvals = approvals or ApprovalStore()
        self._lock = threading.Lock()
        #: request_id -> parked decrypt context awaiting approval.
        self._pending: dict[str, dict[str, Any]] = {}
        #: result_id -> released, governed plaintext values (never raw ciphertext).
        self._results: dict[str, dict[str, Any]] = {}

    @property
    def lineage(self) -> LineageGraph:
        return self._lineage

    def _require_broker(self) -> FHEBrokerClient:
        if self._broker is None:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE, "FHE broker not configured"
            )
        return self._broker

    # -- encrypt ------------------------------------------------------------

    def encrypt(
        self,
        *,
        granted: frozenset[CACPermission],
        containment_state: ContainmentState,
        context_id: str,
        expected_context_hash: str,
        values: list[float],
        dataset_id: str,
        owner: str,
        classification: DataClassification,
        allowed_programs: list[ProgramId],
    ) -> dict[str, Any]:
        """POST /v3/cac/encrypt — encrypting plaintext requires READ_PLAINTEXT (§35)."""
        require_read_plaintext(granted, containment_state)
        broker = self._require_broker()
        ct_path, env = broker.encrypt(
            context_id=context_id, expected_context_hash=expected_context_hash,
            values=values, dataset_id=dataset_id, owner=owner,
            classification=classification, allowed_programs=allowed_programs,
        )
        node = self._lineage.record_ciphertext(
            dataset_id=dataset_id, ciphertext_id=env.ciphertext_id,
            ciphertext_hash=env.ciphertext_hash, classification=classification.value,
            context_id=context_id, key_epoch=env.key_epoch,
        )
        return {"ciphertext_id": env.ciphertext_id, "ciphertext_path": ct_path,
                "envelope": env.model_dump(mode="json"), "lineage_node": node}

    # -- compute ------------------------------------------------------------

    def compute(
        self,
        *,
        granted: frozenset[CACPermission],
        containment_state: ContainmentState,
        context_id: str,
        expected_context_hash: str,
        program_id: ProgramId,
        inputs: list[tuple[str, CiphertextEnvelope]],
        weights: list[float] | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """POST /v3/cac/compute — compute-on-ciphertext; never implies decrypt (§42)."""
        require_compute(granted, containment_state)
        broker = self._require_broker()
        out_path, env = broker.evaluate(
            context_id=context_id, expected_context_hash=expected_context_hash,
            program_id=program_id, inputs=inputs, weights=weights, count=count,
        )
        node = self._lineage.record_result(
            parent_ciphertext_ids=[p.ciphertext_id for _, p in inputs],
            program_id=env.program_id, program_version=env.program_version,
            result_id=env.ciphertext_id, result_hash=env.result_ciphertext_hash,
            lineage_id=env.lineage_id,
        )
        return {"result_id": env.ciphertext_id, "result_path": out_path,
                "envelope": env.model_dump(mode="json"), "lineage_node": node}

    # -- decrypt-request ----------------------------------------------------

    def decrypt_request(
        self,
        *,
        granted: frozenset[CACPermission],
        containment_state: ContainmentState,
        context_id: str,
        result_envelope: ResultEnvelope,
        result_path: str,
        length: int,
        recipient: str,
        purpose: str,
        query: QueryRequest,
        approval_granted: bool = False,
        approval_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """POST /v3/cac/decrypt-requests — gate, govern, and (if cleared) release.

        Order (fail-closed at each step): DECRYPT_RESULT after containment decay →
        query governance (inference-leakage limits) → release gate
        (result-substitution + approval) → decrypt → record release. If the
        classification requires approval and none is granted, the request is
        parked ``PENDING_APPROVAL`` and NO plaintext is produced.
        """
        now = now or _utcnow()
        classification = result_envelope.classification
        request_id = "dreq_" + uuid.uuid4().hex

        # Always record the decrypt request in lineage (even if later denied).
        self._lineage.record_decrypt_request(
            result_id=result_envelope.ciphertext_id, request_id=request_id,
            requester=recipient, purpose=purpose,
        )

        # 1. Confidential Query Governance (§45) — inference-leakage limits.
        governance = self._governor.evaluate(query)
        if not governance.allowed:
            raise CVZTTEError(
                governance.reason or ErrorCode.FHE_QUERY_PATTERN_RISK,
                governance.message or "query governance denied release",
            )

        # 2. Release gate (§60.26). Read the bytes about to be fused for the
        #    substitution check; require approval for restricted classifications.
        result_bytes = Path(result_path).read_bytes()
        release_req = DecryptReleaseRequest(
            recipient=recipient, purpose=purpose, classification=classification,
            granted=granted, containment_state=containment_state,
            result_ciphertext_bytes=result_bytes,
            expected_result_hash=result_envelope.result_ciphertext_hash,
            approval_granted=approval_granted, approval_id=approval_id,
        )
        try:
            self._release.authorize(release_req)
        except CVZTTEError as exc:
            if exc.code is ErrorCode.APPROVAL_REQUIRED and not approval_granted:
                # Park for human approval; produce no plaintext (fail-closed).
                self._approvals.request(
                    decision_id=request_id, agent_id=recipient,
                    action_hash=result_envelope.result_ciphertext_hash,
                    risk_level=4, classification=classification.value, now=now,
                )
                with self._lock:
                    self._pending[request_id] = {
                        "granted": granted, "containment_state": containment_state,
                        "context_id": context_id, "result_envelope": result_envelope,
                        "result_path": result_path, "length": length,
                        "recipient": recipient, "purpose": purpose, "query": query,
                    }
                return {"request_id": request_id,
                        "status": DecryptStatus.PENDING_APPROVAL.value,
                        "reason_code": ErrorCode.APPROVAL_REQUIRED.value}
            raise

        return self._release_now(
            request_id=request_id, granted=granted, containment_state=containment_state,
            context_id=context_id, result_envelope=result_envelope,
            result_path=result_path, length=length, recipient=recipient, query=query,
        )

    def approve_decrypt(
        self, request_id: str, *, approver: str, now: datetime | None = None
    ) -> dict[str, Any]:
        """POST /v3/cac/decrypt-requests/{id}/approve — grant, then release."""
        now = now or _utcnow()
        with self._lock:
            ctx = self._pending.get(request_id)
        if ctx is None:
            raise CVZTTEError(ErrorCode.APPROVAL_REQUIRED, "unknown decrypt request")
        self._approvals.grant(request_id, approver=approver, now=now)
        self._approvals.assert_granted(request_id, now=now)

        # Re-run the release gate with approval granted (containment re-checked).
        result_envelope: ResultEnvelope = ctx["result_envelope"]
        result_bytes = Path(ctx["result_path"]).read_bytes()
        self._release.authorize(
            DecryptReleaseRequest(
                recipient=ctx["recipient"], purpose=ctx["purpose"],
                classification=result_envelope.classification, granted=ctx["granted"],
                containment_state=ctx["containment_state"],
                result_ciphertext_bytes=result_bytes,
                expected_result_hash=result_envelope.result_ciphertext_hash,
                approval_granted=True, approval_id=request_id,
            )
        )
        out = self._release_now(
            request_id=request_id, granted=ctx["granted"],
            containment_state=ctx["containment_state"], context_id=ctx["context_id"],
            result_envelope=result_envelope, result_path=ctx["result_path"],
            length=ctx["length"], recipient=ctx["recipient"], query=ctx["query"],
            approval_id=request_id,
        )
        with self._lock:
            self._pending.pop(request_id, None)
        return out

    def _release_now(
        self, *, request_id: str, granted, containment_state, context_id,
        result_envelope: ResultEnvelope, result_path: str, length: int,
        recipient: str, query: QueryRequest, approval_id: str | None = None,
    ) -> dict[str, Any]:
        broker = self._require_broker()
        values = broker.decrypt(
            context_id=context_id, ciphertext_path=result_path, length=length
        )
        # Governance minimization (rounding) + record the query for future accounting.
        governance = self._governor.governed_release(query)
        values = self._governor.minimize(values, governance)

        result_id = "released_" + uuid.uuid4().hex
        self._lineage.record_release(
            request_id=request_id, release_id=result_id, recipient=recipient,
            released_hash=result_envelope.result_ciphertext_hash, approval_id=approval_id,
        )
        with self._lock:
            self._results[result_id] = {
                "values": values, "recipient": recipient,
                "released_at": _utcnow().isoformat(),
                "result_ciphertext_id": result_envelope.ciphertext_id,
            }
        return {"request_id": request_id, "status": DecryptStatus.RELEASED.value,
                "result_id": result_id, "values": values}

    def get_result(self, result_id: str) -> dict[str, Any]:
        """GET /v3/cac/results/{id} — the released, governed plaintext values."""
        with self._lock:
            rec = self._results.get(result_id)
        if rec is None:
            raise CVZTTEError(ErrorCode.FHE_DECRYPT_DENIED, "unknown or unreleased result")
        return {"result_id": result_id, **rec}
