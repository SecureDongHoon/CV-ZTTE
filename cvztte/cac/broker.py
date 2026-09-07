"""FHE Broker client — the Python↔native-broker seam (spec §36, §40).

Wraps the compiled ``fhe_broker`` C++ executable (``services/fhe-broker/``) as a
narrow subprocess boundary. This client performs **no authorization** — the
control plane runs the full pipeline (identity/OPA/gnark/containment/token) and
only then invokes these methods (§40). The client:

* provisions a registry-controlled CKKS context (agents cannot supply params);
* encrypts / evaluates / decrypts by shelling out to the native broker with an
  argv list (never ``shell=True``);
* pins every ciphertext by a domain-separated hash over its serialized bytes and
  wraps it in a :class:`CiphertextEnvelope` / :class:`ResultEnvelope` (§38);
* fails closed: any non-zero broker exit maps to a ``CVZTTEError`` (never an
  implicit success, §4.20).

Key custody (Phase 14). This foundation is single-key: the broker holds the CKKS
secret key in the context directory and performs ``decrypt`` directly. Genuine
OpenFHE multiparty/threshold decryption — where no single party holds the full
secret key — arrives in Phase 15; see ``docs/FHE_SECURITY_MODEL.md``. Serialized
keys never enter agent context, logs, or audit (§41).
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from cvztte.action.model import DataClassification
from cvztte.cac.context import FHEContext, FHEContextRegistry
from cvztte.cac.envelope import CiphertextEnvelope, ResultEnvelope
from cvztte.cac.program import FHEProgram, FHEProgramRegistry, ProgramId
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit, domain_hash_hex
from cvztte.errors import CVZTTEError, ErrorCode

if TYPE_CHECKING:
    from cvztte.config.profiles import ResourceLimits

_DEFAULT_BINARY = "services/fhe-broker/build/fhe_broker"
_BROKER_TIMEOUT_S = 120


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def default_binary_path() -> str:
    """Locate the compiled broker: ``$CVZTTE_FHE_BROKER`` or the repo default."""
    env = os.environ.get("CVZTTE_FHE_BROKER")
    if env:
        return env
    root = os.environ.get("CVZTTE_ROOT", os.getcwd())
    return str(Path(root) / _DEFAULT_BINARY)


class FHEBrokerClient:
    def __init__(
        self,
        *,
        workspace_root: str,
        context_registry: FHEContextRegistry,
        program_registry: FHEProgramRegistry,
        binary_path: str | None = None,
        resource_limits: ResourceLimits | None = None,
    ) -> None:
        self._binary = binary_path or default_binary_path()
        self._ws = Path(workspace_root)
        self._contexts = context_registry
        self._programs = program_registry
        self._limits = resource_limits

    # -- subprocess ---------------------------------------------------------

    def _run(self, args: list[str]) -> dict:
        if not os.path.exists(self._binary):
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "FHE broker binary not built",
                detail={"path": self._binary},
            )
        try:
            proc = subprocess.run(  # noqa: S603 — fixed binary, list argv, no shell
                [self._binary, *args],
                capture_output=True,
                timeout=_BROKER_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CVZTTEError(ErrorCode.FHE_COMPUTE_TIMEOUT, "FHE broker timed out") from exc
        if proc.returncode != 0:
            # stderr carries the broker's JSON {"error":...}; do not leak stdout.
            raise CVZTTEError(
                ErrorCode.FHE_COMPUTE_FAILED,
                "FHE broker failed",
                detail={"stderr": proc.stderr.decode("utf-8", "replace")[:400]},
            )
        try:
            return json.loads(proc.stdout.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CVZTTEError(ErrorCode.FHE_COMPUTE_FAILED, "unparseable broker output") from exc

    def _context_dir(self, context_id: str) -> Path:
        return self._ws / "contexts" / context_id

    @staticmethod
    def _hash_file(path: Path, domain: Domain) -> str:
        return domain_hash_hex(domain, path.read_bytes())

    def _enforce_ciphertext_size(self, path: Path, *, kind: str) -> None:
        """Reject an oversized ciphertext (§52 resource bound, fail-closed).

        Guards against memory-exhaustion via an outsized ciphertext presented as
        input or produced as output. ``max_ciphertext_bytes == 0`` disables the
        bound. An offending *output* file is removed so nothing dangling remains.
        """
        if self._limits is None or self._limits.max_ciphertext_bytes <= 0:
            return
        size = path.stat().st_size
        if size > self._limits.max_ciphertext_bytes:
            if kind == "output":
                path.unlink(missing_ok=True)
            raise CVZTTEError(
                ErrorCode.FHE_CIPHERTEXT_TOO_LARGE,
                "ciphertext exceeds the deployment resource bound",
                detail={"bytes": size, "limit": self._limits.max_ciphertext_bytes, "kind": kind},
            )

    # -- lifecycle ----------------------------------------------------------

    def provision_context(self, context: FHEContext) -> dict:
        """Materialize the registry context's OpenFHE artifacts. Agent-independent."""
        self._contexts.register(context)
        cdir = self._context_dir(context.context_id)
        cdir.mkdir(parents=True, exist_ok=True)
        out = self._run([
            "gen-context",
            str(cdir),
            str(context.multiplicative_depth),
            str(context.scaling_mod_size),
            str(context.batch_size),
            str(context.ring_dimension),
        ])
        return {
            "context_id": context.context_id,
            "context_hash": context.context_hash(),
            "ring_dimension": out.get("ring_dimension"),
            "context_artifact_hash": self._hash_file(cdir / "context.bin", Domain.FHE_CONTEXT),
        }

    # -- encrypt ------------------------------------------------------------

    def encrypt(
        self,
        *,
        context_id: str,
        expected_context_hash: str,
        values: list[float],
        dataset_id: str,
        owner: str,
        classification: DataClassification,
        allowed_programs: list[ProgramId],
        schema: str = "vector<double>[batch]",
    ) -> tuple[str, CiphertextEnvelope]:
        ctx = self._contexts.require_active(context_id, expected_hash=expected_context_hash)
        ct_id = "ct_" + uuid.uuid4().hex
        ct_path = self._ct_path(context_id, ct_id)
        self._run([
            "encrypt",
            str(self._context_dir(context_id)),
            str(ct_path),
            ",".join(repr(float(v)) for v in values),
        ])
        self._enforce_ciphertext_size(ct_path, kind="output")
        allowed = sorted({p.value for p in allowed_programs})
        envelope = CiphertextEnvelope(
            dataset_id=dataset_id,
            ciphertext_id=ct_id,
            context_id=context_id,
            context_hash=ctx.context_hash(),
            key_epoch=ctx.key_epoch,
            schema=schema,
            classification=classification,
            owner=owner,
            ciphertext_hash=self._hash_file(ct_path, Domain.FHE_CIPHERTEXT),
            created_at=_now(),
            allowed_programs=allowed,
            allowed_program_set_hash=commit(Domain.FHE_PROGRAM, allowed),
        )
        return str(ct_path), envelope

    # -- evaluate -----------------------------------------------------------

    def evaluate(
        self,
        *,
        context_id: str,
        expected_context_hash: str,
        program_id: ProgramId,
        inputs: list[tuple[str, CiphertextEnvelope]],
        weights: list[float] | None = None,
        count: int | None = None,
    ) -> tuple[str, ResultEnvelope]:
        ctx = self._contexts.require_active(context_id, expected_hash=expected_context_hash)
        program = self._programs.require(program_id, context_depth=ctx.multiplicative_depth)
        self._verify_inputs(program, ctx, inputs)

        out_id = "res_" + uuid.uuid4().hex
        out_path = self._ct_path(context_id, out_id)
        args = [
            "evaluate",
            str(self._context_dir(context_id)),
            program_id.value,
            str(out_path),
            *[p for p, _ in inputs],
        ]
        if program.requires_weights:
            if not weights:
                raise CVZTTEError(ErrorCode.FHE_PROGRAM_DENIED, "program requires weights")
            args += ["--weights", ",".join(repr(float(w)) for w in weights)]
        if program.requires_count:
            if not count:
                raise CVZTTEError(ErrorCode.FHE_PROGRAM_DENIED, "program requires count")
            args += ["--count", str(int(count))]
        self._run(args)
        self._enforce_ciphertext_size(out_path, kind="output")

        first = inputs[0][1]
        envelope = ResultEnvelope(
            dataset_id=first.dataset_id,
            ciphertext_id=out_id,
            context_id=context_id,
            context_hash=ctx.context_hash(),
            key_epoch=ctx.key_epoch,
            schema="vector<double>[batch]",
            classification=first.classification,
            owner=first.owner,
            ciphertext_hash=self._hash_file(out_path, Domain.FHE_CIPHERTEXT),
            created_at=_now(),
            allowed_program_set_hash=first.allowed_program_set_hash,
            parent_ciphertext_ids=[env.ciphertext_id for _, env in inputs],
            program_id=program.program_id.value,
            program_version=program.version,
            result_ciphertext_hash=self._hash_file(out_path, Domain.FHE_RESULT),
            lineage_id="lin_" + uuid.uuid4().hex,
        )
        return str(out_path), envelope

    # -- decrypt ------------------------------------------------------------

    def decrypt(self, *, context_id: str, ciphertext_path: str, length: int) -> list[float]:
        """Single-key decrypt (Phase 14). A separate high-risk action (§42).

        Threshold/multiparty decryption replaces this in Phase 15; this direct
        path is used only where the broker legitimately holds the secret key.
        """
        out = self._run([
            "decrypt",
            str(self._context_dir(context_id)),
            str(ciphertext_path),
            str(int(length)),
        ])
        vals = out.get("values")
        if not isinstance(vals, list):
            raise CVZTTEError(ErrorCode.FHE_COMPUTE_FAILED, "decrypt returned no values")
        return [float(v) for v in vals]

    # -- internals ----------------------------------------------------------

    def _ct_path(self, context_id: str, ct_id: str) -> Path:
        d = self._ws / "ciphertexts" / context_id
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{ct_id}.bin"

    def _verify_inputs(
        self,
        program: FHEProgram,
        ctx: FHEContext,
        inputs: list[tuple[str, CiphertextEnvelope]],
    ) -> None:
        if len(inputs) != program.input_arity:
            raise CVZTTEError(
                ErrorCode.FHE_PROGRAM_DENIED, "program input arity mismatch"
            )
        for path, env in inputs:
            # Reject an oversized input ciphertext before touching it (§52).
            self._enforce_ciphertext_size(Path(path), kind="input")
            # Reject context / key-epoch substitution (§38).
            if env.context_id != ctx.context_id or env.context_hash != ctx.context_hash():
                raise CVZTTEError(
                    ErrorCode.FHE_CONTEXT_MISMATCH, "input ciphertext context mismatch"
                )
            if env.key_epoch != ctx.key_epoch:
                raise CVZTTEError(
                    ErrorCode.FHE_KEY_EPOCH_MISMATCH, "input ciphertext key epoch mismatch"
                )
            # Reject ciphertext substitution: bytes must still match the envelope,
            # and the envelope's own allowed-program set must be intact.
            actual = self._hash_file(Path(path), Domain.FHE_CIPHERTEXT)
            if actual != env.ciphertext_hash:
                raise CVZTTEError(
                    ErrorCode.FHE_CIPHERTEXT_INVALID, "ciphertext bytes do not match envelope"
                )
            if commit(Domain.FHE_PROGRAM, sorted(env.allowed_programs)) != env.allowed_program_set_hash:
                raise CVZTTEError(
                    ErrorCode.FHE_CIPHERTEXT_INVALID, "allowed-program set hash mismatch"
                )
            # The program must be in the ciphertext's allowed-program set (§38).
            if not env.allows_program(program.program_id.value):
                raise CVZTTEError(
                    ErrorCode.FHE_PROGRAM_DENIED, "program not in ciphertext allowed set"
                )
