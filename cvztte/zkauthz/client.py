"""Fail-closed subprocess client for the ``zk-authz`` Go service (spec §14, §60.5).

Security properties enforced here:

* The verifier ALWAYS uses the registry-pinned artifact directory; there is no
  argument by which a caller supplies its own verification key (spec §14).
* Any subprocess/binary failure maps to ``SECURITY_DEPENDENCY_UNAVAILABLE`` and
  never to an implicit "verified" (fail closed, spec §4.20).
* A proof that does not verify raises ``GNARK_PROOF_INVALID`` from
  :meth:`ZKAuthzClient.authorize`.
* The verification-key hash returned by the service is cross-checked against the
  registry pin; a mismatch is ``GNARK_ARTIFACT_UNAPPROVED``.
* Credential issuance is a trusted-admin operation, exposed separately.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.zkauthz.registry import ZKRegistry

_ENV_BIN = "CVZTTE_ZKAUTHZ_BIN"
_DEFAULT_TIMEOUT = 60.0


def _resolve_binary(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get(_ENV_BIN)
    if env:
        return env
    found = shutil.which("zk-authz")
    if found:
        return found
    # Conventional build location within the repo.
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "services" / "zk-authz" / "bin" / "zk-authz"
        if candidate.is_file():
            return str(candidate)
    raise CVZTTEError(
        ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
        "zk-authz binary not found",
        detail={"hint": f"set {_ENV_BIN} or build services/zk-authz"},
    )


@dataclass(frozen=True)
class Assignment:
    """Full witness for one proof; all values are BN254 scalars (ints)."""

    # public
    agent_hi: int
    agent_lo: int
    credential_commitment: int
    required_capability: int
    required_clearance: int
    current_epoch: int
    action_hi: int
    action_lo: int
    policy_hi: int
    policy_lo: int
    scope_hi: int
    scope_lo: int
    circuit_ver: int
    session_binding: int
    # private
    capability: int
    clearance: int
    expiry_epoch: int
    salt: int

    def _payload(self, artifact_dir: str) -> dict[str, str]:
        d = {k: str(v) for k, v in asdict(self).items()}
        d["artifact_dir"] = artifact_dir
        return d


class ZKAuthzClient:
    def __init__(
        self,
        registry: ZKRegistry,
        *,
        binary: str | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._registry = registry
        self._bin = _resolve_binary(binary)
        self._timeout = timeout_seconds

    # -- subprocess plumbing -------------------------------------------------

    def _run(self, subcommand: str, payload: dict | None) -> dict:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._bin, subcommand],
                input=(json.dumps(payload).encode("utf-8") if payload is not None else None),
                capture_output=True,
                check=False,
                timeout=self._timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "zk-authz invocation failed",
                detail={"subcommand": subcommand, "error": str(exc)},
            ) from exc

        stdout = proc.stdout.decode("utf-8", "replace").strip()
        last = stdout.splitlines()[-1] if stdout else ""
        try:
            result = json.loads(last) if last else {}
        except ValueError as exc:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "zk-authz produced non-JSON output",
                detail={"subcommand": subcommand},
            ) from exc

        if proc.returncode != 0 or "error" in result:
            raise CVZTTEError(
                ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
                "zk-authz reported an error",
                detail={
                    "subcommand": subcommand,
                    "returncode": proc.returncode,
                    "error": result.get("error"),
                },
            )
        return result

    # -- operations ----------------------------------------------------------

    def issue(self, payload: dict[str, int]) -> dict[str, str]:
        """Trusted-admin path: compute credential_commitment + session_binding.

        ``payload`` provides agent_hi/lo, capability, clearance, expiry_epoch,
        scope_hi/lo, policy_hi/lo, salt, action_hi/lo, epoch, circuit_ver.
        """
        return self._run("issue", {k: str(v) for k, v in payload.items()})

    def prove(self, assignment: Assignment) -> tuple[str, str]:
        """Produce (proof_b64, public_witness_b64) for ``assignment``."""
        result = self._run("prove", assignment._payload(self._registry.artifact_dir))
        return result["proof"], result["public_witness"]

    def verify(self, proof_b64: str, public_witness_b64: str) -> bool:
        """Verify a proof against the registry-pinned VK. Returns bool.

        The artifact directory (hence the VK) comes from the registry, NOT the
        caller. Also cross-checks the service-reported VK hash against the pin.
        """
        result = self._run(
            "verify",
            {
                "artifact_dir": self._registry.artifact_dir,
                "proof": proof_b64,
                "public_witness": public_witness_b64,
            },
        )
        reported = result.get("verification_key_hash")
        if reported != self._registry.verification_key_hash:
            raise CVZTTEError(
                ErrorCode.GNARK_ARTIFACT_UNAPPROVED,
                "verification key hash does not match registry pin",
                detail={
                    "pinned": self._registry.verification_key_hash,
                    "reported": reported,
                },
            )
        return bool(result.get("verified", False))

    def authorize(self, proof_b64: str, public_witness_b64: str) -> None:
        """Verify and raise ``GNARK_PROOF_INVALID`` if the proof does not hold."""
        if not self.verify(proof_b64, public_witness_b64):
            raise CVZTTEError(
                ErrorCode.GNARK_PROOF_INVALID, "authorization proof did not verify"
            )
