"""Threshold key ceremony + decrypt coordinator (spec §41, §42, §60.25).

Two orchestrators that drive a genuine OpenFHE **N-of-N** multiparty protocol
across a set of :class:`~cvztte.cac.threshold.authority.KeyAuthority` participants
(or their subprocess proxies). Neither orchestrator ever sees a secret share:

* :class:`ThresholdKeyCeremony` generates a joint public key + joint eval-sum
  keys by chaining each participant's key-gen round, then installs **only the
  public material** into the shared context directory. Each secret share is
  written by the broker into that party's own directory and stays there.
* :class:`DecryptCoordinator` performs distributed decryption: it applies the
  release policy (§60.26), collects one partial decryption from **every** party
  (lead first), fuses them via the broker, and returns the plaintext to the
  authorized recipient. Missing any party → ``FHE_THRESHOLD_INSUFFICIENT``.

The coordinator handles only ciphertexts and partial-decryption artifacts —
standard protocol messages that do not reveal any secret key (§41).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Protocol

from cvztte.cac.broker import default_binary_path
from cvztte.cac.context import FHEContext
from cvztte.cac.subprocess_util import run_broker_json
from cvztte.cac.threshold.release import DecryptReleaseRequest, ThresholdReleasePolicy
from cvztte.errors import CVZTTEError, ErrorCode


class Participant(Protocol):
    """The operations a threshold participant must expose (in-process or remote)."""

    party_id: str

    def keygen_lead(self, *, context_dir: str, out_pub: str, out_evalsum: str) -> dict: ...

    def keygen_join(
        self,
        *,
        context_dir: str,
        prev_pub: str,
        prev_evalsum: str,
        out_pub: str,
        out_evalsum: str,
    ) -> dict: ...

    def partial_decrypt(
        self, *, context_dir: str, ciphertext_path: str, out_partial: str, lead: bool
    ) -> dict: ...


class ThresholdKeyCeremony:
    """Runs the multiparty key-generation ceremony across ordered participants."""

    def __init__(
        self,
        *,
        participants: list[Participant],
        workspace_root: str | Path,
        binary_path: str | None = None,
    ) -> None:
        if len(participants) < 2:
            raise CVZTTEError(
                ErrorCode.FHE_THRESHOLD_INSUFFICIENT,
                "threshold key ceremony requires at least 2 participants",
            )
        self._participants = participants
        self._ws = Path(workspace_root)
        self._binary = binary_path or default_binary_path()

    def provision(self, context: FHEContext) -> dict:
        """Generate and install the joint public context (no full secret key)."""
        ctx_dir = self._ws / "contexts" / context.context_id
        ctx_dir.mkdir(parents=True, exist_ok=True)
        ceremony = self._ws / "ceremony" / context.context_id
        ceremony.mkdir(parents=True, exist_ok=True)

        # Public context setup (no keys). Coordinator-run — no secret involved.
        gen = run_broker_json(
            self._binary,
            [
                "mp-gen-context",
                str(ctx_dir),
                str(context.multiplicative_depth),
                str(context.scaling_mod_size),
                str(context.batch_size),
                str(context.ring_dimension),
            ],
        )

        # Round 1: lead. Rounds 2..N: joins. Each writes its share to its own dir.
        lead, *joiners = self._participants
        pub = str(ceremony / f"pub-{lead.party_id}.bin")
        es = str(ceremony / f"es-{lead.party_id}.bin")
        lead.keygen_lead(context_dir=str(ctx_dir), out_pub=pub, out_evalsum=es)

        for p in joiners:
            next_pub = str(ceremony / f"pub-{p.party_id}.bin")
            next_es = str(ceremony / f"es-{p.party_id}.bin")
            p.keygen_join(
                context_dir=str(ctx_dir),
                prev_pub=pub,
                prev_evalsum=es,
                out_pub=next_pub,
                out_evalsum=next_es,
            )
            pub, es = next_pub, next_es

        # Install the final joint public key + joint eval-sum keys only.
        run_broker_json(self._binary, ["mp-install-public", str(ctx_dir), pub, es])

        return {
            "context_id": context.context_id,
            "context_dir": str(ctx_dir),
            "ring_dimension": gen.get("ring_dimension"),
            "participants": [p.party_id for p in self._participants],
        }


class DecryptCoordinator:
    """Distributed decryption: release gate → per-party partials → fuse (§42)."""

    def __init__(
        self,
        *,
        participants: list[Participant],
        workspace_root: str | Path,
        expected_parties: int,
        release_policy: ThresholdReleasePolicy | None = None,
        binary_path: str | None = None,
    ) -> None:
        self._participants = participants
        self._ws = Path(workspace_root)
        self._expected = expected_parties
        self._policy = release_policy or ThresholdReleasePolicy()
        self._binary = binary_path or default_binary_path()

    def decrypt(
        self,
        *,
        context_dir: str,
        result_path: str,
        length: int,
        release_request: DecryptReleaseRequest,
    ) -> list[float]:
        """Release-gated N-of-N decryption. Returns plaintext only if authorized."""
        # N-of-N: every configured party must be present (§41).
        if len(self._participants) != self._expected:
            raise CVZTTEError(
                ErrorCode.FHE_THRESHOLD_INSUFFICIENT,
                "not all required decryption parties are present",
                detail={"present": len(self._participants), "required": self._expected},
            )

        # Release policy first — a high-risk, separate action (§42, §60.26).
        self._policy.authorize(release_request)

        partials_dir = self._ws / "partials"
        partials_dir.mkdir(parents=True, exist_ok=True)
        run_id = uuid.uuid4().hex

        partial_paths: list[str] = []
        for idx, p in enumerate(self._participants):
            out = str(partials_dir / f"partial-{run_id}-{p.party_id}.bin")
            p.partial_decrypt(
                context_dir=context_dir,
                ciphertext_path=result_path,
                out_partial=out,
                lead=(idx == 0),
            )
            partial_paths.append(out)

        out = run_broker_json(
            self._binary,
            ["mp-decrypt-fuse", context_dir, str(int(length)), *partial_paths],
        )
        vals = out.get("values")
        if not isinstance(vals, list):
            raise CVZTTEError(
                ErrorCode.FHE_PARTIAL_DECRYPT_INVALID, "fusion returned no plaintext"
            )
        return [float(v) for v in vals]
