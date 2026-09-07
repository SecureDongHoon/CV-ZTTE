"""Threshold FHE key authority (spec §41).

A :class:`KeyAuthority` owns **one party's secret share** and performs only that
party's part of the genuine OpenFHE N-of-N multiparty protocol: its key-gen
round and its partial decryption. It shells out to the native ``fhe_broker``
(list argv, never ``shell=True``) which writes the share to the authority's own
``share_dir`` and leaves it there.

Security invariants (§41):

* The secret share never leaves ``share_dir`` — it is not returned, logged, or
  placed in any coordinator/agent-visible artifact. The broker prints only
  operation metadata.
* No authority ever reconstructs or persists the full secret key. The joint
  secret ``s = s_a + s_b + s_c`` exists only implicitly across the parties.
* Every party is required to decrypt (N-of-N). One missing party cannot decrypt.

Reference authorities (§41, §60.25): Data Owner, Security/Privacy, CV-ZTTE
Decryption. Run as separate processes/containers via ``services/`` entrypoints;
this class is the shared implementation each such process uses.
"""

from __future__ import annotations

import enum
import json
import subprocess
import sys
from pathlib import Path

from cvztte.cac.broker import default_binary_path
from cvztte.cac.subprocess_util import run_broker_json
from cvztte.errors import CVZTTEError, ErrorCode

SHARE_FILE = "share-sec.bin"
_AUTHORITY_TIMEOUT_S = 180


class AuthorityRole(str, enum.Enum):
    """Reference logical authorities (§41, §60.25)."""

    DATA_OWNER = "data_owner"
    SECURITY_PRIVACY = "security_privacy"
    CVZTTE_DECRYPTION = "cvztte_decryption"


class KeyAuthority:
    """Holder of a single secret share; runs its own broker operations."""

    def __init__(
        self,
        *,
        party_id: str,
        role: AuthorityRole,
        share_dir: str | Path,
        binary_path: str | None = None,
    ) -> None:
        self.party_id = party_id
        self.role = role
        self._share_dir = Path(share_dir)
        self._binary = binary_path or default_binary_path()

    # -- key generation rounds ---------------------------------------------

    def keygen_lead(self, *, context_dir: str, out_pub: str, out_evalsum: str) -> dict:
        """Round 1 (lead): fresh KeyGen + eval-sum seed. Share stays local."""
        self._share_dir.mkdir(parents=True, exist_ok=True)
        return run_broker_json(
            self._binary,
            ["mp-keygen-lead", context_dir, str(self._share_dir), out_pub, out_evalsum],
        )

    def keygen_join(
        self,
        *,
        context_dir: str,
        prev_pub: str,
        prev_evalsum: str,
        out_pub: str,
        out_evalsum: str,
    ) -> dict:
        """Join round: extend the joint public/eval-sum keys. Share stays local."""
        self._share_dir.mkdir(parents=True, exist_ok=True)
        return run_broker_json(
            self._binary,
            [
                "mp-keygen-join",
                context_dir,
                str(self._share_dir),
                prev_pub,
                prev_evalsum,
                out_pub,
                out_evalsum,
            ],
        )

    # -- partial decryption -------------------------------------------------

    def partial_decrypt(
        self, *, context_dir: str, ciphertext_path: str, out_partial: str, lead: bool
    ) -> dict:
        """Produce this party's partial decryption of a ciphertext (§42)."""
        cmd = "mp-decrypt-lead" if lead else "mp-decrypt-main"
        return run_broker_json(
            self._binary,
            [cmd, context_dir, str(self._share_dir), ciphertext_path, out_partial],
        )

    # -- introspection ------------------------------------------------------

    def has_share(self) -> bool:
        """True once this authority holds its share (post key-gen)."""
        return (self._share_dir / SHARE_FILE).exists()


class SubprocessParticipant:
    """A threshold participant that runs as a **separate OS process** (§60.25).

    Invokes a ``services/fhe-key-authority-*/main.py`` entrypoint with a list
    argv (never ``shell=True``). The child process is the only thing that ever
    opens this party's share directory, so the coordinator (this process) never
    holds the share. Mirrors the :class:`KeyAuthority` operation surface.
    """

    def __init__(
        self,
        *,
        party_id: str,
        entrypoint: str | Path,
        share_dir: str | Path,
        binary_path: str | None = None,
        python: str | None = None,
    ) -> None:
        self.party_id = party_id
        self._entrypoint = str(entrypoint)
        self._share_dir = str(share_dir)
        self._binary = binary_path
        self._python = python or sys.executable

    def _run(self, subcmd: str, args: list[str]) -> dict:
        argv = [self._python, self._entrypoint, "--share-dir", self._share_dir]
        if self._binary:
            argv += ["--binary", self._binary]
        argv += [subcmd, *args]
        try:
            proc = subprocess.run(  # noqa: S603 — python + entrypoint, list argv, no shell
                argv, capture_output=True, timeout=_AUTHORITY_TIMEOUT_S, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise CVZTTEError(ErrorCode.FHE_COMPUTE_TIMEOUT, "key authority timed out") from exc
        if proc.returncode != 0:
            raise CVZTTEError(
                ErrorCode.FHE_COMPUTE_FAILED,
                "key authority process failed",
                detail={"stderr": proc.stderr.decode("utf-8", "replace")[:400]},
            )
        try:
            return json.loads(proc.stdout.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CVZTTEError(ErrorCode.FHE_COMPUTE_FAILED, "unparseable authority output") from exc

    def keygen_lead(self, *, context_dir: str, out_pub: str, out_evalsum: str) -> dict:
        return self._run(
            "keygen-lead",
            ["--context-dir", context_dir, "--out-pub", out_pub, "--out-evalsum", out_evalsum],
        )

    def keygen_join(
        self,
        *,
        context_dir: str,
        prev_pub: str,
        prev_evalsum: str,
        out_pub: str,
        out_evalsum: str,
    ) -> dict:
        return self._run(
            "keygen-join",
            [
                "--context-dir", context_dir,
                "--prev-pub", prev_pub,
                "--prev-evalsum", prev_evalsum,
                "--out-pub", out_pub,
                "--out-evalsum", out_evalsum,
            ],
        )

    def partial_decrypt(
        self, *, context_dir: str, ciphertext_path: str, out_partial: str, lead: bool
    ) -> dict:
        args = ["--context-dir", context_dir, "--ciphertext", ciphertext_path,
                "--out-partial", out_partial]
        if lead:
            args.append("--lead")
        return self._run("partial-decrypt", args)
