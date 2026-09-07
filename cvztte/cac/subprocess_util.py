"""Shared native-broker subprocess seam (spec §36, §60.12).

A single place that shells out to the compiled ``fhe_broker`` executable with a
**list argv** (never ``shell=True``, §60.12), enforces a timeout, and maps any
failure to a fail-closed :class:`CVZTTEError` (§4.20). The broker only ever
prints operation metadata on stdout — never key material or plaintext (except an
explicit ``decrypt``/``mp-decrypt-fuse``) — so its stdout is safe to parse and
log; stderr (which may echo argv paths) is truncated and kept internal only.
"""

from __future__ import annotations

import json
import os
import subprocess

from cvztte.errors import CVZTTEError, ErrorCode

DEFAULT_TIMEOUT_S = 120


def run_broker_json(binary: str, args: list[str], *, timeout: int = DEFAULT_TIMEOUT_S) -> dict:
    """Invoke ``binary`` with ``args`` and return the parsed single-line JSON.

    Fails closed: a missing binary → ``SECURITY_DEPENDENCY_UNAVAILABLE``; a
    timeout → ``FHE_COMPUTE_TIMEOUT``; any non-zero exit or unparseable output →
    ``FHE_COMPUTE_FAILED``. Never returns implicit success.
    """
    if not os.path.exists(binary):
        raise CVZTTEError(
            ErrorCode.SECURITY_DEPENDENCY_UNAVAILABLE,
            "FHE broker binary not built",
            detail={"path": binary},
        )
    try:
        proc = subprocess.run(  # noqa: S603 — fixed binary, list argv, no shell
            [binary, *args],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CVZTTEError(ErrorCode.FHE_COMPUTE_TIMEOUT, "FHE broker timed out") from exc
    if proc.returncode != 0:
        raise CVZTTEError(
            ErrorCode.FHE_COMPUTE_FAILED,
            "FHE broker failed",
            detail={"stderr": proc.stderr.decode("utf-8", "replace")[:400]},
        )
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise CVZTTEError(ErrorCode.FHE_COMPUTE_FAILED, "unparseable broker output") from exc
