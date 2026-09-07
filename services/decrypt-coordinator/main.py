#!/usr/bin/env python3
"""Decrypt Coordinator service (spec §42, §60.25, §60.26).

A standalone process that orchestrates release-gated N-of-N decryption. It holds
**no** secret share: it collects one partial decryption from each authority
subprocess and fuses them via the broker. Reads a JSON job file:

    {
      "context_dir": "...",
      "result_path": "...",
      "length": 1,
      "expected_result_hash": "sha256:...",
      "participants": [
        {"party_id": "A", "entrypoint": ".../fhe-key-authority-a/main.py", "share_dir": "..."},
        ...
      ],
      "release": {
        "recipient": "sec-supervisor",
        "purpose": "incident-review",
        "classification": "CONFIDENTIAL",
        "granted": ["DECRYPT_RESULT"],
        "containment_state": "NORMAL",
        "approval_granted": true,
        "approval_id": "appr-123"
      }
    }

Prints ``{"values":[...]}`` on success; any denial/failure exits non-zero
(fail-closed) with only a stable error code — never plaintext or key material.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the repo importable when run as a standalone script/process.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cvztte.action.model import DataClassification  # noqa: E402
from cvztte.cac.permissions import CACPermission  # noqa: E402
from cvztte.cac.threshold.authority import SubprocessParticipant  # noqa: E402
from cvztte.cac.threshold.coordinator import DecryptCoordinator  # noqa: E402
from cvztte.cac.threshold.release import DecryptReleaseRequest  # noqa: E402
from cvztte.decision.model import ContainmentState  # noqa: E402
from cvztte.errors import CVZTTEError  # noqa: E402


def _build_request(spec: dict, result_bytes: bytes, expected_hash: str) -> DecryptReleaseRequest:
    return DecryptReleaseRequest(
        recipient=spec["recipient"],
        purpose=spec["purpose"],
        classification=DataClassification(spec["classification"]),
        granted=frozenset(CACPermission(p) for p in spec.get("granted", [])),
        containment_state=ContainmentState(spec.get("containment_state", "NORMAL")),
        result_ciphertext_bytes=result_bytes,
        expected_result_hash=expected_hash,
        approval_granted=bool(spec.get("approval_granted", False)),
        approval_id=spec.get("approval_id"),
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="decrypt-coordinator")
    parser.add_argument("--job", required=True, help="path to JSON job file")
    parser.add_argument("--workspace", required=True, help="coordinator scratch dir")
    parser.add_argument("--binary", default=None, help="fhe_broker path override")
    ns = parser.parse_args(argv)

    job = json.loads(Path(ns.job).read_text())
    participants = [
        SubprocessParticipant(
            party_id=p["party_id"],
            entrypoint=p["entrypoint"],
            share_dir=p["share_dir"],
            binary_path=ns.binary,
        )
        for p in job["participants"]
    ]
    coordinator = DecryptCoordinator(
        participants=participants,
        workspace_root=ns.workspace,
        expected_parties=len(participants),
        binary_path=ns.binary,
    )
    result_bytes = Path(job["result_path"]).read_bytes()
    request = _build_request(job["release"], result_bytes, job["expected_result_hash"])
    try:
        values = coordinator.decrypt(
            context_dir=job["context_dir"],
            result_path=job["result_path"],
            length=int(job["length"]),
            release_request=request,
        )
    except CVZTTEError as exc:
        sys.stderr.write(json.dumps({"error_code": exc.code.value}) + "\n")
        return 2
    sys.stdout.write(json.dumps({"values": values}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
