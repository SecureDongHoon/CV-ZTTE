"""Key-authority service entrypoint (spec §41, §60.25).

Shared CLI implementation that turns a :class:`KeyAuthority` into a standalone
process, so the reference authorities (Data Owner / Security-Privacy / CV-ZTTE
Decryption) run as **separate processes/containers** (§60.25). The thin
``services/fhe-key-authority-{a,b,c}/main.py`` wrappers call this with their
fixed party id, role, and share directory.

The process only ever touches its own share directory (via the broker) and the
shared *public* context; it prints operation metadata as JSON on stdout and
never emits key material (§41). Any failure exits non-zero (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import sys

from cvztte.cac.threshold.authority import AuthorityRole, KeyAuthority
from cvztte.errors import CVZTTEError


def build_parser(prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="CV-ZTTE threshold key authority")
    parser.add_argument("--share-dir", required=True, help="this party's private share directory")
    parser.add_argument("--binary", default=None, help="fhe_broker path override")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen-lead")
    p.add_argument("--context-dir", required=True)
    p.add_argument("--out-pub", required=True)
    p.add_argument("--out-evalsum", required=True)

    p = sub.add_parser("keygen-join")
    p.add_argument("--context-dir", required=True)
    p.add_argument("--prev-pub", required=True)
    p.add_argument("--prev-evalsum", required=True)
    p.add_argument("--out-pub", required=True)
    p.add_argument("--out-evalsum", required=True)

    p = sub.add_parser("partial-decrypt")
    p.add_argument("--context-dir", required=True)
    p.add_argument("--ciphertext", required=True)
    p.add_argument("--out-partial", required=True)
    p.add_argument("--lead", action="store_true")

    return parser


def run_authority_cli(party_id: str, role: AuthorityRole, argv: list[str]) -> int:
    """Dispatch one authority operation; return a process exit code."""
    parser = build_parser(f"fhe-key-authority-{party_id.lower()}")
    ns = parser.parse_args(argv)
    authority = KeyAuthority(
        party_id=party_id, role=role, share_dir=ns.share_dir, binary_path=ns.binary
    )
    try:
        if ns.command == "keygen-lead":
            out = authority.keygen_lead(
                context_dir=ns.context_dir, out_pub=ns.out_pub, out_evalsum=ns.out_evalsum
            )
        elif ns.command == "keygen-join":
            out = authority.keygen_join(
                context_dir=ns.context_dir,
                prev_pub=ns.prev_pub,
                prev_evalsum=ns.prev_evalsum,
                out_pub=ns.out_pub,
                out_evalsum=ns.out_evalsum,
            )
        else:  # partial-decrypt
            out = authority.partial_decrypt(
                context_dir=ns.context_dir,
                ciphertext_path=ns.ciphertext,
                out_partial=ns.out_partial,
                lead=ns.lead,
            )
    except CVZTTEError as exc:
        # Fail-closed: emit only the stable code, never key material or detail.
        sys.stderr.write(json.dumps({"error_code": exc.code.value}) + "\n")
        return 2
    out = {**out, "party_id": party_id, "role": role.value}
    sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - module-run convenience
    # Generic invocation: party/role supplied via env-free defaults for ad-hoc use.
    raise SystemExit(run_authority_cli("X", AuthorityRole.CVZTTE_DECRYPTION, sys.argv[1:]))
