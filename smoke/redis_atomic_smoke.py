#!/usr/bin/env python3
"""Phase 0 feasibility smoke test: Redis atomic replay/freshness (spec §11).

Loads the atomic Lua guard and asserts:
  * first (fresh nonce, increasing sequence) -> OK
  * exact nonce replay                        -> NONCE_REPLAY
  * sequence rollback                         -> SEQUENCE_INVALID
  * concurrent duplicate (same nonce)         -> exactly one OK

Assumes a Redis reachable at $CVZTTE_REDIS_URL (default redis://127.0.0.1:6399/0).
Exits nonzero (fail closed) on any deviation.
"""
from __future__ import annotations

import os
import pathlib
import sys
from concurrent.futures import ThreadPoolExecutor

import redis

URL = os.environ.get("CVZTTE_REDIS_URL", "redis://127.0.0.1:6399/0")
LUA = (pathlib.Path(__file__).parent / "replay_atomic.lua").read_text()


def main() -> int:
    r = redis.Redis.from_url(URL)
    r.flushdb()
    guard = r.register_script(LUA)
    nk, sk = "sess:S1:nonces", "sess:S1:seq"

    # fresh
    assert guard(keys=[nk, sk], args=["nonceA", 1, 60]) == b"OK", "fresh should pass"
    # replay
    assert guard(keys=[nk, sk], args=["nonceA", 2, 60]) == b"NONCE_REPLAY", "replay must fail"
    # rollback (new nonce, but seq <= last committed 1)
    assert guard(keys=[nk, sk], args=["nonceB", 1, 60]) == b"SEQUENCE_INVALID", "rollback must fail"
    # progress
    assert guard(keys=[nk, sk], args=["nonceB", 2, 60]) == b"OK", "increasing seq should pass"

    # concurrent duplicate: 20 threads, same nonce+seq -> exactly one OK
    r.flushdb()
    nk2, sk2 = "sess:S2:nonces", "sess:S2:seq"

    def attempt(_):
        g = r.register_script(LUA)
        return g(keys=[nk2, sk2], args=["dupNonce", 5, 60])

    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(attempt, range(20)))
    ok_count = sum(1 for x in results if x == b"OK")
    assert ok_count == 1, f"concurrent duplicate must yield exactly one OK, got {ok_count}"

    print("[redis] PASS fresh/replay/rollback/concurrent-atomic")
    print("[redis] SMOKE OK")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"[redis] FAIL: {e}", file=sys.stderr)
        sys.exit(1)
