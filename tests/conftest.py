"""Shared test fixtures.

Real dependencies, not mocks (spec §0 rule 10): an ephemeral native OpenSSL
ML-DSA provider and an ephemeral local Redis are started for the tests that
need them, so the acceptance paths exercise genuine crypto and a genuine atomic
freshness store.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator

import pytest

from cvztte.identity import KeyRegistry, OpenSSLMLDSAProvider


@pytest.fixture(scope="session")
def mldsa_provider(tmp_path_factory: pytest.TempPathFactory) -> OpenSSLMLDSAProvider:
    keystore = tmp_path_factory.mktemp("keystore_shared")
    return OpenSSLMLDSAProvider(keystore)


@pytest.fixture()
def registry(mldsa_provider: OpenSSLMLDSAProvider) -> KeyRegistry:
    reg = KeyRegistry(mldsa_provider)
    reg.register_agent("agt_alice")
    return reg


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def _redis_server() -> Iterator[int]:
    if shutil.which("redis-server") is None:
        pytest.skip("redis-server not on PATH (source env.sh)")
    port = _free_port()
    proc = subprocess.Popen(
        [
            "redis-server", "--port", str(port),
            "--save", "", "--appendonly", "no", "--loglevel", "warning",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        import redis

        client = redis.Redis(host="127.0.0.1", port=port)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                if client.ping():
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("ephemeral redis did not become ready")
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture()
def redis_client(_redis_server: int):
    import redis

    client = redis.Redis(host="127.0.0.1", port=_redis_server)
    client.flushdb()
    return client
