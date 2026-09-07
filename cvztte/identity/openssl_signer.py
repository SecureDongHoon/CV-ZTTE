"""Native OpenSSL 3.5+ ML-DSA signer — the PRIMARY provider (spec §9, §60.2).

The private key is isolated on restricted storage (0600 PEM in a keystore
directory) and every cryptographic operation is delegated to the ``openssl``
CLI in a subprocess. Private bytes are therefore never resident in the
application heap alongside model/agent data, and never returned to callers.
This is the PoC form of the mandated isolation; an HSM/KMS/TEE-backed opaque
key is the production evolution point (spec §9, §60.2).

Isolation choices:

* Keystore dir + key files are created ``0700`` / ``0600``.
* ``sign`` / ``verify`` write only the *message* and *signature* to a private
  temp dir; the private key is read by ``openssl`` from its restricted path.
* No secret ever passes through the command line, environment, or a log.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from cvztte.errors import CVZTTEError, ErrorCode
from cvztte.identity.provider import (
    Algorithm,
    DEFAULT_ALGORITHM,
    PrivateKeyHandle,
    PublicKey,
    SignatureProvider,
)


def _resolve_openssl() -> str:
    """Locate the pinned OpenSSL 3.5+ binary (native ML-DSA provider)."""
    home = os.environ.get("CVZTTE_OPENSSL_HOME")
    if home:
        candidate = Path(home) / "bin" / "openssl"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("openssl")
    if found:
        return found
    raise CVZTTEError(
        ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
        "openssl binary not found (need OpenSSL 3.5+ native ML-DSA)",
    )


class OpenSSLMLDSAProvider(SignatureProvider):
    """ML-DSA via the native OpenSSL ``default`` provider (not liboqs)."""

    name = "openssl-native"
    is_production_equivalent = True

    def __init__(
        self,
        keystore_dir: str | os.PathLike[str],
        *,
        algorithm: Algorithm = DEFAULT_ALGORITHM,
        openssl_bin: str | None = None,
    ) -> None:
        self._algorithm = algorithm
        self._openssl = openssl_bin or _resolve_openssl()
        self._keystore = Path(keystore_dir)
        self._keystore.mkdir(parents=True, exist_ok=True)
        os.chmod(self._keystore, 0o700)
        self._verify_algorithm_available()

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #
    def _run(self, args: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._openssl, *args],
                input=stdin,
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise CVZTTEError(
                ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
                "failed to invoke openssl",
                detail=str(exc),
            ) from exc

    def _verify_algorithm_available(self) -> None:
        proc = self._run(["list", "-signature-algorithms"])
        if proc.returncode != 0:
            raise CVZTTEError(
                ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
                "openssl does not support listing signature algorithms",
            )
        if self._algorithm.value.encode() not in proc.stdout:
            raise CVZTTEError(
                ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
                f"{self._algorithm.value} not offered by native OpenSSL provider",
            )

    def _new_key_path(self) -> Path:
        path = self._keystore / f"{uuid.uuid4().hex}.priv.pem"
        # Create with restrictive perms up front (avoid a brief 0644 window).
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        os.close(fd)
        return path

    def _derive_public_pem(self, private_path: Path) -> bytes:
        proc = self._run(["pkey", "-in", str(private_path), "-pubout"])
        if proc.returncode != 0:
            raise CVZTTEError(
                ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
                "failed to derive public key",
                detail=proc.stderr.decode(errors="replace"),
            )
        return proc.stdout

    # ------------------------------------------------------------------ #
    # SignatureProvider API
    # ------------------------------------------------------------------ #
    @property
    def algorithm(self) -> Algorithm:
        return self._algorithm

    def generate_key(self) -> tuple[PrivateKeyHandle, PublicKey]:
        path = self._new_key_path()
        proc = self._run(
            ["genpkey", "-algorithm", self._algorithm.value, "-out", str(path)]
        )
        if proc.returncode != 0:
            path.unlink(missing_ok=True)
            raise CVZTTEError(
                ErrorCode.CRYPTO_PROVIDER_UNAVAILABLE,
                "ML-DSA key generation failed",
                detail=proc.stderr.decode(errors="replace"),
            )
        os.chmod(path, 0o600)
        public = PublicKey(self._algorithm, self._derive_public_pem(path))
        return PrivateKeyHandle(self._algorithm, path), public

    def import_private_key(self, private_pem: bytes) -> PrivateKeyHandle:
        path = self._new_key_path()
        path.write_bytes(private_pem)
        os.chmod(path, 0o600)
        # Validate it parses and matches the provider algorithm.
        proc = self._run(["pkey", "-in", str(path), "-noout"])
        if proc.returncode != 0:
            path.unlink(missing_ok=True)
            raise CVZTTEError(
                ErrorCode.MLDSA_INVALID,
                "imported private key is not a valid key for this provider",
            )
        return PrivateKeyHandle(self._algorithm, path)

    def import_public_key(self, public_pem: bytes) -> PublicKey:
        # Round-trip through openssl to confirm it is a well-formed public key.
        proc = self._run(["pkey", "-pubin", "-pubout"], stdin=public_pem)
        if proc.returncode != 0:
            raise CVZTTEError(
                ErrorCode.MLDSA_INVALID,
                "imported public key is not a valid SPKI",
            )
        return PublicKey(self._algorithm, proc.stdout)

    def sign(self, handle: PrivateKeyHandle, message: bytes) -> bytes:
        if handle.algorithm != self._algorithm:
            raise CVZTTEError(
                ErrorCode.MLDSA_INVALID,
                "key/provider algorithm mismatch (downgrade forbidden)",
            )
        if not handle.path.is_file():
            raise CVZTTEError(ErrorCode.KEY_UNKNOWN, "private key not present")
        with tempfile.TemporaryDirectory() as tmp:
            msg_path = Path(tmp) / "msg.bin"
            sig_path = Path(tmp) / "sig.bin"
            msg_path.write_bytes(message)
            proc = self._run(
                [
                    "pkeyutl", "-sign", "-rawin",
                    "-inkey", str(handle.path),
                    "-in", str(msg_path),
                    "-out", str(sig_path),
                ]
            )
            if proc.returncode != 0 or not sig_path.is_file():
                raise CVZTTEError(
                    ErrorCode.MLDSA_INVALID,
                    "signing failed",
                    detail=proc.stderr.decode(errors="replace"),
                )
            return sig_path.read_bytes()

    def verify(self, public_key: PublicKey, message: bytes, signature: bytes) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            pub_path = Path(tmp) / "pub.pem"
            msg_path = Path(tmp) / "msg.bin"
            sig_path = Path(tmp) / "sig.bin"
            pub_path.write_bytes(public_key.pem)
            msg_path.write_bytes(message)
            sig_path.write_bytes(signature)
            proc = self._run(
                [
                    "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-inkey", str(pub_path),
                    "-in", str(msg_path),
                    "-sigfile", str(sig_path),
                ]
            )
            # Fail closed: any non-zero return (bad signature or malformed
            # input) is treated as "not verified". Provider-availability was
            # established at construction time.
            return proc.returncode == 0

    def provider_metadata(self) -> dict[str, Any]:
        version = self._run(["version"]).stdout.decode(errors="replace").strip()
        return {
            "name": self.name,
            "algorithm": self._algorithm.value,
            "production_equivalent": True,
            "backend": "openssl-default-provider",
            "openssl_version": version,
            "note": "ML-DSA algorithm conformance, not FIPS 140-3 module validation",
        }
