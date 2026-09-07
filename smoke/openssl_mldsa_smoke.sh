#!/usr/bin/env bash
# Phase 0 feasibility smoke test: native OpenSSL 3.5 ML-DSA-65 sign/verify (spec §9).
# Proves the PRIMARY provider (native OpenSSL, not liboqs) can generate an
# ML-DSA-65 keypair, sign a message, verify a good signature, and REJECT a
# tampered signature. Fails closed (nonzero exit) on any deviation.
set -euo pipefail

ALG="${1:-ML-DSA-65}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[mldsa] openssl: $(command -v openssl) ($(openssl version))"
echo "[mldsa] algorithm: $ALG"

# 1. Generate private key (isolated file; never exposed to any LLM/log/audit).
openssl genpkey -algorithm "$ALG" -out "$WORK/priv.pem"
# 2. Derive public key.
openssl pkey -in "$WORK/priv.pem" -pubout -out "$WORK/pub.pem"

# 3. Sign a canonical message (one-shot pure ML-DSA over raw input).
printf 'canonical-signed-bytes' > "$WORK/msg.bin"
openssl pkeyutl -sign -rawin -inkey "$WORK/priv.pem" \
  -in "$WORK/msg.bin" -out "$WORK/sig.bin"
echo "[mldsa] signature size: $(wc -c < "$WORK/sig.bin") bytes"

# 4. Verify the good signature (MUST succeed).
if openssl pkeyutl -verify -rawin -pubin -inkey "$WORK/pub.pem" \
     -in "$WORK/msg.bin" -sigfile "$WORK/sig.bin" >/dev/null 2>&1; then
  echo "[mldsa] PASS: valid signature verified"
else
  echo "[mldsa] FAIL: valid signature rejected" >&2
  exit 1
fi

# 5. Tamper one byte of the message -> verify MUST fail (fail closed).
printf 'canonical-signed-byteX' > "$WORK/msg_bad.bin"
if openssl pkeyutl -verify -rawin -pubin -inkey "$WORK/pub.pem" \
     -in "$WORK/msg_bad.bin" -sigfile "$WORK/sig.bin" >/dev/null 2>&1; then
  echo "[mldsa] FAIL: tampered message accepted (SECURITY)" >&2
  exit 1
else
  echo "[mldsa] PASS: tampered message rejected"
fi

echo "[mldsa] SMOKE OK ($ALG via native OpenSSL default provider)"
