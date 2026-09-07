// Package bridge implements the deterministic SHA-256 -> BN254 field bridge
// defined in docs/GNARK_BINDING.md. It MUST agree bit-for-bit with the Python
// side (cvztte.zkauthz.bridge); substitution tests enforce this.
package bridge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// CapDomain is the domain-separation tag for capability field encoding.
const CapDomain = "cvztte.cap.v3"

// DigestToLimbs splits a 32-byte digest into two big-endian 128-bit limbs.
func DigestToLimbs(d []byte) (*big.Int, *big.Int, error) {
	if len(d) != 32 {
		return nil, nil, fmt.Errorf("digest must be 32 bytes, got %d", len(d))
	}
	hi := new(big.Int).SetBytes(d[:16])
	lo := new(big.Int).SetBytes(d[16:])
	return hi, lo, nil
}

// Sha256HexToLimbs parses "sha256:<hex>" (or bare 64-hex) into (hi, lo).
func Sha256HexToLimbs(commit string) (*big.Int, *big.Int, error) {
	h := strings.TrimPrefix(commit, "sha256:")
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid sha256 hex: %w", err)
	}
	return DigestToLimbs(raw)
}

// CapabilityField encodes a capability name to a single (<2^128) field integer:
// int_be( sha256( CapDomain || 0x00 || name )[16:32] ).
func CapabilityField(name string) *big.Int {
	h := sha256.New()
	h.Write([]byte(CapDomain))
	h.Write([]byte{0x00})
	h.Write([]byte(name))
	sum := h.Sum(nil)
	return new(big.Int).SetBytes(sum[16:])
}
