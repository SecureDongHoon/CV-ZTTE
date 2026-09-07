// Package credential computes issuer-anchored credential commitments and the
// session binding OFF-circuit, using the native Poseidon2 hasher whose default
// parameters match the in-circuit hasher (docs/GNARK_BINDING.md). Issuance is
// restricted to the trusted administration path (spec §14, §60.5).
package credential

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// Attributes are the private credential attributes (plus the public commitments
// they are bound to). Field values are BN254 scalars as big integers.
type Attributes struct {
	AgentHi     *big.Int
	AgentLo     *big.Int
	Capability  *big.Int
	Clearance   *big.Int
	ExpiryEpoch *big.Int
	ScopeHi     *big.Int
	ScopeLo     *big.Int
	PolicyHi    *big.Int
	PolicyLo    *big.Int
	Salt        *big.Int
}

func hashElements(vals ...*big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()
	for _, v := range vals {
		var e fr.Element
		e.SetBigInt(v)
		b := e.Bytes() // 32-byte big-endian canonical serialization
		_, _ = h.Write(b[:])
	}
	sum := h.Sum(nil)
	var out fr.Element
	out.SetBytes(sum)
	res := new(big.Int)
	out.BigInt(res)
	return res
}

// Commit computes the credential commitment in the SAME field order the circuit
// recomputes it.
func Commit(a Attributes) *big.Int {
	return hashElements(
		a.AgentHi, a.AgentLo,
		a.Capability, a.Clearance, a.ExpiryEpoch,
		a.ScopeHi, a.ScopeLo,
		a.PolicyHi, a.PolicyLo,
		a.Salt,
	)
}

// SessionBinding computes Poseidon2(cred, actionHi, actionLo, epoch, circuitVer).
func SessionBinding(cred, actionHi, actionLo, epoch, circuitVer *big.Int) *big.Int {
	return hashElements(cred, actionHi, actionLo, epoch, circuitVer)
}
