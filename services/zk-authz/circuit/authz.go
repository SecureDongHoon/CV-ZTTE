// Package circuit defines the CV-ZTTE authorization circuit (spec §14).
// See docs/GNARK_BINDING.md for exactly what is and is not constrained.
package circuit

import (
	_ "embed"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// CircuitVersion is the schema/circuit version bound as a public input.
const CircuitVersion = 3

// Source is the circuit source, embedded so the registry can record a real
// circuit-source hash (spec §60.5).
//
//go:embed authz.go
var Source []byte

// AuthzCircuit proves possession of a trusted issuer-anchored credential
// binding the exact action. Public inputs are declared in the fixed order
// documented in docs/GNARK_BINDING.md.
type AuthzCircuit struct {
	// --- public inputs ---
	AgentHi              frontend.Variable `gnark:",public"`
	AgentLo              frontend.Variable `gnark:",public"`
	CredentialCommitment frontend.Variable `gnark:",public"`
	RequiredCapability   frontend.Variable `gnark:",public"`
	RequiredClearance    frontend.Variable `gnark:",public"`
	CurrentEpoch         frontend.Variable `gnark:",public"`
	ActionHi             frontend.Variable `gnark:",public"`
	ActionLo             frontend.Variable `gnark:",public"`
	PolicyHi             frontend.Variable `gnark:",public"`
	PolicyLo             frontend.Variable `gnark:",public"`
	ScopeHi              frontend.Variable `gnark:",public"`
	ScopeLo              frontend.Variable `gnark:",public"`
	CircuitVer           frontend.Variable `gnark:",public"`
	SessionBinding       frontend.Variable `gnark:",public"`

	// --- private witness (issuer-anchored credential attributes) ---
	Capability  frontend.Variable
	Clearance   frontend.Variable
	ExpiryEpoch frontend.Variable
	Salt        frontend.Variable
}

func (c *AuthzCircuit) Define(api frontend.API) error {
	// 1. Recompute the credential commitment from private attributes bound to
	//    the public agent / scope / policy commitments, and assert it equals
	//    the issuer-anchored public commitment. Only the trusted issuer knows a
	//    salt producing a registered commitment, so the agent cannot invent
	//    witness attributes (spec §14).
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(
		c.AgentHi, c.AgentLo,
		c.Capability, c.Clearance, c.ExpiryEpoch,
		c.ScopeHi, c.ScopeLo,
		c.PolicyHi, c.PolicyLo,
		c.Salt,
	)
	api.AssertIsEqual(h.Sum(), c.CredentialCommitment)

	// 2. Required capability exists.
	api.AssertIsEqual(c.Capability, c.RequiredCapability)

	// 3. Clearance satisfies requirement (clearance >= required).
	api.AssertIsLessOrEqual(c.RequiredClearance, c.Clearance)

	// 4. Not expired (expiry >= current epoch).
	api.AssertIsLessOrEqual(c.CurrentEpoch, c.ExpiryEpoch)

	// 5. Session binding ties the credential to the EXACT action, epoch, and
	//    circuit version. Combined with Groth16 public-input binding, a proof
	//    for one action cannot verify for another (invariant §4.11).
	h2, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	h2.Write(c.CredentialCommitment, c.ActionHi, c.ActionLo, c.CurrentEpoch, c.CircuitVer)
	api.AssertIsEqual(h2.Sum(), c.SessionBinding)

	return nil
}
