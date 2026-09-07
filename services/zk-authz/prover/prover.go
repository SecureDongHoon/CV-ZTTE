// Package prover loads the pinned Groth16 artifacts and produces authorization
// proofs. The proving key is loaded from the registry-pinned artifact directory;
// the caller supplies the full witness (public assignment + private credential
// attributes) as BN254 scalars (spec §14).
package prover

import (
	"bytes"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"

	"cvztte/zkauthz/circuit"
	"cvztte/zkauthz/registry"
)

// Assignment is the full witness for one proof. All values are BN254 scalars.
type Assignment struct {
	// public
	AgentHi              *big.Int
	AgentLo              *big.Int
	CredentialCommitment *big.Int
	RequiredCapability   *big.Int
	RequiredClearance    *big.Int
	CurrentEpoch         *big.Int
	ActionHi             *big.Int
	ActionLo             *big.Int
	PolicyHi             *big.Int
	PolicyLo             *big.Int
	ScopeHi              *big.Int
	ScopeLo              *big.Int
	CircuitVer           *big.Int
	SessionBinding       *big.Int
	// private
	Capability  *big.Int
	Clearance   *big.Int
	ExpiryEpoch *big.Int
	Salt        *big.Int
}

func (a Assignment) toCircuit() *circuit.AuthzCircuit {
	return &circuit.AuthzCircuit{
		AgentHi:              a.AgentHi,
		AgentLo:              a.AgentLo,
		CredentialCommitment: a.CredentialCommitment,
		RequiredCapability:   a.RequiredCapability,
		RequiredClearance:    a.RequiredClearance,
		CurrentEpoch:         a.CurrentEpoch,
		ActionHi:             a.ActionHi,
		ActionLo:             a.ActionLo,
		PolicyHi:             a.PolicyHi,
		PolicyLo:             a.PolicyLo,
		ScopeHi:              a.ScopeHi,
		ScopeLo:              a.ScopeLo,
		CircuitVer:           a.CircuitVer,
		SessionBinding:       a.SessionBinding,
		Capability:           a.Capability,
		Clearance:            a.Clearance,
		ExpiryEpoch:          a.ExpiryEpoch,
		Salt:                 a.Salt,
	}
}

// Artifacts holds the loaded constraint system and proving key.
type Artifacts struct {
	CS constraint.ConstraintSystem
	PK groth16.ProvingKey
}

// LoadArtifacts loads the constraint system and proving key from a pinned dir.
func LoadArtifacts(dir string) (*Artifacts, error) {
	csPath, pkPath, _ := registry.Paths(dir)

	csBytes, err := os.ReadFile(csPath)
	if err != nil {
		return nil, fmt.Errorf("read cs: %w", err)
	}
	ccs := &cs_bn254.R1CS{}
	if _, err := ccs.ReadFrom(bytes.NewReader(csBytes)); err != nil {
		return nil, fmt.Errorf("decode cs: %w", err)
	}

	pkBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return nil, fmt.Errorf("read pk: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return nil, fmt.Errorf("decode pk: %w", err)
	}

	return &Artifacts{CS: ccs, PK: pk}, nil
}

// Prove builds the witness from the assignment and produces a Groth16 proof,
// returning the marshaled proof and the marshaled public witness.
func (art *Artifacts) Prove(a Assignment) (proof []byte, publicWitness []byte, err error) {
	full, err := frontend.NewWitness(a.toCircuit(), ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("witness: %w", err)
	}
	pub, err := full.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("public witness: %w", err)
	}
	p, err := groth16.Prove(art.CS, art.PK, full)
	if err != nil {
		return nil, nil, fmt.Errorf("prove: %w", err)
	}

	var pbuf bytes.Buffer
	if _, err := p.WriteTo(&pbuf); err != nil {
		return nil, nil, err
	}
	wbytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pbuf.Bytes(), wbytes, nil
}

// PublicWitnessFrom rebuilds only the public witness from an assignment (used by
// the verifier path when re-deriving public inputs independently of the prover).
func PublicWitnessFrom(a Assignment) (witness.Witness, error) {
	full, err := frontend.NewWitness(a.toCircuit(), ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return full.Public()
}
