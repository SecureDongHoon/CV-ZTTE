// Package verifier verifies authorization proofs against the registry-pinned
// verifying key. The VK is ALWAYS loaded from the pinned artifact directory
// selected by the enforcement fabric; a client cannot supply or select its own
// VK (spec §60.5). Any decode/verify error fails closed (returns not-verified).
package verifier

import (
	"bytes"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"

	"cvztte/zkauthz/registry"
)

// Verifier holds the pinned verifying key and its manifest.
type Verifier struct {
	VK       groth16.VerifyingKey
	Manifest *registry.Manifest
}

// Load loads the verifying key and manifest from a pinned artifact directory.
func Load(dir string) (*Verifier, error) {
	m, err := registry.LoadManifest(dir)
	if err != nil {
		return nil, err
	}
	_, _, vkPath := registry.Paths(dir)
	vkBytes, err := os.ReadFile(vkPath)
	if err != nil {
		return nil, fmt.Errorf("read vk: %w", err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return nil, fmt.Errorf("decode vk: %w", err)
	}
	return &Verifier{VK: vk, Manifest: m}, nil
}

// Verify verifies a marshaled proof against a marshaled public witness. It
// returns (true, nil) only on a valid proof; any error yields (false, err) so
// callers fail closed.
func (v *Verifier) Verify(proofBytes, publicWitnessBytes []byte) (bool, error) {
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, fmt.Errorf("decode proof: %w", err)
	}
	pub, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return false, err
	}
	if err := pub.UnmarshalBinary(publicWitnessBytes); err != nil {
		return false, fmt.Errorf("decode public witness: %w", err)
	}
	if err := groth16.Verify(proof, v.VK, pub); err != nil {
		return false, nil
	}
	return true, nil
}
