// Package registry versions and pins the gnark artifacts (spec §60.5): circuit
// source hash, compiled constraint-system hash, proving system, curve, PK/VK
// hashes, and credential schema version.
package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"cvztte/zkauthz/circuit"
)

const (
	ProvingSystem = "groth16"
	Curve         = "BN254"
	SchemaVersion = 3
	csFile        = "cs.bin"
	pkFile        = "pk.bin"
	vkFile        = "vk.bin"
	manifestFile  = "manifest.json"
)

type Manifest struct {
	CircuitVersion       int    `json:"circuit_version"`
	SchemaVersion        int    `json:"schema_version"`
	ProvingSystem        string `json:"proving_system"`
	Curve                string `json:"curve"`
	CircuitSourceHash    string `json:"circuit_source_hash"`
	ConstraintSystemHash string `json:"constraint_system_hash"`
	ProvingKeyHash       string `json:"proving_key_hash"`
	VerificationKeyHash  string `json:"verification_key_hash"`
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// Setup compiles the circuit, runs Groth16 setup, writes the artifacts and a
// manifest into dir, and returns the manifest.
func Setup(dir string) (*Manifest, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var c circuit.AuthzCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup: %w", err)
	}

	csBytes, err := marshal(ccs)
	if err != nil {
		return nil, err
	}
	pkBytes, err := marshal(pk)
	if err != nil {
		return nil, err
	}
	vkBytes, err := marshal(vk)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, csFile), csBytes, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, pkFile), pkBytes, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, vkFile), vkBytes, 0o644); err != nil {
		return nil, err
	}

	m := &Manifest{
		CircuitVersion:       circuit.CircuitVersion,
		SchemaVersion:        SchemaVersion,
		ProvingSystem:        ProvingSystem,
		Curve:                Curve,
		CircuitSourceHash:    sha256Hex(circuit.Source),
		ConstraintSystemHash: sha256Hex(csBytes),
		ProvingKeyHash:       sha256Hex(pkBytes),
		VerificationKeyHash:  sha256Hex(vkBytes),
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, manifestFile), mb, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

// marshal serializes a gnark artifact (constraint system, proving key, or
// verifying key) that implements io.WriterTo into a byte slice.
func marshal(v io.WriterTo) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := v.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// LoadManifest reads and validates the manifest in dir.
func LoadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Paths returns the artifact file paths in dir.
func Paths(dir string) (cs, pk, vk string) {
	return filepath.Join(dir, csFile), filepath.Join(dir, pkFile), filepath.Join(dir, vkFile)
}
