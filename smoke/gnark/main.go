// Phase 0 feasibility smoke test: gnark Groth16 prove/verify (spec §14).
// Proves knowledge of x such that x^3 + x + 5 == y for public y, then
// verifies the proof and confirms a wrong public input is REJECTED (fail closed).
package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CubicCircuit: x^3 + x + 5 == Y  (X private witness, Y public input)
type CubicCircuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

func (c *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

func die(msg string, err error) {
	fmt.Fprintf(os.Stderr, "[gnark] FAIL: %s: %v\n", msg, err)
	os.Exit(1)
}

func main() {
	var circuit CubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		die("compile", err)
	}
	fmt.Printf("[gnark] constraints: %d\n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		die("setup", err)
	}

	// x=3 -> y=35
	assignment := CubicCircuit{X: 3, Y: 35}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		die("witness", err)
	}
	pubW, _ := w.Public()

	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		die("prove", err)
	}

	// Good proof must verify.
	if err := groth16.Verify(proof, vk, pubW); err != nil {
		die("verify(good)", err)
	}
	fmt.Println("[gnark] PASS: valid proof verified")

	// Wrong public input must be rejected.
	bad := CubicCircuit{X: 3, Y: 36}
	badW, _ := frontend.NewWitness(&bad, ecc.BN254.ScalarField())
	badPub, _ := badW.Public()
	if err := groth16.Verify(proof, vk, badPub); err == nil {
		fmt.Fprintln(os.Stderr, "[gnark] FAIL: wrong public input accepted (SECURITY)")
		os.Exit(1)
	}
	fmt.Println("[gnark] PASS: wrong public input rejected")
	fmt.Println("[gnark] SMOKE OK (Groth16/BN254)")
}
