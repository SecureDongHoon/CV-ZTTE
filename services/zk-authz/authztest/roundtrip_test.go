// Package authztest exercises the full setup -> issue -> prove -> verify round
// trip on the real circuit, and asserts action-binding (invariant §4.11): a
// proof for one action cannot verify against another action's public inputs.
package authztest

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"cvztte/zkauthz/bridge"
	"cvztte/zkauthz/circuit"
	"cvztte/zkauthz/credential"
	"cvztte/zkauthz/prover"
	"cvztte/zkauthz/registry"
	"cvztte/zkauthz/verifier"
)

func sha(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func limbs(t *testing.T, s string) (*big.Int, *big.Int) {
	t.Helper()
	hi, lo, err := bridge.DigestToLimbs(sha(s))
	if err != nil {
		t.Fatal(err)
	}
	return hi, lo
}

// buildValid returns a consistent, satisfiable assignment.
func buildValid(t *testing.T, action string) prover.Assignment {
	t.Helper()
	agentHi, agentLo := limbs(t, "agt_alice")
	scopeHi, scopeLo := limbs(t, "scope:db/customers")
	policyHi, policyLo := limbs(t, "policy-v3")
	actionHi, actionLo := limbs(t, action)

	capability := bridge.CapabilityField("db:read")
	clearance := big.NewInt(3)
	requiredClearance := big.NewInt(2)
	expiry := big.NewInt(2000)
	epoch := big.NewInt(1000)
	circuitVer := big.NewInt(int64(circuit.CircuitVersion))
	salt := big.NewInt(1234567890)

	attrs := credential.Attributes{
		AgentHi: agentHi, AgentLo: agentLo,
		Capability: capability, Clearance: clearance, ExpiryEpoch: expiry,
		ScopeHi: scopeHi, ScopeLo: scopeLo,
		PolicyHi: policyHi, PolicyLo: policyLo,
		Salt: salt,
	}
	cred := credential.Commit(attrs)
	sb := credential.SessionBinding(cred, actionHi, actionLo, epoch, circuitVer)

	return prover.Assignment{
		AgentHi: agentHi, AgentLo: agentLo,
		CredentialCommitment: cred,
		RequiredCapability:   capability,
		RequiredClearance:    requiredClearance,
		CurrentEpoch:         epoch,
		ActionHi:             actionHi, ActionLo: actionLo,
		PolicyHi: policyHi, PolicyLo: policyLo,
		ScopeHi: scopeHi, ScopeLo: scopeLo,
		CircuitVer:     circuitVer,
		SessionBinding: sb,
		Capability:     capability,
		Clearance:      clearance,
		ExpiryEpoch:    expiry,
		Salt:           salt,
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := registry.Setup(dir); err != nil {
		t.Fatalf("setup: %v", err)
	}

	art, err := prover.LoadArtifacts(dir)
	if err != nil {
		t.Fatalf("load artifacts: %v", err)
	}
	v, err := verifier.Load(dir)
	if err != nil {
		t.Fatalf("load verifier: %v", err)
	}

	a := buildValid(t, "action-A")
	proof, pub, err := art.Prove(a)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	ok, err := v.Verify(proof, pub)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !ok {
		t.Fatal("valid proof did not verify")
	}

	// Action binding: verify the Action-A proof against Action-B's public inputs.
	b := buildValid(t, "action-B")
	pwB, err := prover.PublicWitnessFrom(b)
	if err != nil {
		t.Fatalf("public witness B: %v", err)
	}
	pwBytes, err := pwB.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ok, err = v.Verify(proof, pwBytes)
	if err != nil {
		t.Fatalf("verify B err: %v", err)
	}
	if ok {
		t.Fatal("proof for Action A verified against Action B public inputs (§4.11 violation)")
	}
}

func TestWrongCapabilityFailsToProve(t *testing.T) {
	dir := t.TempDir()
	if _, err := registry.Setup(dir); err != nil {
		t.Fatalf("setup: %v", err)
	}
	art, err := prover.LoadArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := buildValid(t, "action-A")
	// RequiredCapability differs from the credential's capability -> unsatisfiable.
	a.RequiredCapability = bridge.CapabilityField("db:write")
	if _, _, err := art.Prove(a); err == nil {
		t.Fatal("expected prove to fail on capability mismatch")
	}
}

func TestInsufficientClearanceFailsToProve(t *testing.T) {
	dir := t.TempDir()
	if _, err := registry.Setup(dir); err != nil {
		t.Fatalf("setup: %v", err)
	}
	art, err := prover.LoadArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := buildValid(t, "action-A")
	// require clearance 5 but credential clearance is 3 -> unsatisfiable.
	a.RequiredClearance = big.NewInt(5)
	if _, _, err := art.Prove(a); err == nil {
		t.Fatal("expected prove to fail on insufficient clearance")
	}
}
