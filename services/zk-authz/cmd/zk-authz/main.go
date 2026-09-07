// Command zk-authz is the narrow internal ZK-authorization service invoked as a
// subprocess by the Python control plane (spec §60.5). It speaks JSON over
// stdin/stdout with subcommands: setup, issue, encode, prove, verify, bench.
//
// Security notes:
//   - The verifier ALWAYS loads the VK from the pinned artifact directory; there
//     is no path by which a client supplies its own VK.
//   - Any error is reported as a JSON object with "error" set and a non-zero
//     exit code so the Python caller fails closed.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark/logger"

	"cvztte/zkauthz/bridge"
	"cvztte/zkauthz/credential"
	"cvztte/zkauthz/prover"
	"cvztte/zkauthz/registry"
	"cvztte/zkauthz/verifier"
)

func main() {
	// gnark logs to stdout by default; the CLI contract reserves stdout for the
	// JSON result, so route all gnark logging to stderr.
	logger.SetOutput(os.Stderr)

	if len(os.Args) < 2 {
		fail("usage: zk-authz <setup|issue|encode|prove|verify|bench> [args]")
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "issue":
		err = cmdIssue()
	case "encode":
		err = cmdEncode()
	case "prove":
		err = cmdProve()
	case "verify":
		err = cmdVerify()
	case "bench":
		err = cmdBench()
	default:
		fail("unknown subcommand: " + os.Args[1])
	}
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	out, _ := json.Marshal(map[string]string{"error": msg})
	fmt.Fprintln(os.Stdout, string(out))
	os.Exit(1)
}

func emit(v interface{}) error {
	out, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

func readInput(v interface{}) error {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// bigFromDec parses a base-10 big integer; empty -> error.
func bigFromDec(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal integer: %q", s)
	}
	return n, nil
}

// ---- setup ----

func cmdSetup(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("setup requires exactly one arg: <artifact_dir>")
	}
	m, err := registry.Setup(args[0])
	if err != nil {
		return err
	}
	return emit(m)
}

// ---- encode (bridge; used by substitution tests) ----

type encodeReq struct {
	Sha256     string `json:"sha256,omitempty"`
	Capability string `json:"capability,omitempty"`
}

type encodeResp struct {
	Hi       string `json:"hi,omitempty"`
	Lo       string `json:"lo,omitempty"`
	CapField string `json:"cap_field,omitempty"`
}

func cmdEncode() error {
	var req encodeReq
	if err := readInput(&req); err != nil {
		return err
	}
	var resp encodeResp
	if req.Sha256 != "" {
		hi, lo, err := bridge.Sha256HexToLimbs(req.Sha256)
		if err != nil {
			return err
		}
		resp.Hi = hi.String()
		resp.Lo = lo.String()
	}
	if req.Capability != "" {
		resp.CapField = bridge.CapabilityField(req.Capability).String()
	}
	return emit(resp)
}

// ---- issue (credential commitment; trusted admin path) ----

type issueReq struct {
	AgentHi     string `json:"agent_hi"`
	AgentLo     string `json:"agent_lo"`
	Capability  string `json:"capability"`
	Clearance   string `json:"clearance"`
	ExpiryEpoch string `json:"expiry_epoch"`
	ScopeHi     string `json:"scope_hi"`
	ScopeLo     string `json:"scope_lo"`
	PolicyHi    string `json:"policy_hi"`
	PolicyLo    string `json:"policy_lo"`
	Salt        string `json:"salt"`
	// session binding inputs
	ActionHi   string `json:"action_hi"`
	ActionLo   string `json:"action_lo"`
	Epoch      string `json:"epoch"`
	CircuitVer string `json:"circuit_ver"`
}

type issueResp struct {
	CredentialCommitment string `json:"credential_commitment"`
	SessionBinding       string `json:"session_binding"`
}

func cmdIssue() error {
	var req issueReq
	if err := readInput(&req); err != nil {
		return err
	}
	fields := map[string]*big.Int{}
	for name, s := range map[string]string{
		"agent_hi": req.AgentHi, "agent_lo": req.AgentLo, "capability": req.Capability,
		"clearance": req.Clearance, "expiry_epoch": req.ExpiryEpoch,
		"scope_hi": req.ScopeHi, "scope_lo": req.ScopeLo,
		"policy_hi": req.PolicyHi, "policy_lo": req.PolicyLo, "salt": req.Salt,
		"action_hi": req.ActionHi, "action_lo": req.ActionLo,
		"epoch": req.Epoch, "circuit_ver": req.CircuitVer,
	} {
		n, err := bigFromDec(s)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fields[name] = n
	}
	attrs := credential.Attributes{
		AgentHi: fields["agent_hi"], AgentLo: fields["agent_lo"],
		Capability: fields["capability"], Clearance: fields["clearance"],
		ExpiryEpoch: fields["expiry_epoch"],
		ScopeHi:     fields["scope_hi"], ScopeLo: fields["scope_lo"],
		PolicyHi: fields["policy_hi"], PolicyLo: fields["policy_lo"],
		Salt: fields["salt"],
	}
	cred := credential.Commit(attrs)
	sb := credential.SessionBinding(cred, fields["action_hi"], fields["action_lo"], fields["epoch"], fields["circuit_ver"])
	return emit(issueResp{
		CredentialCommitment: cred.String(),
		SessionBinding:       sb.String(),
	})
}

// ---- prove ----

// assignmentReq mirrors prover.Assignment with all values as decimal strings.
type assignmentReq struct {
	ArtifactDir string `json:"artifact_dir"`
	// public
	AgentHi              string `json:"agent_hi"`
	AgentLo              string `json:"agent_lo"`
	CredentialCommitment string `json:"credential_commitment"`
	RequiredCapability   string `json:"required_capability"`
	RequiredClearance    string `json:"required_clearance"`
	CurrentEpoch         string `json:"current_epoch"`
	ActionHi             string `json:"action_hi"`
	ActionLo             string `json:"action_lo"`
	PolicyHi             string `json:"policy_hi"`
	PolicyLo             string `json:"policy_lo"`
	ScopeHi              string `json:"scope_hi"`
	ScopeLo              string `json:"scope_lo"`
	CircuitVer           string `json:"circuit_ver"`
	SessionBinding       string `json:"session_binding"`
	// private
	Capability  string `json:"capability"`
	Clearance   string `json:"clearance"`
	ExpiryEpoch string `json:"expiry_epoch"`
	Salt        string `json:"salt"`
}

func (r assignmentReq) toAssignment() (prover.Assignment, error) {
	get := func(s string) (*big.Int, error) { return bigFromDec(s) }
	fields := []struct {
		name string
		src  string
		dst  **big.Int
	}{}
	var a prover.Assignment
	fields = append(fields,
		f("agent_hi", r.AgentHi, &a.AgentHi),
		f("agent_lo", r.AgentLo, &a.AgentLo),
		f("credential_commitment", r.CredentialCommitment, &a.CredentialCommitment),
		f("required_capability", r.RequiredCapability, &a.RequiredCapability),
		f("required_clearance", r.RequiredClearance, &a.RequiredClearance),
		f("current_epoch", r.CurrentEpoch, &a.CurrentEpoch),
		f("action_hi", r.ActionHi, &a.ActionHi),
		f("action_lo", r.ActionLo, &a.ActionLo),
		f("policy_hi", r.PolicyHi, &a.PolicyHi),
		f("policy_lo", r.PolicyLo, &a.PolicyLo),
		f("scope_hi", r.ScopeHi, &a.ScopeHi),
		f("scope_lo", r.ScopeLo, &a.ScopeLo),
		f("circuit_ver", r.CircuitVer, &a.CircuitVer),
		f("session_binding", r.SessionBinding, &a.SessionBinding),
		f("capability", r.Capability, &a.Capability),
		f("clearance", r.Clearance, &a.Clearance),
		f("expiry_epoch", r.ExpiryEpoch, &a.ExpiryEpoch),
		f("salt", r.Salt, &a.Salt),
	)
	for _, fl := range fields {
		n, err := get(fl.src)
		if err != nil {
			return a, fmt.Errorf("%s: %w", fl.name, err)
		}
		*fl.dst = n
	}
	return a, nil
}

func f(name, src string, dst **big.Int) struct {
	name string
	src  string
	dst  **big.Int
} {
	return struct {
		name string
		src  string
		dst  **big.Int
	}{name, src, dst}
}

type proveResp struct {
	Proof         string `json:"proof"`
	PublicWitness string `json:"public_witness"`
}

func cmdProve() error {
	var req assignmentReq
	if err := readInput(&req); err != nil {
		return err
	}
	if req.ArtifactDir == "" {
		return fmt.Errorf("artifact_dir is required")
	}
	a, err := req.toAssignment()
	if err != nil {
		return err
	}
	art, err := prover.LoadArtifacts(req.ArtifactDir)
	if err != nil {
		return err
	}
	proof, pub, err := art.Prove(a)
	if err != nil {
		return err
	}
	return emit(proveResp{
		Proof:         base64.StdEncoding.EncodeToString(proof),
		PublicWitness: base64.StdEncoding.EncodeToString(pub),
	})
}

// ---- verify ----

type verifyReq struct {
	ArtifactDir   string `json:"artifact_dir"`
	Proof         string `json:"proof"`
	PublicWitness string `json:"public_witness"`
}

type verifyResp struct {
	Verified        bool   `json:"verified"`
	CircuitVersion  int    `json:"circuit_version"`
	VerificationKey string `json:"verification_key_hash"`
}

func cmdVerify() error {
	var req verifyReq
	if err := readInput(&req); err != nil {
		return err
	}
	if req.ArtifactDir == "" {
		return fmt.Errorf("artifact_dir is required")
	}
	proof, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil {
		return fmt.Errorf("decode proof b64: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicWitness)
	if err != nil {
		return fmt.Errorf("decode public_witness b64: %w", err)
	}
	v, err := verifier.Load(req.ArtifactDir)
	if err != nil {
		return err
	}
	ok, err := v.Verify(proof, pub)
	if err != nil {
		return err
	}
	return emit(verifyResp{
		Verified:        ok,
		CircuitVersion:  v.Manifest.CircuitVersion,
		VerificationKey: v.Manifest.VerificationKeyHash,
	})
}

// ---- bench ----

type benchReq struct {
	ArtifactDir string `json:"artifact_dir"`
	Iterations  int    `json:"iterations"`
	// A full assignment to prove repeatedly.
	Assignment assignmentReq `json:"assignment"`
}

type benchResp struct {
	Iterations       int     `json:"iterations"`
	ProvingSystem    string  `json:"proving_system"`
	Curve            string  `json:"curve"`
	AvgProveMillis   float64 `json:"avg_prove_ms"`
	AvgVerifyMillis  float64 `json:"avg_verify_ms"`
	ProofBytes       int     `json:"proof_bytes"`
	PublicInputCount int     `json:"public_input_count"`
}

func cmdBench() error {
	var req benchReq
	if err := readInput(&req); err != nil {
		return err
	}
	if req.Iterations <= 0 {
		req.Iterations = 10
	}
	a, err := req.Assignment.toAssignment()
	if err != nil {
		return err
	}
	art, err := prover.LoadArtifacts(req.ArtifactDir)
	if err != nil {
		return err
	}
	v, err := verifier.Load(req.ArtifactDir)
	if err != nil {
		return err
	}

	var proveTotal, verifyTotal time.Duration
	var proofBytes int
	for i := 0; i < req.Iterations; i++ {
		t0 := time.Now()
		proof, pub, err := art.Prove(a)
		if err != nil {
			return err
		}
		proveTotal += time.Since(t0)
		proofBytes = len(proof)

		t1 := time.Now()
		ok, err := v.Verify(proof, pub)
		if err != nil {
			return err
		}
		verifyTotal += time.Since(t1)
		if !ok {
			return fmt.Errorf("bench: proof failed to verify at iteration %d", i)
		}
	}
	n := float64(req.Iterations)
	return emit(benchResp{
		Iterations:       req.Iterations,
		ProvingSystem:    registry.ProvingSystem,
		Curve:            registry.Curve,
		AvgProveMillis:   float64(proveTotal.Microseconds()) / n / 1000.0,
		AvgVerifyMillis:  float64(verifyTotal.Microseconds()) / n / 1000.0,
		ProofBytes:       proofBytes,
		PublicInputCount: 14,
	})
}
