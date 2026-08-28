package scanner

import "context"

// Verification Orchestrator (Phase 6). Each vuln class has its own PROOF
// technique; a Verifier exposes CanVerify/Verify and returns a decisive verdict
// with confidence, evidence and reason. Detectors never self-confirm — the
// orchestrator routes a candidate to the right verifier and only a VERIFIED
// result may become a finding.

// Verdicts.
const (
	VerifyVerified     = "VERIFIED"
	VerifyRejected     = "REJECTED"
	VerifyInconclusive = "INCONCLUSIVE"
)

// VerifyResult is a verifier's decision.
type VerifyResult struct {
	Verdict    string // VERIFIED | REJECTED | INCONCLUSIVE
	Confidence int
	Evidence   string
	Reason     string // esp. for INCONCLUSIVE (WAF/rate-limit/session/etc.)
	Method     string // which verifier/technique
}

// Verifier proves (or refutes) a candidate by its class-appropriate technique.
type Verifier interface {
	Name() string
	CanVerify(c VulnerabilityCandidate) bool
	Verify(ctx context.Context, c VulnerabilityCandidate) VerifyResult
}

// Orchestrator holds the registered verifiers and routes candidates.
type Orchestrator struct {
	verifiers []Verifier
}

func NewOrchestrator(vs ...Verifier) *Orchestrator { return &Orchestrator{verifiers: vs} }

// Register adds a verifier.
func (o *Orchestrator) Register(v Verifier) { o.verifiers = append(o.verifiers, v) }

// Verify routes a candidate to the first verifier that can handle it. If none
// can, the result is INCONCLUSIVE (never a silent false-confirm).
func (o *Orchestrator) Verify(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	for _, v := range o.verifiers {
		if v.CanVerify(c) {
			r := v.Verify(ctx, c)
			if r.Method == "" {
				r.Method = v.Name()
			}
			return r
		}
	}
	return VerifyResult{Verdict: VerifyInconclusive, Reason: "no verifier available for type " + c.Type, Method: "none"}
}
