package scanner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Unified vulnerability candidate lifecycle (Phase 1). Detectors emit a
// normalized VulnerabilityCandidate instead of writing straight to vuln_findings;
// the VerificationOrchestrator promotes only PROVEN candidates. This makes
// "detection ≠ verification ≠ finding" a real, queryable state machine — the
// authz engine already worked this way; this generalizes it.

// Candidate lifecycle statuses.
const (
	CandDetected     = "DETECTED"
	CandTriaged      = "TRIAGED"
	CandVerifying    = "VERIFYING"
	CandVerified     = "VERIFIED"
	CandConfirmed    = "CONFIRMED"
	CandRejected     = "REJECTED"
	CandInconclusive = "INCONCLUSIVE"
	CandDuplicate    = "DUPLICATE"
)

// VulnerabilityCandidate is the normalized pre-finding record every detector can
// produce.
type VulnerabilityCandidate struct {
	ID              string
	TargetID        string
	Type            string // sqli | xss | cmdi | ssti | ssrf | nuclei | …
	Subtype         string
	URL             string
	Method          string
	Parameter       string
	Location        string // query|body|json|header|cookie|path
	Payload         string
	DetectionSource string // internal | nuclei | dalfox | …
	DetectionMethod string // boolean-diff | timing | reflection | template:<id> …
	Severity        string
	Confidence      int
	Status          string
	Evidence        string
}

// Fingerprint uniquely identifies a candidate (type+endpoint-template+param+loc)
// so the same signal from the same place dedups instead of piling up.
func (c VulnerabilityCandidate) Fingerprint() string {
	h := sha1.Sum([]byte(c.Type + "|" + NormalizeURL(c.URL) + "|" + c.Parameter + "|" + c.Location))
	return hex.EncodeToString(h[:])
}

// StoreCandidate upserts a candidate (dedup by fingerprint), returning its id.
func StoreCandidate(ctx context.Context, db *database.DB, c VulnerabilityCandidate) string {
	if c.Status == "" {
		c.Status = CandDetected
	}
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.Location == "" {
		c.Location = "query"
	}
	fp := c.Fingerprint()
	id := uuid.New().String()
	_, _ = db.ExecContext(ctx, `
		INSERT INTO candidates (id, target_id, type, subtype, url, method, parameter, location, payload,
			detection_source, detection_method, severity, confidence, status, evidence, fingerprint)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, fingerprint) DO UPDATE SET
			confidence=MAX(candidates.confidence, excluded.confidence),
			payload=excluded.payload, evidence=excluded.evidence`,
		id, c.TargetID, c.Type, c.Subtype, c.URL, c.Method, c.Parameter, c.Location, c.Payload,
		c.DetectionSource, c.DetectionMethod, c.Severity, c.Confidence, c.Status, c.Evidence, fp)
	var out string
	_ = db.QueryRowContext(ctx, `SELECT id FROM candidates WHERE target_id=? AND fingerprint=?`, c.TargetID, fp).Scan(&out)
	if out == "" {
		out = id
	}
	return out
}

// SetCandidateStatus records a verification result on a candidate. It is the
// backward-compatible entry point every existing detector/verifier already uses;
// its implementation now goes through the guarded lifecycle state machine
// (lifecycle.go) so terminal states can't be silently overwritten, transitions
// are concurrency-safe and idempotent, they are audited, and the linked
// vuln_findings projection is kept consistent. Signature unchanged on purpose.
func SetCandidateStatus(ctx context.Context, db *database.DB, id, status, method, reason string, confidence int) {
	applyState(ctx, db, id, status, "detector", method, reason, confidence, false)
}
