package scanner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

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

// Fingerprint uniquely identifies one detector observation. Subtype, method and
// detection source are deliberately part of the identity: a rejected reflected
// XSS observation must never poison a later DOM-XSS/browser observation at the
// same URL+parameter, and GET/POST observations need independent lifecycles.
func (c VulnerabilityCandidate) Fingerprint() string {
	h := sha1.Sum([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(c.Type)),
		strings.ToLower(strings.TrimSpace(c.Subtype)),
		strings.ToUpper(strings.TrimSpace(c.Method)),
		NormalizeURL(c.URL),
		strings.ToLower(strings.TrimSpace(c.Parameter)),
		strings.ToLower(strings.TrimSpace(c.Location)),
		strings.ToLower(strings.TrimSpace(c.DetectionSource)),
	}, "|")))
	return hex.EncodeToString(h[:])
}

// StoreCandidateE upserts a DETECTED observation and returns its authoritative
// candidate id. Outcome states are never accepted here: every verifier result
// must pass through RecordCandidateResult/TransitionCandidate so the audit trail
// and finding projection cannot be bypassed.
func StoreCandidateE(ctx context.Context, db *database.DB, c VulnerabilityCandidate) (string, error) {
	if db == nil {
		return "", fmt.Errorf("candidate store: nil database")
	}
	if strings.TrimSpace(c.TargetID) == "" || strings.TrimSpace(c.Type) == "" || strings.TrimSpace(c.URL) == "" {
		return "", fmt.Errorf("candidate store: target_id, type and url are required")
	}
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.Location == "" {
		c.Location = "query"
	}
	fp := c.Fingerprint()
	id := uuid.New().String()
	_, err := db.ExecContext(ctx, `
		INSERT INTO candidates (id, target_id, type, subtype, url, method, parameter, location, payload,
			detection_source, detection_method, severity, confidence, status, evidence, fingerprint)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id, fingerprint) DO UPDATE SET
			confidence=MAX(candidates.confidence, excluded.confidence),
			payload=CASE WHEN excluded.payload<>'' THEN excluded.payload ELSE candidates.payload END,
			evidence=CASE WHEN excluded.evidence<>'' THEN excluded.evidence ELSE candidates.evidence END,
			detection_method=CASE WHEN excluded.detection_method<>'' THEN excluded.detection_method ELSE candidates.detection_method END,
			severity=CASE WHEN excluded.severity<>'' THEN excluded.severity ELSE candidates.severity END`,
		id, c.TargetID, c.Type, c.Subtype, c.URL, c.Method, c.Parameter, c.Location, c.Payload,
		c.DetectionSource, c.DetectionMethod, c.Severity, c.Confidence, CandDetected, c.Evidence, fp)
	if err != nil {
		return "", fmt.Errorf("candidate store: %w", err)
	}
	var out string
	if err := db.QueryRowContext(ctx, `SELECT id FROM candidates WHERE target_id=? AND fingerprint=?`, c.TargetID, fp).Scan(&out); err != nil {
		return "", fmt.Errorf("candidate lookup: %w", err)
	}
	if out == "" {
		out = id
	}
	return out, nil
}

// StoreCandidate is the compatibility wrapper used by detection-only paths.
// New code that projects a result should use RecordCandidateResult.
func StoreCandidate(ctx context.Context, db *database.DB, c VulnerabilityCandidate) string {
	id, _ := StoreCandidateE(ctx, db, c)
	return id
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
