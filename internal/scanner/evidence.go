package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Structured evidence engine (P0-2 / Phase 7). Findings get reproducible,
// REDACTED request/response evidence — including the per-identity pair for
// cross-identity findings — instead of a prose string.

// EvidenceItem is one request/response observation attached to a finding.
type EvidenceItem struct {
	IdentityLabel string
	Request       string // human-readable request line + safe headers (redacted)
	Response      string // status + safe headers + truncated body (redacted)
	Comparison    string // what this proves relative to other identities
}

// StoreEvidence persists a set of evidence items for a finding, redacting
// credentials from every field first. Returns the number stored.
func StoreEvidence(ctx context.Context, db *database.DB, findingID, targetID, kind, note string, items []EvidenceItem) int {
	n := 0
	for _, it := range items {
		id := uuid.New().String()
		_, err := db.ExecContext(ctx, `
			INSERT INTO evidence (id, finding_id, target_id, kind, identity_label, request_text, response_text, comparison, note)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, findingID, targetID, kind, it.IdentityLabel,
			RedactText(it.Request), RedactText(it.Response), RedactText(it.Comparison), RedactText(note))
		if err == nil {
			n++
		}
	}
	return n
}

// withComparison attaches a comparison note to an evidence item.
func withComparison(it EvidenceItem, comparison string) EvidenceItem {
	it.Comparison = comparison
	return it
}

// evidenceFromResponse renders a compact, safe request/response transcript for a
// single identity's view of a URL.
func evidenceFromResponse(method, url string, id Identity, r IdentityResponse) EvidenceItem {
	if method == "" {
		method = "GET"
	}
	// Request line + a note that auth was present (values redacted, keys shown).
	var reqB strings.Builder
	fmt.Fprintf(&reqB, "%s %s HTTP/1.1\n", method, url)
	if len(id.Headers) > 0 {
		for k := range RedactHeaders(id.Headers) {
			fmt.Fprintf(&reqB, "%s: [REDACTED]\n", k)
		}
	} else {
		reqB.WriteString("(no authentication — unauthenticated request)\n")
	}

	body := r.Body
	if len(body) > 1500 {
		body = body[:1500] + "\n…(truncated)"
	}
	respTxt := fmt.Sprintf("HTTP %d  (%s, %d bytes)\n\n%s", r.Status, r.CT, r.Len, body)

	return EvidenceItem{
		IdentityLabel: id.Label,
		Request:       reqB.String(),
		Response:      respTxt,
	}
}
