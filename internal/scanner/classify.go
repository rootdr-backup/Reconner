package scanner

// classify.go centralises the Finding-vs-Candidate decision and the confidence
// bands defined in the scanning spec. Every module funnels its verdict through
// here so the rule is applied identically everywhere:
//
//	100      → proven with a working PoC / out-of-band callback
//	 95      → confirmed by 2+ independent tools/signals
//	 90      → single evidence-based confirmation (exact reflection, magic bytes)
//	 70–89   → candidate: suggestive but unconfirmed
//	 <70     → hidden (too weak to surface)
//
// >=90 ⇒ status "finding"; 70–89 ⇒ "candidate"; <70 ⇒ dropped by the caller.

const (
	// Canonical confidence values for the common proof levels.
	ConfPoC          = 100 // working proof-of-concept / OOB callback
	ConfMultiTool    = 95  // two or more independent tools agree
	ConfEvidence     = 90  // one solid evidence-based signal
	ConfCandidateHi  = 85  // strong but single-signal / heuristic
	ConfCandidateLo  = 70  // weak candidate, still worth surfacing
	ConfHiddenCutoff = 70  // below this: do not store
)

// StatusFinding / StatusCandidate are the two persisted states.
const (
	StatusFinding   = "finding"
	StatusCandidate = "candidate"
)

// ClassifyStatus maps a confidence score to a persisted status. Returns
// ("", false) when the score is below the surfacing cutoff (caller drops it).
func ClassifyStatus(confidence int) (string, bool) {
	switch {
	case confidence >= ConfEvidence:
		return StatusFinding, true
	case confidence >= ConfHiddenCutoff:
		return StatusCandidate, true
	default:
		return "", false
	}
}

// IsFinding reports whether a confidence score qualifies as a confirmed finding.
func IsFinding(confidence int) bool {
	return confidence >= ConfEvidence
}
