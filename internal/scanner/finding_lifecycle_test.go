package scanner

import (
	"context"
	"testing"
)

func TestRecordCandidateResultProjectsConfirmedFinding(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	c := VulnerabilityCandidate{
		TargetID: tid, Type: "xss", Subtype: "reflected", URL: "https://example.test/?q=1",
		Method: "GET", Parameter: "q", Location: "query", DetectionSource: "test",
		DetectionMethod: "browser", Severity: "high", Payload: "<svg onload=alert(1)>",
	}
	id, err := RecordCandidateResult(context.Background(), db, c, VerifyResult{
		Verdict: VerifyVerified, Confidence: 99, Evidence: "execution proof", Method: "browser",
	}, FindingMeta{Actor: "test"})
	if err != nil {
		t.Fatalf("record result: %v", err)
	}
	var state string
	if err := db.QueryRow(`SELECT status FROM candidates WHERE id=?`, id).Scan(&state); err != nil || state != CandConfirmed {
		t.Fatalf("candidate state=%q err=%v", state, err)
	}
	var status, candidateID, lifecycle string
	if err := db.QueryRow(`SELECT status,candidate_id,lifecycle FROM vuln_findings WHERE target_id=? AND type='xss'`, tid).
		Scan(&status, &candidateID, &lifecycle); err != nil {
		t.Fatalf("finding projection: %v", err)
	}
	if status != StatusFinding || candidateID != id || lifecycle != CandConfirmed {
		t.Fatalf("projection status=%q candidate=%q lifecycle=%q", status, candidateID, lifecycle)
	}
}

func TestRejectedCandidateCanReopenOnFreshProof(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	c := VulnerabilityCandidate{TargetID: tid, Type: "xss", Subtype: "reflected",
		URL: "https://example.test/?q=1", Method: "GET", Parameter: "q", Location: "query",
		DetectionSource: "test", DetectionMethod: "context", Severity: "high", Confidence: 70}
	id, err := RecordCandidateResult(context.Background(), db, c,
		VerifyResult{Verdict: VerifyRejected, Method: "context", Reason: "encoded"}, FindingMeta{Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := candidateState(context.Background(), db, id); got != CandRejected {
		t.Fatalf("first state=%q", got)
	}
	id2, err := RecordCandidateResult(context.Background(), db, c,
		VerifyResult{Verdict: VerifyVerified, Confidence: 99, Method: "browser", Evidence: "executed"}, FindingMeta{Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id || candidateState(context.Background(), db, id) != CandConfirmed {
		t.Fatalf("candidate did not reopen/confirm: id=%q id2=%q state=%q", id, id2, candidateState(context.Background(), db, id))
	}
}

func TestDetectorSignalStaysQueuedForVerifier(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	c := VulnerabilityCandidate{
		TargetID: tid, Type: "sqli", Subtype: "error-based", URL: "https://x.test/?id=1",
		Method: "GET", Parameter: "id", Location: "query", DetectionSource: "dast",
		DetectionMethod: "error-diff", Severity: "high", Confidence: 80, Evidence: "new SQL error",
	}
	id, err := RecordCandidateDetection(context.Background(), db, c, FindingMeta{Actor: "dast"})
	if err != nil {
		t.Fatal(err)
	}
	if got := candState(t, db, id); got != CandDetected {
		t.Fatalf("detector-only signal left verifier queue: got %s", got)
	}
	var findingStatus string
	if err := db.QueryRow(`SELECT status FROM vuln_findings WHERE candidate_id=?`, id).Scan(&findingStatus); err != nil {
		t.Fatalf("visible high-confidence candidate was not projected: %v", err)
	}
	if findingStatus != StatusCandidate {
		t.Fatalf("projected detector signal status=%q", findingStatus)
	}
}

func TestExistingCandidateResultUsesCandidateID(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	c := VulnerabilityCandidate{
		TargetID: tid, Type: "xss", Subtype: "reflected", URL: "https://x.test/?q=1",
		Method: "POST", Parameter: "q", Location: "body", DetectionSource: "nuclei",
		DetectionMethod: "template:xss", Severity: "high", Confidence: 75,
	}
	id, err := RecordCandidateDetection(context.Background(), db, c, FindingMeta{Actor: "nuclei"})
	if err != nil {
		t.Fatal(err)
	}
	// Verifiers commonly only know the row id and proof. They must update that
	// exact observation instead of deriving a second fingerprint from sparse data.
	_, err = RecordCandidateResult(context.Background(), db, VulnerabilityCandidate{ID: id, Payload: "working"},
		VerifyResult{Verdict: VerifyVerified, Confidence: 99, Method: "browser", Evidence: "executed"},
		FindingMeta{Actor: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	var candidates int
	_ = db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=?`, tid).Scan(&candidates)
	if candidates != 1 {
		t.Fatalf("sparse verifier result split one observation into %d candidates", candidates)
	}
	if got := candState(t, db, id); got != CandConfirmed {
		t.Fatalf("existing candidate state=%s", got)
	}
}
