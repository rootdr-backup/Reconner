package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// FindingMeta contains projection-only fields. The candidate remains the
// authoritative detection/verification record; vuln_findings is just the UI and
// report projection of that state.
type FindingMeta struct {
	Priority   int
	Provenance string
	Actor      string
}

// DetectorObservation is the small adapter used by production detectors while
// they migrate off direct vuln_findings writes. Verdict must be DETECTED for a
// signal awaiting another verifier, or one of the three Verify* results when the
// detector has already performed a class-specific proof/refutation step.
type DetectorObservation struct {
	TargetID, Type, Subtype, Severity string
	URL, Method, Parameter, Location  string
	Payload, Evidence                 string
	Source, DetectionMethod           string
	Confidence, Priority              int
	Provenance, Verdict               string
}

type ObservationIDs struct {
	CandidateID string
	FindingID   string
}

// RecordDetectorObservation guarantees that every production detector uses the
// same candidate identity, transition audit and finding projection rules.
func RecordDetectorObservation(ctx context.Context, db *database.DB, o DetectorObservation) (ObservationIDs, error) {
	if o.Source == "" {
		o.Source = "internal"
	}
	if o.DetectionMethod == "" {
		o.DetectionMethod = "detector:" + strings.TrimSpace(o.Type)
	}
	c := VulnerabilityCandidate{
		TargetID: o.TargetID, Type: o.Type, Subtype: o.Subtype, Severity: o.Severity,
		URL: o.URL, Method: o.Method, Parameter: o.Parameter, Location: o.Location,
		Payload: o.Payload, Evidence: o.Evidence, DetectionSource: o.Source,
		DetectionMethod: o.DetectionMethod, Confidence: o.Confidence,
	}
	meta := FindingMeta{Actor: o.Source, Priority: o.Priority, Provenance: o.Provenance}
	var (
		id  string
		err error
	)
	if o.Verdict == CandDetected {
		id, err = RecordCandidateDetection(ctx, db, c, meta)
	} else {
		id, err = RecordCandidateResult(ctx, db, c, VerifyResult{
			Verdict: o.Verdict, Confidence: o.Confidence, Evidence: o.Evidence,
			Reason: o.Evidence, Method: o.DetectionMethod,
		}, meta)
	}
	ids := ObservationIDs{CandidateID: id}
	if err != nil || id == "" {
		return ids, err
	}
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(finding_id,'') FROM candidates WHERE id=?`, id).Scan(&ids.FindingID)
	return ids, nil
}

// RecordCandidateDetection is the canonical detector-only path. A detector has
// observed a signal, but no class-specific verifier has made a decision yet, so
// the lifecycle intentionally remains DETECTED. Conflating this state with
// INCONCLUSIVE would remove the row from verifier work queues (for example the
// sqlmap pass) and create a silent false negative.
func RecordCandidateDetection(ctx context.Context, db *database.DB, c VulnerabilityCandidate, meta FindingMeta) (string, error) {
	if meta.Actor == "" {
		meta.Actor = strings.TrimSpace(c.DetectionSource)
		if meta.Actor == "" {
			meta.Actor = "detector"
		}
	}
	if c.DetectionMethod == "" {
		c.DetectionMethod = meta.Actor
	}
	id, err := StoreCandidateE(ctx, db, c)
	if err != nil {
		return "", err
	}
	state := candidateState(ctx, db, id)
	// A new observation may legitimately re-open a previous negative/unknown
	// result. CONFIRMED is sticky and is never downgraded by detector traffic.
	if state == CandRejected || state == CandInconclusive {
		if reopenCandidate(ctx, db, id, meta.Actor, c.DetectionMethod, "fresh detector observation") {
			state = CandDetected
		} else {
			state = candidateState(ctx, db, id)
		}
	}
	projection := VerifyResult{
		Confidence: c.Confidence,
		Evidence:   c.Evidence,
		Reason:     "awaiting class-specific verification",
		Method:     c.DetectionMethod,
	}
	if err := upsertFindingProjection(ctx, db, id, c, projection, state, meta); err != nil {
		return id, err
	}
	return id, nil
}

func loadCandidateForResult(ctx context.Context, db *database.DB, id string) (VulnerabilityCandidate, error) {
	var c VulnerabilityCandidate
	c.ID = id
	err := db.QueryRowContext(ctx, `SELECT target_id,type,COALESCE(subtype,''),url,COALESCE(method,'GET'),
		COALESCE(parameter,''),COALESCE(location,'query'),COALESCE(payload,''),COALESCE(detection_source,''),
		COALESCE(detection_method,''),COALESCE(severity,''),COALESCE(confidence,0),COALESCE(evidence,'')
		FROM candidates WHERE id=?`, id).Scan(&c.TargetID, &c.Type, &c.Subtype, &c.URL, &c.Method,
		&c.Parameter, &c.Location, &c.Payload, &c.DetectionSource, &c.DetectionMethod,
		&c.Severity, &c.Confidence, &c.Evidence)
	if err != nil {
		return c, fmt.Errorf("candidate result lookup: %w", err)
	}
	return c, nil
}

// RecordCandidateResult is the only production path that may turn a detector
// observation into a surfaced candidate/finding. It enforces the same lifecycle
// for every detector:
//
//	DETECTED -> VERIFYING -> VERIFIED -> CONFIRMED
//	                         |-> REJECTED / INCONCLUSIVE
//
// Verified results are clamped to the evidence bar. Inconclusive results are
// projected only when they meet the candidate visibility bar; weaker signals
// remain queryable in candidates without polluting the UI/report.
func RecordCandidateResult(ctx context.Context, db *database.DB, c VulnerabilityCandidate, result VerifyResult, meta FindingMeta) (string, error) {
	if result.Verdict != VerifyVerified && result.Verdict != VerifyRejected && result.Verdict != VerifyInconclusive {
		return "", fmt.Errorf("candidate result: unknown verdict %q", result.Verdict)
	}
	if meta.Actor == "" {
		meta.Actor = strings.TrimSpace(c.DetectionSource)
		if meta.Actor == "" {
			meta.Actor = "detector"
		}
	}
	if result.Method == "" {
		result.Method = strings.TrimSpace(c.DetectionMethod)
		if result.Method == "" {
			result.Method = meta.Actor
		}
	}
	if result.Evidence == "" {
		result.Evidence = c.Evidence
	}
	if result.Confidence <= 0 && result.Verdict != VerifyRejected {
		result.Confidence = c.Confidence
	}
	if result.Verdict == VerifyVerified && result.Confidence < ConfEvidence {
		result.Confidence = ConfEvidence
	}
	c.Confidence = result.Confidence
	if result.Evidence != "" {
		c.Evidence = result.Evidence
	}

	var (
		id  string
		err error
	)
	if strings.TrimSpace(c.ID) != "" {
		id = strings.TrimSpace(c.ID)
		stored, loadErr := loadCandidateForResult(ctx, db, id)
		if loadErr != nil {
			return "", loadErr
		}
		// The stored observation is authoritative for identity/projection fields;
		// a verifier may supply a better working payload/evidence.
		if c.Payload != "" {
			stored.Payload = c.Payload
		}
		if c.Evidence != "" {
			stored.Evidence = c.Evidence
		}
		if c.Severity != "" {
			stored.Severity = c.Severity
		}
		c = stored
		_, err = db.ExecContext(ctx, `UPDATE candidates SET
			confidence=MAX(COALESCE(confidence,0),?),
			payload=CASE WHEN ?<>'' THEN ? ELSE payload END,
			evidence=CASE WHEN ?<>'' THEN ? ELSE evidence END
			WHERE id=?`, result.Confidence, c.Payload, c.Payload, result.Evidence, RedactText(result.Evidence), id)
	} else {
		id, err = StoreCandidateE(ctx, db, c)
	}
	if err != nil {
		return "", err
	}

	state := candidateState(ctx, db, id)
	// A rejected/inconclusive observation is not a lifetime suppression rule. A
	// later scan with fresh evidence may re-open it; CONFIRMED remains sticky so a
	// single transient verification failure cannot erase proven evidence.
	if state == CandRejected || state == CandInconclusive {
		if !reopenCandidate(ctx, db, id, meta.Actor, result.Method, "fresh detector observation") {
			state = candidateState(ctx, db, id)
		} else {
			state = CandDetected
		}
	}

	if state != CandConfirmed {
		_, state = TransitionCandidate(ctx, db, id, CandVerifying, meta.Actor, result.Method, result.Reason, result.Confidence)
	}

	finalState := state
	if state == CandConfirmed {
		finalState = CandConfirmed
	} else {
		switch result.Verdict {
		case VerifyVerified:
			_, state = TransitionCandidate(ctx, db, id, CandVerified, meta.Actor, result.Method, result.Evidence, result.Confidence)
			if state == CandVerified {
				_, state = TransitionCandidate(ctx, db, id, CandConfirmed, meta.Actor, result.Method, result.Evidence, result.Confidence)
			}
			finalState = state
		case VerifyRejected:
			_, finalState = TransitionCandidate(ctx, db, id, CandRejected, meta.Actor, result.Method, result.Reason, 0)
		case VerifyInconclusive:
			_, finalState = TransitionCandidate(ctx, db, id, CandInconclusive, meta.Actor, result.Method, result.Reason, result.Confidence)
		}
	}

	if err := upsertFindingProjection(ctx, db, id, c, result, finalState, meta); err != nil {
		return id, err
	}
	return id, nil
}

func candidateState(ctx context.Context, db *database.DB, id string) string {
	var state string
	_ = db.QueryRowContext(ctx, `SELECT status FROM candidates WHERE id=?`, id).Scan(&state)
	return state
}

// reopenCandidate is an explicit, audited new-observation transition. It is kept
// outside the ordinary legal map so stale verifier goroutines cannot resurrect a
// terminal row accidentally.
func reopenCandidate(ctx context.Context, db *database.DB, id, actor, method, reason string) bool {
	var from, targetID string
	var version int
	if err := db.QueryRowContext(ctx,
		`SELECT status, target_id, COALESCE(state_version,0) FROM candidates WHERE id=?`, id).
		Scan(&from, &targetID, &version); err != nil {
		return false
	}
	if from != CandRejected && from != CandInconclusive {
		return false
	}
	res, err := db.ExecContext(ctx, `
		UPDATE candidates SET status=?, state_version=state_version+1,
			verification_method='', verification_reason=''
		WHERE id=? AND status=? AND COALESCE(state_version,0)=?`,
		CandDetected, id, from, version)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false
	}
	_, _ = db.ExecContext(ctx, `
		INSERT INTO candidate_transitions
			(id,candidate_id,target_id,from_state,to_state,actor,method,reason,state_version)
		VALUES (?,?,?,?,?,?,?,?,?)`, uuid.New().String(), id, targetID, from,
		CandDetected, actor, method, RedactText(reason), version+1)
	return true
}

func upsertFindingProjection(ctx context.Context, db *database.DB, candidateID string, c VulnerabilityCandidate, result VerifyResult, lifecycle string, meta FindingMeta) error {
	// Normalize the URL BEFORE the UNIQUE(target_id,type,url,parameter) insert
	// so https://www.x.com:443/a and https://x.com/a hit the same row instead
	// of showing as two Needs Review rows for the same file. Raw evidence stays
	// untouched; only the identity column is canonical.
	c.URL = NormalizeURL(c.URL)
	status := ""
	switch lifecycle {
	case CandConfirmed, CandVerified:
		status = StatusFinding
	case CandInconclusive, CandDetected, CandTriaged, CandVerifying:
		if result.Confidence >= ConfHiddenCutoff {
			status = StatusCandidate
		}
	case CandRejected:
		// Keep a formerly projected row consistent, but do not create rejected
		// noise in vuln_findings. The authoritative rejection remains in candidates.
		_, _ = db.ExecContext(ctx, `UPDATE vuln_findings SET status='rejected', lifecycle=?, confidence=0
			WHERE candidate_id=?`, lifecycle, candidateID)
		return nil
	}
	if status == "" {
		return nil
	}

	severity := strings.TrimSpace(c.Severity)
	if severity == "" {
		severity = "medium"
	}
	evidence := result.Evidence
	if evidence == "" {
		evidence = result.Reason
	}
	if evidence == "" {
		evidence = c.Evidence
	}

	newID := uuid.New().String()
	_, err := db.ExecContext(ctx, `
		INSERT INTO vuln_findings
			(id,target_id,type,severity,url,parameter,payload,evidence,confidence,priority,status,provenance,candidate_id,lifecycle)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(target_id,type,url,parameter) DO UPDATE SET
			severity=CASE
				WHEN excluded.status='finding' THEN excluded.severity
				ELSE vuln_findings.severity END,
			payload=CASE
				WHEN excluded.status='finding' OR COALESCE(vuln_findings.status,'')<>'finding' THEN excluded.payload
				ELSE vuln_findings.payload END,
			evidence=CASE
				WHEN excluded.status='finding' OR COALESCE(vuln_findings.status,'')<>'finding' THEN excluded.evidence
				ELSE vuln_findings.evidence END,
			confidence=MAX(COALESCE(vuln_findings.confidence,0),excluded.confidence),
			priority=MAX(COALESCE(vuln_findings.priority,0),excluded.priority),
			status=CASE
				WHEN excluded.status='finding' THEN 'finding'
				WHEN COALESCE(vuln_findings.status,'')='finding' THEN 'finding'
				ELSE excluded.status END,
			provenance=CASE WHEN excluded.provenance<>'' THEN excluded.provenance ELSE vuln_findings.provenance END,
			candidate_id=CASE
				WHEN excluded.status='finding' OR COALESCE(vuln_findings.status,'')<>'finding' THEN excluded.candidate_id
				ELSE vuln_findings.candidate_id END,
			lifecycle=CASE
				WHEN excluded.status='finding' OR COALESCE(vuln_findings.status,'')<>'finding' THEN excluded.lifecycle
				ELSE vuln_findings.lifecycle END`,
		newID, c.TargetID, c.Type, severity, c.URL, c.Parameter, c.Payload,
		RedactText(evidence), result.Confidence, meta.Priority, status,
		RedactText(meta.Provenance), candidateID, lifecycle)
	if err != nil {
		return fmt.Errorf("finding projection: %w", err)
	}
	var findingID string
	if err := db.QueryRowContext(ctx, `SELECT id FROM vuln_findings
		WHERE target_id=? AND type=? AND url=? AND COALESCE(parameter,'')=?`,
		c.TargetID, c.Type, c.URL, c.Parameter).Scan(&findingID); err == nil {
		_, _ = db.ExecContext(ctx, `UPDATE candidates SET finding_id=? WHERE id=?`, findingID, candidateID)
	}
	return nil
}
