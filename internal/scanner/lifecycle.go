package scanner

import (
	"context"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Canonical vulnerability lifecycle (P1). The `candidates` table is the
// AUTHORITATIVE state source; `vuln_findings` is a finding/report PROJECTION.
//
// State machine (candidates.status):
//
//	DETECTED ─► TRIAGED ─► VERIFYING ─► VERIFIED ─► CONFIRMED
//	                          │  │  └────────────────────►│
//	                          │  └─► INCONCLUSIVE ─(re)─► VERIFYING
//	                          └────► REJECTED
//	  (any non-terminal) ───────────────────────────────► DUPLICATE
//
// Semantic distinction (documented, deliberately minimal):
//   - VERIFIED   = a verifier produced positive technical evidence.
//   - CONFIRMED  = the system has enough evidence to SURFACE the issue as a
//     confirmed finding (the reportable state).
//
// Most in-repo verifiers already hold decisive proof at verify time and move
// straight to CONFIRMED; VERIFIED is retained as the legal intermediate for
// verifiers that separate "positive evidence" from "surface it". We do NOT add
// states beyond the six the codebase already declares.
//
// Terminal, sticky states (a conflicting later verdict must NOT overwrite them —
// the stale-verification guard): CONFIRMED, REJECTED, DUPLICATE. Only a move to
// DUPLICATE may supersede CONFIRMED.

// LifecycleLegacy marks a projected finding with no authoritative candidate
// (created before P1). Such rows are preserved and NEVER auto-marked CONFIRMED.
const LifecycleLegacy = "LEGACY"

// legalFrom maps a target state to the set of states it may legally come from
// (strict machine used by TransitionCandidate).
var legalFrom = map[string]map[string]bool{
	CandTriaged:      {CandDetected: true},
	CandVerifying:    {CandDetected: true, CandTriaged: true, CandInconclusive: true},
	CandVerified:     {CandVerifying: true},
	CandConfirmed:    {CandVerifying: true, CandVerified: true, CandDetected: true},
	CandRejected:     {CandVerifying: true, CandVerified: true},
	CandInconclusive: {CandVerifying: true, CandVerified: true},
	CandDuplicate: {
		CandDetected: true, CandTriaged: true, CandVerifying: true,
		CandVerified: true, CandConfirmed: true, CandInconclusive: true,
	},
}

// terminalState reports whether a state is sticky (cannot be overwritten by a
// conflicting later verdict; only DUPLICATE may supersede).
func terminalState(s string) bool {
	return s == CandConfirmed || s == CandRejected || s == CandDuplicate
}

// TransitionCandidate performs a STRICT, guarded lifecycle transition following
// the legal map. Returns (applied, resultingState). It is idempotent (a no-op
// when already in the target state), concurrency-safe (compare-and-set on
// state_version), audited, and projects the change onto the linked finding.
func TransitionCandidate(ctx context.Context, db *database.DB, id, to, actor, method, reason string, confidence int) (bool, string) {
	return applyState(ctx, db, id, to, actor, method, reason, confidence, true)
}

// applyState is the single guarded mutator behind both TransitionCandidate
// (strict=true, full legal map) and SetCandidateStatus (strict=false, lenient
// but still terminal-guarded, for backward compatibility). All lifecycle changes
// funnel through here — there is exactly one place that can mutate candidate
// state, which is what makes the guarantees hold.
func applyState(ctx context.Context, db *database.DB, id, to, actor, method, reason string, confidence int, strict bool) (bool, string) {
	var cur, targetID string
	var ver int
	err := db.QueryRowContext(ctx,
		`SELECT status, COALESCE(state_version,0), target_id FROM candidates WHERE id=?`, id).
		Scan(&cur, &ver, &targetID)
	if err != nil {
		return false, ""
	}

	// Idempotent: already in the target state → refresh verification meta only,
	// never bump the version or re-fire a transition.
	if cur == to {
		_, _ = db.ExecContext(ctx,
			`UPDATE candidates SET verification_method=?, verification_reason=?, confidence=MAX(COALESCE(confidence,0),?) WHERE id=? AND status=?`,
			method, RedactText(reason), confidence, id, to)
		return false, cur
	}

	// Terminal stale-guard: a sticky terminal state is only superseded by
	// DUPLICATE. This blocks "CONFIRMED → REJECTED" and "REJECTED → CONFIRMED"
	// stale overwrites regardless of strict/lenient mode.
	if terminalState(cur) && to != CandDuplicate {
		return false, cur
	}

	if strict {
		if !legalFrom[to][cur] {
			return false, cur
		}
	} else if _, known := legalFrom[to]; !known && to != CandDetected {
		return false, cur // unknown target state
	}

	// Compare-and-set on (status, state_version): if a concurrent transition
	// already moved this candidate, RowsAffected == 0 and we lose the race
	// cleanly instead of corrupting state.
	res, err := db.ExecContext(ctx, `
		UPDATE candidates
		SET status=?, state_version=state_version+1,
		    verification_method=?, verification_reason=?, confidence=?
		WHERE id=? AND status=? AND COALESCE(state_version,0)=?`,
		to, method, RedactText(reason), confidence, id, cur, ver)
	if err != nil {
		return false, cur
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, cur
	}

	// Audit trail (append-only, reason redacted).
	_, _ = db.ExecContext(ctx, `
		INSERT INTO candidate_transitions
			(id, candidate_id, target_id, from_state, to_state, actor, method, reason, state_version)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), id, targetID, cur, to, actor, method, RedactText(reason), ver+1)

	projectFinding(ctx, db, id, targetID, to)
	return true, to
}

// projectFinding keeps the vuln_findings projection consistent with the
// authoritative candidate state. It links the finding to its candidate and,
// for outcome states, updates the finding's surfaced status so a later
// REJECTED/INCONCLUSIVE verdict cannot leave a stale "confirmed" finding.
//
// Intermediate states (DETECTED/TRIAGED/VERIFYING) update lifecycle + link only,
// never downgrading a status a detector deliberately set — that keeps existing
// self-verified findings visible until an actual outcome verdict arrives.
func projectFinding(ctx context.Context, db *database.DB, candidateID, targetID, state string) {
	var typ, url, param string
	_ = db.QueryRowContext(ctx,
		`SELECT type, url, COALESCE(parameter,'') FROM candidates WHERE id=?`, candidateID).
		Scan(&typ, &url, &param)

	newStatus, changeStatus := findingStatusForLifecycle(state)

	// Prefer an already-linked finding.
	if changeStatus {
		res, _ := db.ExecContext(ctx,
			`UPDATE vuln_findings SET lifecycle=?, status=?, candidate_id=? WHERE candidate_id=?`,
			state, newStatus, candidateID, candidateID)
		if n, _ := res.RowsAffected(); n > 0 {
			return
		}
	} else {
		res, _ := db.ExecContext(ctx,
			`UPDATE vuln_findings SET lifecycle=?, candidate_id=? WHERE candidate_id=?`,
			state, candidateID, candidateID)
		if n, _ := res.RowsAffected(); n > 0 {
			return
		}
	}

	// Otherwise adopt an unlinked finding matching the candidate's identity.
	if changeStatus {
		_, _ = db.ExecContext(ctx, `
			UPDATE vuln_findings SET lifecycle=?, status=?, candidate_id=?
			WHERE target_id=? AND type=? AND url=? AND COALESCE(parameter,'')=?
			  AND (candidate_id='' OR candidate_id IS NULL)`,
			state, newStatus, candidateID, targetID, typ, url, param)
	} else {
		_, _ = db.ExecContext(ctx, `
			UPDATE vuln_findings SET lifecycle=?, candidate_id=?
			WHERE target_id=? AND type=? AND url=? AND COALESCE(parameter,'')=?
			  AND (candidate_id='' OR candidate_id IS NULL)`,
			state, candidateID, targetID, typ, url, param)
	}
}

// findingStatusForLifecycle maps a lifecycle state to the projected
// vuln_findings.status, and whether that status should be changed. Report reads
// status='finding' for the confirmed view; 'rejected'/'duplicate' are hidden;
// 'candidate' is the analyst/unverified view.
func findingStatusForLifecycle(state string) (status string, change bool) {
	switch state {
	case CandConfirmed, CandVerified:
		return StatusFinding, true
	case CandRejected:
		return "rejected", true
	case CandDuplicate:
		return "duplicate", true
	case CandInconclusive:
		return StatusCandidate, true
	default:
		// DETECTED / TRIAGED / VERIFYING — don't touch status, only lifecycle.
		return "", false
	}
}
