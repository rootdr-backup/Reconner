package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// AuthzEngine turns semantic data (identities, objects, ownership, actions) into
// verified authorization findings via the observation → candidate → hypothesis →
// execution → verification → finding pipeline. It auto-verifies READ BOLA
// (non-destructive); state-changing candidates (write/delete/BFLA) are persisted
// as ranked hypotheses for researcher-triggered replay — the engine never
// performs destructive actions automatically.
type AuthzEngine struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewAuthzEngine(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *AuthzEngine {
	return &AuthzEngine{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

// Hypothesis lifecycle statuses.
const (
	HypHypothesis = "HYPOTHESIS"
	HypTested     = "TESTED"
	HypVerified   = "VERIFIED"
	HypRejected   = "REJECTED"
)

func (s *AuthzEngine) Run(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	logFn("info", "authz", "Authorization engine: turning captured semantics into targeted authz tests...")

	ids := LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret))
	if len(ids) < 2 {
		logFn("info", "authz", "Need ≥2 captured identities for cross-identity authorization testing — skipping (add identities in the target's Identities panel).")
		return nil
	}
	byLabel := map[string]Identity{}
	var labels []string
	for _, id := range ids {
		byLabel[id.Label] = id
		labels = append(labels, id.Label)
	}

	cands := GenerateCandidates(ctx, s.db, targetID, labels)
	if len(cands) == 0 {
		logFn("info", "authz", "No cross-identity candidates (need authenticated traffic showing owned objects). Capture traffic via the browser session, then re-run.")
		return nil
	}
	logFn("info", "authz", fmt.Sprintf("Generated %d ranked authorization candidate(s).", len(cands)))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var findings atomic.Int64

	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		hypID := s.storeHypothesis(ctx, targetID, c)

		if !c.AutoVerify {
			// state-changing: leave as a ranked hypothesis for researcher replay.
			continue
		}
		attacker, ok := byLabel[c.AttackerLabel]
		if !ok {
			continue
		}
		victim := byLabel[c.VictimLabel]

		wg.Add(1)
		sem <- struct{}{}
		go func(c Candidate, hypID string, attacker, victim Identity) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.verifyReadBOLA(ctx, targetID, c, hypID, attacker, victim, logFn) {
				findings.Add(1)
			}
		}(c, hypID, attacker, victim)
	}
	wg.Wait()
	logFn("info", "authz", fmt.Sprintf("Authorization engine done. %d verified authz finding(s); remaining candidates persisted as hypotheses.", findings.Load()))
	return nil
}

// verifyReadBOLA runs the CrossIdentityRead test plan: baseline owner read, then
// attacker read, and confirms a BOLA only on strong, reproducible signal.
func (s *AuthzEngine) verifyReadBOLA(ctx context.Context, targetID string, c Candidate, hypID string, attacker, victim Identity, logFn LogFunc) bool {
	spec := ReplaySpec{Method: "GET", URL: c.URL}

	// Baseline: the victim (owner) must actually see their object.
	ownerResp := Replay(ctx, spec, &victim)
	if InterpretResponse(ownerResp.Response, c.ObjectID) != VerdictAuthorized {
		s.updateHypothesis(ctx, hypID, HypRejected, VerdictAmbiguous, 0, "")
		return false
	}
	// Control: unauthenticated must be denied (proves the resource is protected).
	unauth := Replay(ctx, spec, nil)
	if InterpretResponse(unauth.Response, c.ObjectID) == VerdictAuthorized {
		s.updateHypothesis(ctx, hypID, HypRejected, VerdictAuthorized, 0, "public resource, not an authz bug")
		return false
	}
	// Test: attacker (no relationship) reads the victim's object.
	attResp := Replay(ctx, spec, &attacker)
	observed := InterpretResponse(attResp.Response, c.ObjectID)
	expected := ExpectDenied // attacker has no relationship (guaranteed by candidate gen)

	StoreObservation(ctx, s.db, targetID, AuthorizationObservation{
		IdentityLabel: attacker.Label, ObjectType: c.ObjectType, ObjectID: c.ObjectID,
		ActionVerb: c.Action, EndpointTemplate: c.EndpointTemplate,
		Expected: expected, Observed: observed, Confidence: 90, Source: "authz-engine",
	})

	// Confirm: flaw AND the attacker received the SAME object (not a different/empty one).
	sameObject := bodiesSameObject(ownerResp.Response.Body, attResp.Response.Body)
	if !IsAuthzFlaw(expected, observed) || !sameObject {
		s.updateHypothesis(ctx, hypID, HypTested, observed, 60, "attacker not authorized / different object — authorization appears intact")
		return false
	}

	// VERIFIED cross-identity BOLA.
	evidence := fmt.Sprintf(
		"BOLA: %s#%s is owned by %q and requires a session (unauth denied), yet %q — who has NO relationship to it — read the SAME object (semantically confirmed identical) via %s. Expected DENIED, observed AUTHORIZED.",
		c.ObjectType, c.ObjectID, victim.Label, attacker.Label, c.URL)
	findingID := s.storeFinding(ctx, targetID, "bola", "critical", c.URL, c.ObjectType+"#"+c.ObjectID, evidence, 95)
	StoreEvidence(ctx, s.db, findingID, targetID, "cross_identity",
		"Expected: attacker denied. Actual: attacker read the owner's object. Comparison: identical object bodies.",
		[]EvidenceItem{
			withComparison(evidenceFromResponse("GET", c.URL, victim, ownerResp.Response), "OWNER — victim's own object (authorized)"),
			withComparison(evidenceFromResponse("GET", c.URL, Identity{Label: "unauthenticated"}, unauth.Response), "CONTROL — no session: denied (resource is protected)"),
			withComparison(evidenceFromResponse("GET", c.URL, attacker, attResp.Response), "ATTACKER — no relationship, received the OWNER'S object (BOLA)"),
		})
	s.updateHypothesis(ctx, hypID, HypVerified, observed, 95, "")
	_, _ = s.db.ExecContext(ctx, `UPDATE hypotheses SET finding_id=? WHERE id=?`, findingID, hypID)
	logFn("warn", "authz", fmt.Sprintf("BOLA VERIFIED [critical]: %s read %q's %s#%s (%s)", attacker.Label, victim.Label, c.ObjectType, c.ObjectID, c.URL))
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "bola", "url": c.URL, "parameter": c.ObjectType + "#" + c.ObjectID})
	}
	return true
}

// WriteVerifySpec is a researcher-triggered state-changing verification.
type WriteVerifySpec struct {
	OwnerLabel    string // whose object it is (reads the before/after snapshot)
	AttackerLabel string // the identity performing the unauthorized write
	ObjectType    string
	ObjectID      string
	ReadURL       string // owner-readable URL for the object (snapshot source)
	WriteMethod   string
	WriteURL      string
	WriteBody     string
	ContentType   string
	HypothesisID  string // optional — updated to VERIFIED/TESTED
}

// WriteVerifyResult is returned to the caller/UI.
type WriteVerifyResult struct {
	SideEffect bool   `json:"side_effect"`
	Summary    string `json:"summary"`
	Observed   string `json:"observed"`
	FindingID  string `json:"finding_id"`
	Before     int    `json:"before_status"`
	After      int    `json:"after_status"`
	WriteResp  int    `json:"write_status"`
}

// VerifyWrite runs the state-snapshot WRITE/DELETE/BFLA verification: snapshot the
// object as the owner, perform the attacker's write, snapshot again, and confirm a
// real SIDE EFFECT. Destructive — the researcher triggers it explicitly for an
// authorized target. Produces before/after evidence and a finding only on a
// confirmed side effect by an identity with no relationship to the object.
func (s *AuthzEngine) VerifyWrite(ctx context.Context, targetID string, ids []Identity, spec WriteVerifySpec) WriteVerifyResult {
	byLabel := map[string]Identity{}
	for _, id := range ids {
		byLabel[id.Label] = id
	}
	owner, okO := byLabel[spec.OwnerLabel]
	attacker, okA := byLabel[spec.AttackerLabel]
	if !okO || !okA {
		return WriteVerifyResult{Summary: "owner/attacker identity not found"}
	}
	// Guard: attacker must NOT have a legitimate relationship to the object.
	if hasStrongRelationship(ctx, s.db, targetID, spec.ObjectType, spec.ObjectID, spec.AttackerLabel) {
		return WriteVerifyResult{Summary: "attacker has a legitimate relationship to the object — not an authz test"}
	}

	before := SnapshotState(ctx, spec.ReadURL, &owner, spec.ObjectType, spec.ObjectID, "before")
	StoreSnapshot(ctx, s.db, targetID, "verify-write", before)

	writeResp := Replay(ctx, ReplaySpec{Method: spec.WriteMethod, URL: spec.WriteURL, Body: spec.WriteBody, ContentType: spec.ContentType}, &attacker)

	after := SnapshotState(ctx, spec.ReadURL, &owner, spec.ObjectType, spec.ObjectID, "after")
	StoreSnapshot(ctx, s.db, targetID, "verify-write", after)

	diff := DiffSnapshots(before, after)
	observed := VerdictDenied
	if diff.Changed {
		observed = VerdictSideEffect
	}
	StoreObservation(ctx, s.db, targetID, AuthorizationObservation{
		IdentityLabel: attacker.Label, ObjectType: spec.ObjectType, ObjectID: spec.ObjectID,
		ActionVerb: "WRITE", EndpointTemplate: NormalizeURL(spec.WriteURL),
		Expected: ExpectDenied, Observed: observed, Confidence: 95, Source: "verify-write",
	})

	res := WriteVerifyResult{
		SideEffect: diff.Changed, Summary: diff.Summary, Observed: observed,
		Before: before.Status, After: after.Status, WriteResp: writeResp.Status,
	}
	if !diff.Changed {
		if spec.HypothesisID != "" {
			s.updateHypothesis(ctx, spec.HypothesisID, HypTested, observed, 60, "no observable side effect — authorization appears intact")
		}
		return res
	}
	// Confirmed unauthorized state change.
	evidence := "Unauthorized state change (BFLA/BOLA-write): " + attacker.Label +
		" has NO relationship to " + spec.ObjectType + "#" + spec.ObjectID + " (owned by " + owner.Label +
		"), yet " + spec.WriteMethod + " " + spec.WriteURL + " caused an observable side effect confirmed by the owner's before/after view — " + diff.Summary + "."
	findingID := s.storeFinding(ctx, targetID, "bfla", "critical",
		spec.WriteURL, spec.ObjectType+"#"+spec.ObjectID, evidence, 96)
	StoreEvidence(ctx, s.db, findingID, targetID, "state_change",
		"Expected: attacker denied / no side effect. Actual: owner-observed state changed after the attacker's write.",
		[]EvidenceItem{
			{IdentityLabel: owner.Label + " (BEFORE)", Request: "GET " + spec.ReadURL, Response: snapshotText(before), Comparison: "owner's view before the test"},
			{IdentityLabel: attacker.Label + " (WRITE)", Request: spec.WriteMethod + " " + spec.WriteURL, Response: "HTTP " + itoa(writeResp.Status), Comparison: "attacker performed the state-changing action"},
			{IdentityLabel: owner.Label + " (AFTER)", Request: "GET " + spec.ReadURL, Response: snapshotText(after), Comparison: diff.Summary},
		})
	if spec.HypothesisID != "" {
		s.updateHypothesis(ctx, spec.HypothesisID, HypVerified, observed, 96, "")
		_, _ = s.db.ExecContext(ctx, `UPDATE hypotheses SET finding_id=? WHERE id=?`, findingID, spec.HypothesisID)
	}
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "bfla", "url": spec.WriteURL, "parameter": spec.ObjectType + "#" + spec.ObjectID})
	}
	res.FindingID = findingID
	return res
}

// RunWorkflow executes a researcher-defined multi-step workflow with variable
// propagation and, if a step marked ExpectDenied succeeded (a prerequisite /
// workflow authorization bypass), records a verified finding with the step chain
// as evidence.
func (s *AuthzEngine) RunWorkflow(ctx context.Context, targetID string, ids []Identity, steps []WorkflowStep, seed map[string]string) WorkflowResult {
	res := RunWorkflow(ctx, s.db, targetID, ids, steps, seed)
	if res.FlaggedStep < 0 {
		return res
	}
	fs := res.Steps[res.FlaggedStep]
	var chain []string
	var items []EvidenceItem
	for _, st := range res.Steps {
		line := "step " + itoa(st.Index) + ": " + st.Identity + " " + st.Method + " " + st.URL + " → HTTP " + itoa(st.Status) + " (" + st.Verdict + ")"
		chain = append(chain, line)
		items = append(items, EvidenceItem{IdentityLabel: st.Identity, Request: st.Method + " " + st.URL, Response: "HTTP " + itoa(st.Status) + " — " + st.Verdict, Comparison: line})
	}
	evidence := "Workflow authorization bypass: step " + itoa(fs.Index) + " (" + fs.Identity + " " + fs.Method + " " + fs.URL +
		") was expected to be DENIED but succeeded (AUTHORIZED) within the chain:\n" + strings.Join(chain, "\n")
	findingID := s.storeFinding(ctx, targetID, "workflow_authz_bypass", "high", fs.URL, "step-"+itoa(fs.Index), evidence, 88)
	StoreEvidence(ctx, s.db, findingID, targetID, "workflow",
		"A step expected to require prerequisites/authorization succeeded for an identity that should not have been able to complete it.", items)
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "workflow_authz_bypass", "url": fs.URL, "parameter": "step-" + itoa(fs.Index)})
	}
	return res
}

func snapshotText(s StateSnapshot) string {
	out := "HTTP " + itoa(s.Status)
	for k, v := range s.Fields {
		out += "\n" + k + ": " + v
	}
	return RedactText(out)
}

func (s *AuthzEngine) storeHypothesis(ctx context.Context, targetID string, c Candidate) string {
	id := uuid.New().String()
	kind := "BOLA"
	if c.Plan == PlanPrivilegeBoundary || c.Plan == PlanRoleBoundary {
		kind = "BFLA"
	} else if c.Plan == PlanTenantBoundary {
		kind = "TENANT"
	}
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO hypotheses (id, target_id, kind, identity_label, object_type, object_id, action_verb, endpoint_template, expected, observed, status, confidence, test_plan, reason)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, targetID, kind, c.AttackerLabel, c.ObjectType, c.ObjectID, c.Action, c.EndpointTemplate,
		ExpectDenied, VerdictUnknown, HypHypothesis, c.Score, c.Plan, c.Reason)
	return id
}

func (s *AuthzEngine) updateHypothesis(ctx context.Context, id, status, observed string, confidence int, note string) {
	_, _ = s.db.ExecContext(ctx,
		`UPDATE hypotheses SET status=?, observed=?, confidence=?, reason=CASE WHEN ?='' THEN reason ELSE ? END WHERE id=?`,
		status, observed, confidence, note, note, id)
}

func (s *AuthzEngine) storeFinding(ctx context.Context, targetID, typ, sev, url, param, evidence string, confidence int) string {
	priority := confidence * severityWeightIDOR(sev)
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	ids, _ := RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: typ, Severity: sev, URL: url, Method: "REPLAY",
		Parameter: param, Location: "authorization", Evidence: evidence, Source: "authz-engine",
		DetectionMethod: "cross-identity-replay", Confidence: confidence,
		Priority: priority, Verdict: verdict,
	})
	return ids.FindingID
}
