package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/recon-platform/internal/database"
)

// Multi-step workflow execution (deterministic). A researcher defines an ordered
// chain of steps; each runs as a chosen identity, can reference variables
// extracted from earlier steps (${var}), and extracts new variables from its
// response. This turns the dataflow model into an executable engine — enough to
// express "User A creates a project → capture project.id → User B tries to act on
// it". Destructive steps run only because the researcher defined and triggered
// the workflow on an authorized target.

// WorkflowStep is one step in a chain.
type WorkflowStep struct {
	IdentityLabel string            `json:"identity_label"` // "" or "unauthenticated" = no session
	Method        string            `json:"method"`
	URL           string            `json:"url"`  // may contain ${var}
	Body          string            `json:"body"` // may contain ${var}
	ContentType   string            `json:"content_type"`
	Extract       map[string]string `json:"extract"`       // varName → response JSON field to capture
	ExpectDenied  bool              `json:"expect_denied"` // if true, an AUTHORIZED result is flagged (prereq/authz bypass)
}

// StepResult is one step's outcome.
type StepResult struct {
	Index     int               `json:"index"`
	Identity  string            `json:"identity"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Status    int               `json:"status"`
	Verdict   string            `json:"verdict"`
	Missing   []string          `json:"missing_refs"`
	Extracted map[string]string `json:"extracted"`
	Flagged   bool              `json:"flagged"` // ExpectDenied but observed AUTHORIZED
}

// WorkflowResult is the whole run.
type WorkflowResult struct {
	Steps       []StepResult      `json:"steps"`
	Vars        map[string]string `json:"vars"`
	Aborted     bool              `json:"aborted"`
	AbortReason string            `json:"abort_reason"`
	FlaggedStep int               `json:"flagged_step"` // -1 if none
}

// RunWorkflow executes the chain with variable propagation. Aborts (without
// running later steps) if a step references a variable no earlier step produced —
// that's a real prerequisite gap, surfaced rather than silently substituted.
func RunWorkflow(ctx context.Context, db *database.DB, targetID string, ids []Identity, steps []WorkflowStep, seed map[string]string) WorkflowResult {
	byLabel := map[string]Identity{}
	for i := range ids {
		byLabel[ids[i].Label] = ids[i]
	}
	// Scope basis for RE-validating every step's RESOLVED url. The API validates the
	// raw step URLs, but ${var} references are filled from earlier RESPONSES, so a
	// later step's url is attacker-influenceable — it must be re-checked against the
	// target scope right before a credentialed Replay, or a workflow could exfiltrate
	// a session to an out-of-scope host.
	var wfDomain string
	_ = db.QueryRow(`SELECT domain FROM targets WHERE id=?`, targetID).Scan(&wfDomain)
	var wfOrigins []string
	for i := range ids {
		if ids[i].Origin != "" {
			wfOrigins = append(wfOrigins, ids[i].Origin)
		}
	}
	vars := map[string]string{}
	for k, v := range seed {
		vars[k] = v
	}
	res := WorkflowResult{Vars: vars, FlaggedStep: -1}

	for i, st := range steps {
		if ctx.Err() != nil {
			break
		}
		url, missU := ResolveRefs(st.URL, vars)
		body, missB := ResolveRefs(st.Body, vars)
		missing := append(missU, missB...)
		sr := StepResult{Index: i, Identity: st.IdentityLabel, Method: st.Method, URL: url, Missing: missing, Extracted: map[string]string{}}
		if len(missing) > 0 {
			sr.Verdict = "PREREQUISITE_MISSING"
			res.Steps = append(res.Steps, sr)
			res.Aborted, res.AbortReason = true, "step "+itoa(i)+" needs unresolved variable(s): "+strings.Join(missing, ", ")
			break
		}

		// Re-validate the RESOLVED url (post variable substitution) before any
		// credentialed request — fail closed if the workflow tried to leave scope.
		if !URLInScope(wfDomain, wfOrigins, url) {
			sr.Verdict = "OUT_OF_SCOPE"
			res.Steps = append(res.Steps, sr)
			res.Aborted, res.AbortReason = true, "step "+itoa(i)+" resolved to an out-of-scope URL and was blocked: "+url
			break
		}

		var id *Identity
		if st.IdentityLabel != "" && st.IdentityLabel != "unauthenticated" {
			if v, ok := byLabel[st.IdentityLabel]; ok {
				id = &v
			}
		}
		r := Replay(ctx, ReplaySpec{Method: st.Method, URL: url, Body: body, ContentType: st.ContentType}, id)
		sr.Status = r.Response.Status
		sr.Verdict = InterpretResponse(r.Response, "")

		// propagate extracted variables
		for name, field := range st.Extract {
			if val := extractJSONField(r.Response.Body, field); val != "" {
				vars[name] = val
				sr.Extracted[name] = val
				StoreVariable(ctx, db, targetID, "workflow", Variable{Name: name, Value: val, SourceID: st.IdentityLabel, SourceURL: url})
			}
		}
		// record for the graph/semantics
		RecordInteraction(ctx, db, targetID,
			CanonRequest{Method: st.Method, URL: url, IdentityLabel: st.IdentityLabel, Scanner: "workflow"},
			CanonResponse{Status: r.Response.Status, CT: r.Response.CT, Len: r.Response.Len})
		a := ClassifyAction(st.Method, url, body, r.Response.Status)
		StoreAction(ctx, db, targetID, "", st.IdentityLabel, "workflow", a)

		// a step the researcher expects to be DENIED that succeeds = bypass signal
		if st.ExpectDenied && sr.Verdict == VerdictAuthorized {
			sr.Flagged = true
			if res.FlaggedStep < 0 {
				res.FlaggedStep = i
			}
		}
		res.Steps = append(res.Steps, sr)
	}
	return res
}

// extractJSONField pulls a single field's value from a JSON-ish body.
func extractJSONField(body, field string) string {
	re, err := regexp.Compile(regexp.QuoteMeta(`"`+field+`"`) + `\s*:\s*"?([^",}\s]+)"?`)
	if err != nil {
		return ""
	}
	if m := re.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}
