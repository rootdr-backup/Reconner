package scanner

import (
	"path"
	"strings"
)

// False-Positive management engine (vulnerability-scanner core, section 3).
//
// A finding can be triaged to one of a small set of professional states, and an
// operator's triage decisions become REUSABLE suppression rules that auto-apply
// on future scans (learning from feedback). This file is the pure, DB-independent
// core: the finding-state vocabulary, the rule model, and the matcher. Persistence
// and API wiring layer on top of it.

// Finding triage states (superset of the legacy "finding"/"candidate").
const (
	StateNew          = "new"            // freshly detected, not yet triaged
	StateConfirmed    = "confirmed"      // operator verified it is real (True Positive)
	StateFalsePos     = "false_positive" // operator marked it not real
	StateAcceptedRisk = "accepted_risk"  // real but accepted by the business
	StateFixed        = "fixed"          // remediated and re-verified
)

// ValidTriageState reports whether s is an operator-settable triage state.
func ValidTriageState(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case StateNew, StateConfirmed, StateFalsePos, StateAcceptedRisk, StateFixed:
		return true
	}
	return false
}

// FPScope bounds where a suppression rule applies.
type FPScope string

const (
	FPGlobal FPScope = "global" // applies to every target
	FPTarget FPScope = "target" // applies to one target only
)

// FPRule is a reusable suppression rule. An empty selector field matches ANY
// value; a non-empty one must match for the rule to apply. A rule with NO
// selectors set is inert (never matches) so an "empty" rule can't nuke everything.
type FPRule struct {
	ID         string
	Scope      FPScope
	TargetID   string // required when Scope == FPTarget
	Type       string // vuln type, e.g. "xss" (exact, case-insensitive)
	TemplateID string // nuclei/check template id (exact, case-insensitive)
	URLPattern string // glob against the finding URL (path.Match semantics, plus "*substr*")
	Parameter  string // affected parameter (exact, case-insensitive)
	Payload    string // substring match against the finding payload
	Reason     string // operator's note (shown in reports)
	Enabled    bool
}

// FindingKey is the minimal projection of a finding the matcher needs.
type FindingKey struct {
	TargetID   string
	Type       string
	TemplateID string
	URL        string
	Parameter  string
	Payload    string
}

// hasSelector reports whether the rule constrains at least one field.
func (r FPRule) hasSelector() bool {
	return r.Type != "" || r.TemplateID != "" || r.URLPattern != "" || r.Parameter != "" || r.Payload != ""
}

// Matches reports whether this rule suppresses the given finding. ALL non-empty
// selectors must match (AND semantics); an inert rule (no selectors) never matches.
func (r FPRule) Matches(f FindingKey) bool {
	if !r.Enabled || !r.hasSelector() {
		return false
	}
	if r.Scope == FPTarget && !strings.EqualFold(r.TargetID, f.TargetID) {
		return false
	}
	if r.Type != "" && !strings.EqualFold(r.Type, f.Type) {
		return false
	}
	if r.TemplateID != "" && !strings.EqualFold(r.TemplateID, f.TemplateID) {
		return false
	}
	if r.Parameter != "" && !strings.EqualFold(r.Parameter, f.Parameter) {
		return false
	}
	if r.Payload != "" && !strings.Contains(f.Payload, r.Payload) {
		return false
	}
	if r.URLPattern != "" && !urlPatternMatch(r.URLPattern, f.URL) {
		return false
	}
	return true
}

// urlPatternMatch supports both shell-glob (path.Match) and a lenient
// "*substring*" contains form, so operators can write either
// "https://x/api/*" or "*/legacy/*" without learning glob edge cases.
func urlPatternMatch(pattern, url string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	// Pure wildcard-wrapped substring: *foo* → contains "foo".
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && !strings.ContainsAny(pattern[1:len(pattern)-1], "*?[") {
		return strings.Contains(url, pattern[1:len(pattern)-1])
	}
	if ok, err := path.Match(pattern, url); err == nil && ok {
		return true
	}
	// Fall back to a plain prefix/contains so a trailing "*" behaves intuitively.
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(url, strings.TrimRight(pattern, "*"))
	}
	return pattern == url
}

// ApplyFPRules returns the first matching rule (if any). Global rules are checked
// before target rules so a broad org-wide suppression wins deterministically.
func ApplyFPRules(rules []FPRule, f FindingKey) (matched *FPRule, suppressed bool) {
	for i := range rules {
		if rules[i].Scope == FPGlobal && rules[i].Matches(f) {
			return &rules[i], true
		}
	}
	for i := range rules {
		if rules[i].Scope == FPTarget && rules[i].Matches(f) {
			return &rules[i], true
		}
	}
	return nil, false
}

// FalsePositiveHints returns human-readable "why this might be a false positive"
// notes for a finding, derived from its confidence and shape. Shown on every
// finding so a triager has context (section 3 requirement).
func FalsePositiveHints(typ string, confidence int, reflectedOnly, statusOnly, wafSeen bool) []string {
	var hints []string
	if confidence < ConfEvidence {
		hints = append(hints, "Confidence is below the evidence bar — treat as needs-review, not confirmed.")
	}
	if statusOnly {
		hints = append(hints, "Signal is status-code-only; a differential/semantic confirmation is missing.")
	}
	if reflectedOnly {
		hints = append(hints, "Payload was reflected but execution/rendering context was not confirmed (possible inert reflection).")
	}
	if wafSeen {
		hints = append(hints, "A WAF/edge block page was observed — response differences may be the WAF, not the app.")
	}
	switch strings.ToLower(typ) {
	case "xss":
		hints = append(hints, "Verify the reflection lands in an executable HTML/JS context, not text/JSON.")
	case "sqli":
		hints = append(hints, "Confirm with a boolean/time differential or sqlmap before treating as exploitable.")
	case "idor", "bola", "bfla":
		hints = append(hints, "Confirm the object truly belongs to another user (ownership), not shared/public data.")
	case "open_redirect", "redirect":
		hints = append(hints, "Confirm the redirect target is attacker-controlled and off-origin.")
	}
	return hints
}
