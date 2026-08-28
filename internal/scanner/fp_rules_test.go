package scanner

import "testing"

func TestFPRuleMatching(t *testing.T) {
	f := FindingKey{TargetID: "t1", Type: "xss", TemplateID: "reflected-xss", URL: "https://x.test/api/legacy/echo", Parameter: "q", Payload: "<svg onload=1>"}

	// exact type + param
	if !(FPRule{Enabled: true, Scope: FPGlobal, Type: "XSS", Parameter: "q"}).Matches(f) {
		t.Error("case-insensitive type+param rule must match")
	}
	// non-matching param must NOT match
	if (FPRule{Enabled: true, Scope: FPGlobal, Type: "xss", Parameter: "other"}).Matches(f) {
		t.Error("different parameter must not match")
	}
	// url glob + substring forms
	if !(FPRule{Enabled: true, Scope: FPGlobal, URLPattern: "*/legacy/*"}).Matches(f) {
		t.Error("*/legacy/* substring pattern must match")
	}
	if !(FPRule{Enabled: true, Scope: FPGlobal, URLPattern: "https://x.test/api/*"}).Matches(f) {
		t.Error("prefix glob must match")
	}
	// payload substring
	if !(FPRule{Enabled: true, Scope: FPGlobal, Payload: "onload="}).Matches(f) {
		t.Error("payload substring must match")
	}
	// template id
	if !(FPRule{Enabled: true, Scope: FPGlobal, TemplateID: "reflected-xss"}).Matches(f) {
		t.Error("template id must match")
	}
	// inert rule (no selectors) must NEVER match
	if (FPRule{Enabled: true, Scope: FPGlobal}).Matches(f) {
		t.Error("an empty rule must not suppress everything")
	}
	// disabled rule must not match
	if (FPRule{Enabled: false, Scope: FPGlobal, Type: "xss"}).Matches(f) {
		t.Error("disabled rule must not match")
	}
	// target-scoped rule only matches its target
	if (FPRule{Enabled: true, Scope: FPTarget, TargetID: "other", Type: "xss"}).Matches(f) {
		t.Error("target rule must not match a different target")
	}
	if !(FPRule{Enabled: true, Scope: FPTarget, TargetID: "t1", Type: "xss"}).Matches(f) {
		t.Error("target rule must match its own target")
	}
}

func TestApplyFPRulesGlobalWins(t *testing.T) {
	f := FindingKey{TargetID: "t1", Type: "sqli", URL: "https://x.test/a"}
	rules := []FPRule{
		{ID: "tgt", Enabled: true, Scope: FPTarget, TargetID: "t1", Type: "sqli"},
		{ID: "glb", Enabled: true, Scope: FPGlobal, Type: "sqli"},
	}
	m, ok := ApplyFPRules(rules, f)
	if !ok || m.ID != "glb" {
		t.Fatalf("global rule must win, got %+v ok=%v", m, ok)
	}
	if _, ok := ApplyFPRules(nil, f); ok {
		t.Error("no rules must not suppress")
	}
}

func TestTriageStates(t *testing.T) {
	for _, s := range []string{StateNew, StateConfirmed, StateFalsePos, StateAcceptedRisk, StateFixed, "FALSE_POSITIVE"} {
		if !ValidTriageState(s) {
			t.Errorf("%q must be a valid triage state", s)
		}
	}
	if ValidTriageState("garbage") {
		t.Error("garbage must be rejected")
	}
}

func TestFalsePositiveHints(t *testing.T) {
	h := FalsePositiveHints("xss", 60, true, false, false)
	if len(h) == 0 {
		t.Fatal("low-confidence reflected XSS must produce hints")
	}
	joined := ""
	for _, s := range h {
		joined += s + " "
	}
	if !contains(joined, "context") {
		t.Errorf("XSS hints must mention execution context: %v", h)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
