package scanner

import "testing"

func TestCSTIEvaluationRequiresClientOnlyResult(t *testing.T) {
	payload := "rcncsti{{7*7}}z"
	expected := "rcncsti49z"
	if !cstiEvaluationProven("<p>"+payload+"</p>", payload, expected, "<p>"+expected+"</p>") {
		t.Fatal("raw expression evaluated only after render must be proven")
	}
	if cstiEvaluationProven("<p>"+expected+"</p>", payload, expected, "<p>"+expected+"</p>") {
		t.Fatal("server-side evaluation must not be mislabeled CSTI")
	}
	if cstiEvaluationProven("<p>"+payload+"</p>", payload, expected, "<p>"+payload+"</p>") {
		t.Fatal("plain reflection must not be a CSTI finding")
	}
	if cstiEvaluationProven("<p>rcncsti&#123;&#123;7*7&#125;&#125;z</p>", payload, expected, "<p>"+expected+"</p>") {
		t.Fatal("a modified/entity-encoded raw expression must not satisfy the strict CSTI proof")
	}
}
