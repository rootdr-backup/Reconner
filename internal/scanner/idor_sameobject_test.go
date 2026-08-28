package scanner

import (
	"fmt"
	"strings"
	"testing"
)

// Two DIFFERENT users' pages that share a large common template (header / nav /
// footer) but hold different personal data must NOT be judged the same object —
// otherwise the cross-identity IDOR/BOLA check reports a false positive when a
// safe app correctly returns each user their own (similarly-templated) page.
func TestBodiesSameObjectRejectsTemplateCollision(t *testing.T) {
	chrome := strings.Repeat("<div class=nav>menu</div>", 40) // shared template
	footer := strings.Repeat("<footer>site</footer>", 40)
	pageFor := func(name, email, bio string) string {
		return chrome +
			"<h1>Profile: " + name + "</h1>" +
			"<span>email: " + email + "</span>" +
			strings.Repeat("<p>"+bio+"</p>", 20) +
			footer
	}
	alice := pageFor("Alice Anderson", "alice@corp.test", "Alice loves hiking and coffee")
	bob := pageFor("Bob Brown", "bob@corp.test", "Bob enjoys cycling and tea aaaa")

	// Same length band (same template) but different personal data → NOT same object.
	if bodiesSameObject(alice, bob) {
		t.Fatalf("two different users' template-shared pages must NOT be judged the same object (len a=%d b=%d)", len(alice), len(bob))
	}

	// The SAME page with only a rotating CSRF token differs → still the same object.
	base := pageFor("Alice Anderson", "alice@corp.test", "Alice loves hiking and coffee")
	withTok := strings.Replace(base, "<footer>site</footer>",
		`<footer>site</footer><input name="csrf" value="`+fmt.Sprintf("%d", 1786500000)+`">`, 1)
	withTok2 := strings.Replace(base, "<footer>site</footer>",
		`<footer>site</footer><input name="csrf" value="`+fmt.Sprintf("%d", 1786599999)+`">`, 1)
	if !bodiesSameObject(withTok, withTok2) {
		t.Fatal("the same object with only a rotating token must still be judged the same object")
	}
}
