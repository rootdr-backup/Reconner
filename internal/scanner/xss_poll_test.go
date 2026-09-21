package scanner

import (
	"strings"
	"testing"
)

func TestXSSProofPollIsNonceScopedAndHydrationAware(t *testing.T) {
	expr := xssProofPollExpression(`RCNX"quoted`)
	for _, want := range []string{
		`document.querySelectorAll('*')`,
		`a.value.includes(n)`,
		`startsWith('javascript:')`,
		`window.` + xssProofResultKey,
		`RCNX\"quoted`,
	} {
		if !strings.Contains(expr, want) {
			t.Fatalf("poll expression missing %q: %s", want, expr)
		}
	}
	if strings.Contains(expr, "setTimeout") {
		t.Fatal("proof poll must not reintroduce an unconditional wait")
	}
}
