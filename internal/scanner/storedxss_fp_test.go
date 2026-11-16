package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A persisted payload only matters if the page a victim loads is rendered as
// HTML. cleanFetch must reject text/plain, text/css/js and JSON responses so a
// stored payload surfacing in a non-HTML endpoint isn't reported as stored XSS.
func TestStoredXSSCleanFetchContentTypeGate(t *testing.T) {
	withLoopbackAllowed(t)
	payload := "<svg onload=alert(1)>"
	mux := http.NewServeMux()
	mux.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + payload + "</div>"))
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("<div>" + payload + "</div>"))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"x":"` + payload + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &VulnScanner{}
	if b := s.cleanFetch(context.Background(), srv.URL+"/html", nil); !strings.Contains(b, payload) {
		t.Fatalf("a text/html page must be fetched, got %q", b)
	}
	if b := s.cleanFetch(context.Background(), srv.URL+"/plain", nil); b != "" {
		t.Fatalf("text/plain must be rejected (payload cannot execute as markup), got %q", b)
	}
	if b := s.cleanFetch(context.Background(), srv.URL+"/json", nil); b != "" {
		t.Fatalf("application/json must be rejected, got %q", b)
	}
}

// TestHTMLAttrInjectedRequiresLiveParsedElement is the regression test for
// the stored-XSS false positive RunStoredBlindXSS used to produce: a plain
// substring match of the injected payload was previously treated as proof of
// execution (via the old classifyXSSContext tag-position heuristic), but the
// exact same bytes also survive when a server interpolates the stored value
// into a <script> block, a <textarea>, or an HTML comment WITHOUT HTML-
// encoding it — none of which a real browser executes, since the HTML5
// tokenizer only ends a <script>/RAWTEXT/RCDATA element or a comment on its
// own literal close sequence, never on a bare '>'. storeVuln always verdicts
// such a hit VerifyVerified/critical with no further gate, so this was a
// real, high-severity false-positive path. htmlAttrInjected now requires the
// breakout to have genuinely formed a live, parsed element instead.
func TestHTMLAttrInjectedRequiresLiveParsedElement(t *testing.T) {
	const payload = `rcnsto0123"><svg/onload=alert(1)>`
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "genuine HTML-text breakout forms a live svg element",
			body: `<html><body><div>` + payload + `</div></body></html>`,
			want: true,
		},
		{
			name: "server interpolates the value unescaped into a script block: stays inert text",
			body: `<html><body><script>var state = {"comment": "` + payload + `"};</script></body></html>`,
			want: false,
		},
		{
			name: "application/json-typed script data block: stays inert text",
			body: `<html><body><script type="application/json">{"last":"` + payload + `"}</script></body></html>`,
			want: false,
		},
		{
			name: "inside a textarea: stays inert text",
			body: `<html><body><textarea>` + payload + `</textarea></body></html>`,
			want: false,
		},
		{
			name: "inside an HTML comment: stays inert text",
			body: `<html><body><!-- ` + payload + ` --></body></html>`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := htmlAttrInjected(tc.body, "svg", "onload", "alert(1)"); got != tc.want {
				t.Fatalf("htmlAttrInjected=%v, want %v for body %q", got, tc.want, tc.body)
			}
		})
	}
}

// TestHTMLAttrInjectedMatchesAttributeExactly guards the helper's own
// precision: it must not match a same-named element with a DIFFERENT
// attribute value (a coincidental, unrelated onload elsewhere on the page),
// and attribute-name matching must be case-insensitive like real HTML.
func TestHTMLAttrInjectedMatchesAttributeExactly(t *testing.T) {
	if !htmlAttrInjected(`<svg ONLOAD="alert(1)"></svg>`, "svg", "onload", "alert(1)") {
		t.Fatal("expected a case-insensitive attribute-name match")
	}
	if htmlAttrInjected(`<svg onload="alert(2)"></svg>`, "svg", "onload", "alert(1)") {
		t.Fatal("a different attribute value must not match")
	}
	if htmlAttrInjected(`<div onload="alert(1)"></div>`, "svg", "onload", "alert(1)") {
		t.Fatal("a different element name must not match")
	}
}
