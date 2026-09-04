package scanner

import (
	"net/http"
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestScopedBrowserHeadersDoNotLeakOffScope(t *testing.T) {
	id := requestIdentity{
		userAgent: "Program UA",
		headers:   http.Header{"X-Program": {"program-token"}},
		hosts:     []string{"example.com"},
	}
	existing := network.Headers{"Accept": "text/html", "X-Explicit": "page"}
	entries, ok := scopedBrowserHeaderEntries(id, "https://app.example.com/", existing, map[string]string{
		"Cookie":     "session=one",
		"X-Explicit": "auth",
	})
	if !ok {
		t.Fatal("in-scope browser request did not receive headers")
	}
	got := map[string]string{}
	for _, entry := range entries {
		got[entry.Name] = entry.Value
	}
	if got["User-Agent"] != "Program UA" || got["X-Program"] != "program-token" || got["Cookie"] != "session=one" {
		t.Fatalf("missing browser request identity: %#v", got)
	}
	if got["X-Explicit"] != "auth" {
		t.Fatalf("explicit auth header did not win: %#v", got)
	}

	if entries, ok := scopedBrowserHeaderEntries(id, "https://cdn.invalid/app.js", existing, map[string]string{"Cookie": "session=one"}); ok || entries != nil {
		t.Fatalf("headers leaked to an off-scope subresource: %#v", entries)
	}
}
