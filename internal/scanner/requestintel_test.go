package scanner

import (
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	a := NormalizeURL("https://x.com/api/orders/123/items?b=2&a=1")
	b := NormalizeURL("https://x.com/api/orders/999/items?a=9&b=8")
	if a != b {
		t.Fatalf("numeric ids + query values must normalize equal: %q vs %q", a, b)
	}
	if !strings.Contains(a, "/api/orders/{id}/items") {
		t.Fatalf("ids must collapse to {id}: %q", a)
	}
}

func TestNormalizeURLHostNormalization(t *testing.T) {
	// Same file served via www + explicit :443 must fold to one key,
	// otherwise Needs Review lists them as separate rows.
	groups := [][]string{
		{
			"https://www.example.com:443/js/app.js",
			"https://example.com/js/app.js",
			"https://WWW.EXAMPLE.COM/js/app.js",
		},
		{ // default ports stripped per scheme
			"https://example.com:443/a?q=1",
			"https://example.com/a?q=2",
		},
		{
			"http://example.com:80/a",
			"http://example.com/a",
		},
		{ // fragment + trailing slash noise
			"https://example.com/a#section",
			"https://example.com/a",
			"https://example.com/a/",
		},
	}
	for i, g := range groups {
		want := NormalizeURL(g[0])
		for _, u := range g[1:] {
			if got := NormalizeURL(u); got != want {
				t.Errorf("group %d: %q should normalize to %q, got %q", i, u, want, got)
			}
		}
	}

	// Must stay distinct: non-default port, different subdomain, different scheme.
	distinct := [][2]string{
		{"https://example.com:8443/a", "https://example.com/a"},
		{"https://api.example.com/a", "https://example.com/a"},
		{"http://example.com/a", "https://example.com/a"},
		{"https://example.com:443/a", "http://example.com:443/a"},
	}
	for _, d := range distinct {
		if NormalizeURL(d[0]) == NormalizeURL(d[1]) {
			t.Errorf("must stay distinct: %q vs %q (both -> %q)", d[0], d[1], NormalizeURL(d[0]))
		}
	}
}

func TestBodyHashStableUnderNonce(t *testing.T) {
	h1 := BodyHash(`{"user":"alice","csrf":"AAA111","ts":1699999999}`)
	h2 := BodyHash(`{"user":"alice","csrf":"BBB222","ts":1700000001}`)
	if h1 != h2 {
		t.Fatal("hash must ignore volatile csrf/timestamp tokens")
	}
	if h1 == BodyHash(`{"user":"bob"}`) {
		t.Fatal("structurally different bodies must hash differently")
	}
}

func TestSemanticCompare(t *testing.T) {
	obj := IdentityResponse{Status: 200, Len: 300, CT: "application/json", Body: strings.Repeat("x", 300)}
	denied := IdentityResponse{Status: 403}
	if SemanticCompare(obj, obj) != "same-object" {
		t.Error("identical → same-object")
	}
	if SemanticCompare(obj, denied) != "one-denied" {
		t.Error("one denied → one-denied")
	}
	if SemanticCompare(denied, denied) != "both-denied" {
		t.Error("both denied → both-denied")
	}
}

func TestRedaction(t *testing.T) {
	in := "Authorization: Bearer eyJhbGciOiJIUzI1.aaaaaa.bbbbbb\nCookie: session=deadbeefcafe\napi_key=SECRETVALUE123"
	out := RedactText(in)
	for _, leak := range []string{"eyJhbGciOiJIUzI1", "deadbeefcafe", "SECRETVALUE123"} {
		if strings.Contains(out, leak) {
			t.Fatalf("credential leaked through redaction: %q", leak)
		}
	}
	h := RedactHeaders(map[string]string{"Cookie": "s=1", "Authorization": "Bearer x", "Accept": "*/*"})
	if h["Cookie"] != "[REDACTED]" || h["Authorization"] != "[REDACTED]" {
		t.Fatal("sensitive headers must be masked")
	}
	if h["Accept"] != "*/*" {
		t.Fatal("non-sensitive headers must be preserved")
	}
}
