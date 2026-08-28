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
