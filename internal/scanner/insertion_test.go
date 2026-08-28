package scanner

import (
	"context"
	"io"
	"strings"
	"testing"
)

func reqBody(t *testing.T, ip insertionPoint, value string) string {
	t.Helper()
	req, err := buildInjectedRequest(context.Background(), ip, value, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(req.Body)
	return string(b)
}

// Regression: a pre-encoded bypass payload (%0a, ..%2f) injected into a POST form
// body must survive to the wire, NOT be double-encoded (%0a → %250a) by
// url.Values.Encode() into an inert literal — which silently defeated every
// injection detector's encoded WAF-bypass payloads on POST endpoints.
func TestPostBodyPreservesPreEncodedPayload(t *testing.T) {
	ip := insertionPoint{URL: "http://x.com/login?next=/home", Param: "user", Method: "POST"}
	body := reqBody(t, ip, "x%0asleep 5")

	if !strings.Contains(body, "user=x%0asleep%205") {
		t.Fatalf("pre-encoded payload was mangled in POST body: %q", body)
	}
	if strings.Contains(body, "%250a") {
		t.Fatalf("payload was double-encoded (%%0a -> %%250a): %q", body)
	}
	// Sibling query param is preserved as a normal (encoded) field.
	if !strings.Contains(body, "next=") {
		t.Fatalf("sibling form field lost: %q", body)
	}
}

// A raw structural character in the value must still be escaped so it can't break
// out of its own field (preserving field boundaries).
func TestPostBodyEscapesFieldBoundaries(t *testing.T) {
	ip := insertionPoint{URL: "http://x.com/s", Param: "q", Method: "POST"}
	body := reqBody(t, ip, "a&admin=1")
	// The '&' in the value must be escaped, so it cannot inject a second field.
	if strings.Contains(body, "q=a&admin=1") {
		t.Fatalf("unescaped & let the value inject a new field: %q", body)
	}
	if !strings.Contains(body, "q=a%26admin=1") {
		t.Fatalf("value & not escaped as expected: %q", body)
	}
}
