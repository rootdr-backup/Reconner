package scanner

import (
	"strings"
	"testing"
)

// Browser-confirmation payloads may show the requested Reconner proof popup, but
// must not turn that proof into data access or exfiltration.
func TestXSSBrowserPayloadsAreNonExfiltratingProofs(t *testing.T) {
	for _, payload := range xssBrowserPayloads() {
		lower := strings.ToLower(payload)
		if !strings.Contains(payload, "document.title") {
			t.Errorf("payload lacks the nonce proof sink: %q", payload)
		}
		if !strings.Contains(payload, "alert('reconner')") {
			t.Errorf("payload lacks the requested Reconner proof popup: %q", payload)
		}
		if !strings.Contains(payload, "postMessage") {
			t.Errorf("payload lacks the cross-frame nonce proof channel: %q", payload)
		}
		for _, forbidden := range []string{
			"confirm(", "prompt(", "document.cookie", "localstorage",
			"sessionstorage", "fetch(", "xmlhttprequest", "sendbeacon(",
		} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("payload contains non-proof behavior %q: %q", forbidden, payload)
			}
		}
	}
}
