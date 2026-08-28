package scanner

import "testing"

// TestLooksLikeBlockPage proves the WAF/block-page gate distinguishes an edge
// block/challenge response (where a "reflection" is the WAF echoing our payload,
// not the app rendering it) from a real application page.
func TestLooksLikeBlockPage(t *testing.T) {
	blocks := []struct {
		status int
		body   string
	}{
		{403, "<html><body>Access Denied — request blocked by Cloudflare. Ray ID: abc123</body></html>"},
		{406, "Not Acceptable — mod_security"},
		{429, "Attention Required! Unusual traffic detected."},
		{503, "<title>Just a moment...</title> checking your browser — DataDome"},
		{200, "Request rejected by the web application firewall"}, // small 200 block template
	}
	for _, b := range blocks {
		if !looksLikeBlockPage(b.status, b.body) {
			t.Errorf("expected block page for status=%d body=%q", b.status, b.body)
		}
	}

	// NOT block pages — real app responses (even a 403 app page with no WAF signature,
	// and a large 200 page that merely mentions a WAF vendor in prose).
	notBlocks := []struct {
		status int
		body   string
	}{
		{200, "<html><body>Welcome to your dashboard. rcnx9137'\"<> reflected here.</body></html>"},
		{403, "<html><body>You do not have permission to edit this note.</body></html>"},
		{200, largePageMentioning("We use Cloudflare for our CDN. ") + "rcnx9137'\"<>"},
	}
	for _, b := range notBlocks {
		if looksLikeBlockPage(b.status, b.body) {
			t.Errorf("did NOT expect block page for status=%d (len=%d)", b.status, len(b.body))
		}
	}
}

func largePageMentioning(s string) string {
	out := s
	for len(out) < 8000 {
		out += "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor. "
	}
	return out
}
