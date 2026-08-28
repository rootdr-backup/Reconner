package scanner

import "testing"

func TestParamTokens(t *testing.T) {
	cases := map[string][]string{
		"returnUrl":    {"return", "url"},
		"redirect_uri": {"redirect", "uri"},
		"imageURL2":    {"image", "url", "2"},
		"file.path":    {"file", "path"},
		"user_id":      {"user", "id"},
	}
	for in, want := range cases {
		got := paramTokens(in)
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: got %v, want %v", in, got, want)
				break
			}
		}
	}
}

// The headline upgrade: names the OLD exact-match maps missed must now route.
func TestClassifierCatchesRealParams(t *testing.T) {
	prone := func(c VulnClass, name string) bool { return paramProneTo(c, name, "") }

	// SSRF — camelCase / underscored variants the exact-match map missed.
	for _, n := range []string{"returnUrl", "redirect_uri", "image_url", "callbackUrl", "fileURL", "webhook_url"} {
		if !prone(ClassSSRF, n) {
			t.Errorf("SSRF must route %q", n)
		}
	}
	// LFI
	for _, n := range []string{"file_path", "downloadFile", "templateName", "includePath"} {
		if !prone(ClassLFI, n) {
			t.Errorf("LFI must route %q", n)
		}
	}
	// Open-redirect must keep goto/returnUrl but DROP the substring FPs.
	if !prone(ClassRedirect, "goto") || !prone(ClassRedirect, "returnUrl") {
		t.Error("redirect must route goto / returnUrl")
	}
	for _, fp := range []string{"token", "photo", "layout", "about", "custom"} {
		if prone(ClassRedirect, fp) {
			t.Errorf("redirect must NOT route the substring false positive %q", fp)
		}
	}
}

// Value heuristics route regardless of the parameter name.
func TestClassifierValueHeuristics(t *testing.T) {
	if !paramProneTo(ClassSSRF, "data", "https://internal.example/") {
		t.Error("a URL-valued param must route to SSRF even with a plain name")
	}
	if !paramProneTo(ClassRedirect, "data", "//evil.com") {
		t.Error("a protocol-relative URL value must route to open-redirect")
	}
	if !paramProneTo(ClassLFI, "x", "/var/www/config.php") {
		t.Error("a path-looking value must route to LFI")
	}
	if !paramProneTo(ClassIDOR, "ref", "1024") {
		t.Error("a numeric value must route to IDOR")
	}
	// A plain word value provides no signal on its own.
	if paramProneTo(ClassSSRF, "color", "blue") {
		t.Error("a plain value must not route to SSRF")
	}
}
