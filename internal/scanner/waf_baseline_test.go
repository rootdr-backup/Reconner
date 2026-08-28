package scanner

import "testing"

func TestLooksLikeWAFBlock(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"cloudflare challenge", 403, "<title>Just a moment...</title> cf-ray: 8ab", true},
		{"cloudflare attention", 403, "Attention Required! | Cloudflare", true},
		{"incapsula", 200, "Request unsuccessful. Incapsula incident ID: 123-456", true},
		{"f5 asm", 200, "The requested URL was rejected. Please consult with your administrator.", true},
		{"modsecurity 406", 406, "anything", true},
		{"rate limited 429", 429, "", true},
		{"sucuri", 403, "Sucuri Website Firewall - Access Denied", true},
		{"plain 403 app page", 403, "You must be logged in to view this page.", false},
		{"normal json", 200, `{"id":1,"name":"widget"}`, false},
		{"empty", 200, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeWAFBlock(c.status, c.body); got != c.want {
				t.Fatalf("looksLikeWAFBlock(%d, %q) = %v, want %v", c.status, c.body, got, c.want)
			}
		})
	}
}

func TestVolProfileThresholds(t *testing.T) {
	// A quiet endpoint keeps the fixed floor.
	quiet := volProfile{valid: true, baseLen: 1000, noise: 0}
	if got := quiet.sigDiff(200); got != 200 {
		t.Fatalf("quiet.sigDiff floor: got %d want 200", got)
	}
	if !quiet.matchesBaseline(1040) { // within noise(0)+48
		t.Fatalf("quiet.matchesBaseline(1040) should be true")
	}
	if quiet.matchesBaseline(1100) {
		t.Fatalf("quiet.matchesBaseline(1100) should be false")
	}

	// A noisy endpoint (wobbles 400B on its own) raises the bar well above 200 so
	// a 400B payload-driven swing no longer counts as signal.
	noisy := volProfile{valid: true, baseLen: 5000, noise: 400}
	if got := noisy.sigDiff(200); got <= 400 {
		t.Fatalf("noisy.sigDiff should exceed the 400B noise floor, got %d", got)
	}
	if !noisy.matchesBaseline(5400) { // within noise(400)+48
		t.Fatalf("noisy.matchesBaseline(5400) should be true")
	}

	// An unmeasured profile degrades to the fixed constants (old behaviour).
	var invalid volProfile
	if got := invalid.sigDiff(200); got != 200 {
		t.Fatalf("invalid.sigDiff should fall back to floor 200, got %d", got)
	}
	// baseLen is 0 for an unmeasured profile, so matchesBaseline uses the fixed
	// ±48 window around 0: 40 is inside it, 100 is outside.
	if !invalid.matchesBaseline(40) || invalid.matchesBaseline(100) {
		t.Fatalf("invalid.matchesBaseline fixed ±48 window around baseLen=0 misbehaved")
	}
}

func TestIntSwingAndMedian(t *testing.T) {
	if got := intSwing([]int{100, 340, 220}); got != 240 {
		t.Fatalf("intSwing = %d want 240", got)
	}
	if got := medianInts([]int{300, 100, 200}); got != 200 {
		t.Fatalf("medianInts = %d want 200", got)
	}
	if got := intSwing(nil); got != 0 {
		t.Fatalf("intSwing(nil) = %d want 0", got)
	}
}
