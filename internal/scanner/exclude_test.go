package scanner

import "testing"

func TestExclusions(t *testing.T) {
	e := ParseExclusions("dev.example.com, *.staging.example.com, 10.0.0.0/24, https://admin.example.com/panel, 192.168.5.5")

	excluded := []string{
		"dev.example.com",              // exact
		"DEV.example.com",              // case-insensitive
		"staging.example.com",          // wildcard apex
		"api.staging.example.com",      // wildcard subdomain
		"deep.api.staging.example.com", // nested wildcard
		"admin.example.com",            // from URL
		"10.0.0.7",                     // CIDR
		"192.168.5.5",                  // exact IP
		"dev.example.com:8443",         // host:port stripped
	}
	for _, h := range excluded {
		if !e.Excludes(h) {
			t.Errorf("%q should be excluded", h)
		}
	}

	kept := []string{
		"example.com",             // apex not excluded by a subdomain rule
		"www.example.com",         // unrelated host
		"staging.example.org",     // different registrable
		"10.0.1.7",                // outside the /24
		"notstaging.example.com",  // must not match the *.staging suffix loosely
	}
	for _, h := range kept {
		if e.Excludes(h) {
			t.Errorf("%q should NOT be excluded", h)
		}
	}

	// Network-side: excluded IPs are dropped from an expanded scope.
	ips := []string{"10.0.0.1", "10.0.0.99", "192.168.5.5", "8.8.8.8"}
	kept, dropped := FilterExcludedIPs(ips, e)
	if dropped != 3 { // 10.0.0.1, 10.0.0.99 (in /24), 192.168.5.5
		t.Errorf("dropped=%d want 3 (kept=%v)", dropped, kept)
	}
	if len(kept) != 1 || kept[0] != "8.8.8.8" {
		t.Errorf("kept=%v want [8.8.8.8]", kept)
	}
	if _, d := FilterExcludedIPs(ips, ParseExclusions("")); d != 0 {
		t.Errorf("no exclusions must drop nothing, dropped=%d", d)
	}

	if !ParseExclusions("").Empty() {
		t.Error("empty exclude string must yield an Empty set")
	}
	if ParseExclusions("a.com").Excludes("b.com") {
		t.Error("unrelated host must not be excluded")
	}
}
