package scanner

import "testing"

func TestResolveScanProfile(t *testing.T) {
	q := ResolveScanProfile("quick", nil)
	if q.Name != ProfileQuick || q.Enabled(FamRace) || !q.Enabled(FamInjection) || q.AuthzMode != "safe" {
		t.Errorf("quick profile wrong: %+v", q)
	}
	s := ResolveScanProfile("", nil) // default → standard
	if s.Name != ProfileStandard || !s.Enabled(FamAccess) || s.Enabled(FamRace) {
		t.Errorf("standard profile wrong: %+v", s)
	}
	d := ResolveScanProfile("DEEP", nil)
	if d.Name != ProfileDeep || !d.Enabled(FamRace) || !d.Enabled(FamProtocol) || d.AuthzProfileFor() != AuthzDeep {
		t.Errorf("deep profile wrong: %+v", d)
	}
	c := ResolveScanProfile("custom", []string{"injection", "ssrf"})
	if c.Name != ProfileCustom || !c.Enabled(FamInjection) || !c.Enabled(FamSSRF) || !c.Enabled(FamCrawl) || c.Enabled(FamRace) {
		t.Errorf("custom profile wrong: %+v", c)
	}
}
