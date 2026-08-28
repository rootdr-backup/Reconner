package scanner

import (
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/models"
)

// Surfaces that MUST collapse to one fingerprint (safe dedup).
func TestNucleiSurfaceFolds(t *testing.T) {
	groups := [][]string{
		{ // query values
			"https://x.com/api/user?id=1",
			"https://x.com/api/user?id=2",
			"https://x.com/api/user?id=99999",
		},
		{ // numeric path id
			"https://x.com/user/123",
			"https://x.com/user/456",
		},
		{ // uuid path id
			"https://x.com/u/9a3f1c2e-1111-2222-3333-444455556666",
			"https://x.com/u/7b2c9d4a-aaaa-bbbb-cccc-ddddeeeeffff",
		},
		{ // hex/hash path id
			"https://x.com/f/ab12cd34ef56",
			"https://x.com/f/00ffaa11bb22",
		},
		{ // long-digit / timestamp segment
			"https://x.com/order-1699000000",
			"https://x.com/order-1700000123",
		},
		{ // tracking params dropped
			"https://x.com/p?id=1",
			"https://x.com/p?id=1&utm_source=fb",
			"https://x.com/p?id=1&gclid=abc&fbclid=xyz",
		},
		{ // default port + host case
			"https://X.com:443/a?q=1",
			"https://x.com/a?q=2",
		},
		{ // query key ordering
			"https://x.com/s?a=1&b=2",
			"https://x.com/s?b=9&a=8",
		},
	}
	for i, g := range groups {
		want := nucleiSurfaceFingerprint(g[0])
		for _, u := range g[1:] {
			if got := nucleiSurfaceFingerprint(u); got != want {
				t.Errorf("group %d: %q should fold to %q, got %q", i, u, want, got)
			}
		}
	}
}

// Surfaces that MUST stay distinct (no false-positive dedup — the critical test).
func TestNucleiSurfaceKeepsDistinct(t *testing.T) {
	distinct := [][2]string{
		{"https://x.com/user", "https://x.com/admin/user"},      // different path
		{"https://x.com/a?id=1", "https://x.com/a?id=1&role=2"}, // extra MEANINGFUL param
		{"https://x.com/a", "https://y.com/a"},                  // different host
		{"https://x.com/api/v1/x", "https://x.com/api/v2/x"},    // version in path is meaningful (non-numeric)
		{"https://x.com/p?id=1", "https://x.com/p?uid=1"},       // different param name
		{"http://x.com/a", "https://x.com/a"},                   // scheme differs
	}
	for _, d := range distinct {
		if nucleiSurfaceFingerprint(d[0]) == nucleiSurfaceFingerprint(d[1]) {
			t.Errorf("must stay distinct: %q vs %q", d[0], d[1])
		}
	}
}

func TestDedupeNucleiSurfaces(t *testing.T) {
	raw := []string{
		"https://x.com/api/user?id=1",
		"https://x.com/api/user?id=2",
		"https://x.com/api/user?id=3",
		"https://x.com/admin/user?id=1", // distinct path
		"https://x.com/api/user?id=4&utm_source=x",
	}
	out, collapsed := dedupeNucleiSurfaces(raw, 0, 0)
	if len(out) != 2 {
		t.Fatalf("expected 2 canonical surfaces, got %d: %v", len(out), out)
	}
	if collapsed != 3 {
		t.Fatalf("expected 3 folded, got %d", collapsed)
	}
	// representative must be a real (first-seen) URL, not a fingerprint
	if out[0] != "https://x.com/api/user?id=1" {
		t.Fatalf("first representative should be the first-seen URL, got %q", out[0])
	}
}

func TestDedupeNucleiSurfacesCap(t *testing.T) {
	raw := []string{
		"https://a.com/1", "https://b.com/1", "https://c.com/1", "https://d.com/1",
	}
	out, _ := dedupeNucleiSurfaces(raw, 2, 0)
	if len(out) != 2 {
		t.Fatalf("cap not honored: got %d", len(out))
	}
}

// The aparat.com case: thousands of alphabetic slug paths under the same parent
// (/v/<slug>, /profile/<user>) are ONE logical surface each and must collapse via
// adaptive high-cardinality folding — not explode into thousands of nuclei targets.
func TestDedupeNucleiSurfacesAdaptiveSlugFolding(t *testing.T) {
	var raw []string
	for i := 0; i < 500; i++ {
		raw = append(raw, "https://aparat.com/v/video-title-"+string(rune('a'+i%26))+itoaSurf(i))
		raw = append(raw, "https://aparat.com/profile/user"+itoaSurf(i))
	}
	// A couple of genuinely distinct low-cardinality paths must SURVIVE.
	raw = append(raw, "https://aparat.com/login", "https://aparat.com/admin/config")

	out, _ := dedupeNucleiSurfaces(raw, 8000, 0)
	// 1002 raw URLs collapse to: /v/{dyn}, /profile/{dyn}, /login, /admin/config = 4.
	if len(out) > 8 {
		t.Fatalf("adaptive folding failed: 1000+ slug URLs must collapse to a handful, got %d", len(out))
	}
	joined := " " + surfJoin(out) + " "
	if !containsSurf(joined, "/login") || !containsSurf(joined, "/admin/config") {
		t.Fatalf("low-cardinality real paths must survive folding: %v", out)
	}
}

// Per-host cap: one giant host cannot consume the whole budget.
func TestDedupeNucleiSurfacesPerHostCap(t *testing.T) {
	var raw []string
	// 100 distinct meaningful param surfaces on one path (query keys stay distinct
	// and are NOT adaptively folded), so this isolates the per-host cap.
	for i := 0; i < 100; i++ {
		raw = append(raw, "https://big.com/search?k"+itoaSurf(i)+"=1")
	}
	raw = append(raw, "https://small.com/x", "https://small.com/y")
	out, _ := dedupeNucleiSurfaces(raw, 8000, 10)
	big, small := 0, 0
	for _, u := range out {
		if surfaceHost(u) == "big.com" {
			big++
		} else {
			small++
		}
	}
	if big != 10 {
		t.Fatalf("per-host cap should limit big.com to 10, got %d", big)
	}
	if small != 2 {
		t.Fatalf("other hosts must not be starved by the per-host cap: got %d", small)
	}
}

func itoaSurf(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
func surfJoin(s []string) string {
	out := ""
	for _, x := range s {
		out += x + " "
	}
	return out
}
func containsSurf(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The finding-dedup fix: the same (target, template, matched_url) must insert
// exactly once even across repeated stores (re-scan / restart).
func TestNucleiFindingDedup(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	s := &NucleiScanner{db: db}

	mk := func() *models.NucleiFinding {
		return &models.NucleiFinding{
			ID: uuid.New().String(), TargetID: tid, TemplateID: "cve-2021-1234",
			TemplateName: "n", Severity: "high", MatchedURL: "https://x.com/a",
			Tags: []string{"cve"}, Meta: map[string]string{},
		}
	}
	for i := 0; i < 3; i++ {
		if err := s.storeFinding(mk()); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM nuclei_findings WHERE target_id=? AND template_id='cve-2021-1234' AND matched_url='https://x.com/a'`, tid).Scan(&n)
	if n != 1 {
		t.Fatalf("expected exactly 1 finding after 3 identical stores, got %d", n)
	}
	// a different matched_url is a distinct finding
	f := mk()
	f.MatchedURL = "https://x.com/b"
	_ = s.storeFinding(f)
	_ = db.QueryRow(`SELECT COUNT(*) FROM nuclei_findings WHERE target_id=?`, tid).Scan(&n)
	if n != 2 {
		t.Fatalf("distinct matched_url should be a new finding: got %d", n)
	}
}
