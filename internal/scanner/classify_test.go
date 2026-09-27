package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClassifyStatusBands(t *testing.T) {
	cases := []struct {
		conf     int
		wantStat string
		wantOK   bool
	}{
		{100, StatusFinding, true},
		{95, StatusFinding, true},
		{90, StatusFinding, true},
		{89, StatusCandidate, true},
		{70, StatusCandidate, true},
		{69, "", false},
		{0, "", false},
	}
	for _, c := range cases {
		got, ok := ClassifyStatus(c.conf)
		if got != c.wantStat || ok != c.wantOK {
			t.Errorf("ClassifyStatus(%d)=(%q,%v) want (%q,%v)", c.conf, got, ok, c.wantStat, c.wantOK)
		}
	}
}

// TestOpenRedirectExternalVsInternal spins up a server that honors the payload
// for an external target but keeps `next=/home` internal.
func TestOpenRedirectExternalVsInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(200)
			return
		}
		// Vulnerable: reflect whatever 'next' is into Location verbatim.
		w.Header().Set("Location", next)
		w.WriteHeader(302)
	}))
	defer srv.Close()

	// External payload → verified finding.
	res, ok := checkOpenRedirectURL(srv.URL+"/login?next=x", "next")
	if !ok || res.class != redirectExternal {
		t.Fatalf("expected external finding, got ok=%v class=%v", ok, res.class)
	}

	// A server that only ever redirects to a same-origin path → candidate.
	internalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect internally regardless of payload (sanitised app).
		w.Header().Set("Location", "/home")
		w.WriteHeader(302)
	}))
	defer internalSrv.Close()
	res2, ok2 := checkOpenRedirectURL(internalSrv.URL+"/login?next=x", "next")
	if !ok2 || res2.class != redirectInternal {
		t.Fatalf("expected internal candidate, got ok=%v class=%v", ok2, res2.class)
	}
}

func TestStripScriptStyleReflection(t *testing.T) {
	// Probe only inside <script> → must NOT count.
	jsOnly := "<html><body>hello</body><script>var x='" + reflectProbe + "';</script></html>"
	if strings.Contains(stripScriptStyle(jsOnly), reflectProbe) {
		t.Error("JS-only reflection should be stripped")
	}
	// Probe in real HTML body → must count.
	htmlBody := "<html><body>echo " + reflectProbe + "</body></html>"
	if !strings.Contains(stripScriptStyle(htmlBody), reflectProbe) {
		t.Error("HTML-body reflection should remain")
	}
}

func TestIsExternalRedirectHost(t *testing.T) {
	cases := []struct {
		final, origin string
		want          bool
	}{
		{"evil.com", "target.com", true},
		{"target.com", "target.com", false},
		{"app.target.com", "target.com", false}, // subdomain = same org
		{"", "target.com", false},
	}
	for _, c := range cases {
		if got := isExternalRedirectHost(c.final, c.origin); got != c.want {
			t.Errorf("isExternalRedirectHost(%q,%q)=%v want %v", c.final, c.origin, got, c.want)
		}
	}
}

func TestSSRFReflectionGuard(t *testing.T) {
	payload := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	// The classic FP: endpoint echoes our payload URL back into the page.
	reflected := "<html>Redirecting to " + payload + " ...</html>"
	if !responseReflectsPayload(reflected, payload) {
		t.Error("must flag payload reflection (the gama.ir-style FP)")
	}
	// Payload host present but not the full URL → still reflection.
	partial := "error: could not reach 169.254.169.254"
	if !responseReflectsPayload(partial, payload) {
		t.Error("metadata host in body must be treated as reflection")
	}
	// A genuine creds JSON never contains the request URL or metadata host.
	realCreds := `{"Code":"Success","AccessKeyId":"ASIAX","SecretAccessKey":"abc"}`
	if responseReflectsPayload(realCreds, payload) {
		t.Error("real creds JSON must NOT be treated as reflection")
	}
}

// TestSSRFRedirectChainPayloads proves the redirect-chain SSRF bypass is built
// only from a CONFIRMED (verified=1) open redirect on the target's own
// domain, and that the metadata target is substituted into the exact
// parameter the redirect was proven vulnerable through — never a param this
// scanner invented on its own, and never an unverified/candidate row.
func TestSSRFRedirectChainPayloads(t *testing.T) {
	db, tid := testDB(t)
	_, err := db.Exec(`INSERT INTO open_redirect_findings (id, target_id, url, redirect_to, parameter, verified)
		VALUES ('or1', ?, 'https://target.example/go?next=https%3A%2F%2Fgood.example%2F', 'evil.com', 'next', 1)`, tid)
	if err != nil {
		t.Fatal(err)
	}
	// An unverified (candidate) redirect must NOT be turned into an SSRF payload.
	_, err = db.Exec(`INSERT INTO open_redirect_findings (id, target_id, url, redirect_to, parameter, verified)
		VALUES ('or2', ?, 'https://target.example/go2?dest=/relative', '', 'dest', 0)`, tid)
	if err != nil {
		t.Fatal(err)
	}

	s := &SSRFScanner{db: db}
	got := s.redirectChainPayloads(context.Background(), tid)
	if len(got) != len(redirectChainMetaTargets) {
		t.Fatalf("expected %d payload(s) from the one verified redirect, got %d: %+v", len(redirectChainMetaTargets), len(got), got)
	}
	for _, p := range got {
		u, err := url.Parse(p.url)
		if err != nil {
			t.Fatalf("payload is not a valid URL: %q", p.url)
		}
		if u.Host != "target.example" || u.Path != "/go" {
			t.Errorf("expected the target's own trusted host/path to be preserved, got %q", p.url)
		}
		next := u.Query().Get("next")
		if !strings.Contains(next, "169.254.169.254") && !strings.Contains(next, "2852039166") {
			t.Errorf("expected the vulnerable parameter to carry a metadata URL, got %q", next)
		}
		if u.Query().Get("dest") != "" {
			t.Errorf("must not touch the unverified redirect's parameter: %q", p.url)
		}
	}
}

func TestVersionMatchesConstraint(t *testing.T) {
	cases := []struct {
		ver, con string
		want     bool
	}{
		{"3.4.1", "<3.5.0", true},
		{"3.5.0", "<3.5.0", false},
		{"4.17.20", "<4.17.21", true},
		{"1.6.0", "*", true},
		{"4.6.2", "4.x", true},
		{"3.6.2", "4.x", false},
	}
	for _, c := range cases {
		if got := versionMatchesConstraint(c.ver, c.con); got != c.want {
			t.Errorf("versionMatchesConstraint(%q,%q)=%v want %v", c.ver, c.con, got, c.want)
		}
	}
}

func TestVulnerableLibraryFingerprint(t *testing.T) {
	js := `/*! jQuery JavaScript Library v3.3.1 */ ;window.x=1;`
	hits := fingerprintVulnerableLibraries(js)
	if len(hits) == 0 || hits[0].Name != "jQuery" {
		t.Fatalf("expected jQuery CVE hit, got %+v", hits)
	}
	// A patched version must NOT flag.
	if len(fingerprintVulnerableLibraries(`jQuery JavaScript Library v3.7.1`)) != 0 {
		t.Error("patched jQuery should not be flagged")
	}
}
