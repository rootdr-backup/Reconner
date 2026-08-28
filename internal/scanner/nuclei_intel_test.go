package scanner

import (
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
)

func TestClassifyNucleiTemplate(t *testing.T) {
	cases := []struct {
		id   string
		tags []string
		want string
	}{
		{"CVE-2021-1234-sql-injection", []string{"cve", "sqli"}, "sqli"},
		{"generic-xss", []string{"xss"}, "xss"},
		{"ssrf-detection", []string{"ssrf"}, "ssrf"},
		{"path-traversal-lfi", []string{"lfi"}, "lfi"},
		{"apache-struts-rce", []string{"rce"}, "command_injection"},
		{"jinja2-ssti", []string{"ssti"}, "ssti"},
		{"generic-open-redirect", []string{"redirect"}, "open_redirect"},
		{"xxe-billion-laughs", []string{"xxe"}, "xxe"},
		{"git-config-exposure", []string{"exposure", "config"}, "exposure"},
		{"tomcat-default-login", []string{"default-login"}, "default_login"},
		{"apache-httpd-detect", []string{"tech"}, "nuclei"}, // no vuln class
	}
	for _, tc := range cases {
		got, _ := classifyNucleiTemplate(tc.id, tc.tags)
		if got != tc.want {
			t.Errorf("classify(%s,%v) = %q; want %q", tc.id, tc.tags, got, tc.want)
		}
	}
}

func TestNucleiNoisyTemplateGuard(t *testing.T) {
	// detection-only templates → noisy (candidate-only, never a standalone finding)
	noisy := []struct {
		id   string
		tags []string
	}{
		{"apache-detect", []string{"tech", "detect"}},
		{"waf-detect", []string{"waf"}},
		{"tls-version", []string{"ssl", "tls"}},
		{"http-missing-security-header", []string{"headers", "misc"}},
		{"favicon-detection", []string{"tech"}},
	}
	for _, c := range noisy {
		if !nucleiNoisyTemplate(c.id, c.tags) {
			t.Errorf("%s must be treated as noisy", c.id)
		}
	}
	// real vuln classes → NEVER noisy, even with a fingerprint-ish id
	real := []struct {
		id   string
		tags []string
	}{
		{"wordpress-sqli-detect", []string{"sqli", "cve"}}, // has real vuln tag → not noisy
		{"apache-struts-rce", []string{"rce", "cve"}},
		{"open-redirect", []string{"redirect"}},
		{"env-file-exposure", []string{"exposure"}},
	}
	for _, c := range real {
		if nucleiNoisyTemplate(c.id, c.tags) {
			t.Errorf("%s carries a real vuln tag and must NOT be noisy", c.id)
		}
	}
}

func TestNucleiBlockedTemplate(t *testing.T) {
	blocked := []struct{ id, name string }{
		{"SQL", "SQL Injecion"},
		{"sql", "anything"},
		{"header-reflection", "Looking for reflected values from request headers"},
		{"graphite-browser-default-credential", "graphite-browser-default-credential"},
		{"smb-anonymous-access-detection", "SMB Anonymous Access Detection"},
		{"smb-signing-not-required", "SMB Signing Not Required"},
		{"some-other-id", "LFR in Express via GET"}, // name-pattern match, id doesn't matter
		{"lfr-in-express-via-get", "whatever"},      // now blocked by id too (so -eid stops it running)
		{"express-lfr", "whatever"},
	}
	for _, c := range blocked {
		if !nucleiBlockedTemplate(c.id, c.name) {
			t.Errorf("nucleiBlockedTemplate(%q, %q) = false, want true (blocked)", c.id, c.name)
		}
	}
	allowed := []struct{ id, name string }{
		{"sqli-error-based-mysql", "MySQL Error-Based SQL Injection"},
		{"CVE-2021-1234", "Some Real CVE"},
		{"open-redirect-bypass", "Open Redirect Vulnerability Detection"},
	}
	for _, c := range allowed {
		if nucleiBlockedTemplate(c.id, c.name) {
			t.Errorf("nucleiBlockedTemplate(%q, %q) = true, want false (not blocked)", c.id, c.name)
		}
	}
}

func TestNucleiExcludeIDFlag(t *testing.T) {
	flag := nucleiExcludeIDFlag(nil)
	if len(flag) != 2 || flag[0] != "-eid" {
		t.Fatalf("nucleiExcludeIDFlag(nil) = %v, want [-eid <ids>]", flag)
	}
	if !strings.Contains(flag[1], "sql") {
		t.Fatalf("nucleiExcludeIDFlag(nil) must include the built-in blocklist, got %q", flag[1])
	}

	cfg := &config.Config{NucleiExcludeTemplateIDs: []string{"my-custom-bad-template"}}
	flag2 := nucleiExcludeIDFlag(cfg)
	if !strings.Contains(flag2[1], "my-custom-bad-template") {
		t.Fatalf("operator-added exclusions must be included: %q", flag2[1])
	}
	if !strings.Contains(flag2[1], "sql") {
		t.Fatalf("operator-added exclusions must be ADDITIVE to the built-in list, got %q", flag2[1])
	}
}

func TestParamFromURL(t *testing.T) {
	if got := paramFromURL("https://x.com/a?id=5&foo=bar"); got != "id" {
		t.Errorf("should prefer injectable param 'id', got %q", got)
	}
	if got := paramFromURL("https://x.com/a?redirect=/home"); got != "redirect" {
		t.Errorf("should pick 'redirect', got %q", got)
	}
	if got := paramFromURL("https://x.com/a"); got != "" {
		t.Errorf("no query → empty, got %q", got)
	}
}

func TestNucleiToCandidateVerifiableCarriesParam(t *testing.T) {
	c := nucleiToCandidate("t1", "generic-xss", "XSS", "high", "https://x.com/s?q=hi", []string{"xss"})
	if c.Type != "xss" || c.Parameter != "q" || c.Location != "query" {
		t.Fatalf("xss candidate must carry the query param: %+v", c)
	}
	if c.DetectionSource != "nuclei" || c.DetectionMethod != "template:generic-xss" {
		t.Fatalf("provenance must name the template: %+v", c)
	}
	// a non-verifiable exposure hit needn't carry a param
	e := nucleiToCandidate("t1", "git-exposure", "git", "medium", "https://x.com/.git/config", []string{"exposure"})
	if e.Type != "exposure" {
		t.Fatalf("exposure classification: %+v", e)
	}
}
