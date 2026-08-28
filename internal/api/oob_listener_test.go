package api

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Handler{db: db, logger: logger.New("error")}
}

func TestLog4ShellListenerPromotesTokenToFinding(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('tgt-1','example.com')`); err != nil {
		t.Fatal(err)
	}
	// Register a Log4Shell probe.
	tok := "rcnoob0123456789"
	if _, err := h.db.Exec(
		`INSERT INTO oob_probes (token, target_id, url, parameter, kind, sink) VALUES (?,?,?,?,?,?)`,
		tok, "tgt-1", "10.0.0.5:8080", "", "log4shell", "log4shell headers"); err != nil {
		t.Fatal(err)
	}

	// Simulate the inbound LDAP connection carrying the token in its bytes.
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.handleRawOOBConn(server, 1389); close(done) }()
	// Minimal LDAP-ish bytes with the DN = token.
	payload := append([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07}, []byte("0,"+tok)...)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	client.Write(payload)
	client.Close()
	<-done

	var typ, sev string
	err := h.db.QueryRow(`SELECT type, severity FROM vuln_findings WHERE target_id='tgt-1'`).Scan(&typ, &sev)
	if err != nil {
		t.Fatalf("no finding created: %v", err)
	}
	if typ != "log4shell_rce" || sev != "critical" {
		t.Fatalf("bad finding: type=%s sev=%s", typ, sev)
	}
	// hit_count must have incremented.
	var hits int
	h.db.QueryRow(`SELECT hit_count FROM oob_probes WHERE token=?`, tok).Scan(&hits)
	if hits != 1 {
		t.Fatalf("hit_count=%d want 1", hits)
	}
}

func TestLog4ShellListenerIgnoresUnknownToken(t *testing.T) {
	h := newTestHandler(t)
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { h.handleRawOOBConn(server, 1389); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	client.Write([]byte("rcnoobffffffffff not registered"))
	client.Close()
	<-done
	var n int
	h.db.QueryRow(`SELECT COUNT(*) FROM vuln_findings`).Scan(&n)
	if n != 0 {
		t.Fatalf("unknown token must not create a finding, got %d", n)
	}
}

func TestOOBVulnTypeMapping(t *testing.T) {
	cases := map[string]string{
		"log4shell": "log4shell_rce", "rce": "blind_rce", "sqli": "blind_sqli",
		"xxe": "blind_xxe", "ssrf": "blind_ssrf", "": "blind_ssrf",
	}
	for kind, want := range cases {
		if got := oobVulnType(kind); got != want {
			t.Errorf("oobVulnType(%q)=%q want %q", kind, got, want)
		}
	}
}

func TestOOBTokenRegex(t *testing.T) {
	got := oobTokenRe.FindString("blah\x00cn=rcnoobabc0123def,dc=x")
	if got != "rcnoobabc0123def" {
		t.Fatalf("token extract = %q", got)
	}
	if oobTokenRe.MatchString("rcnoobZZZ") {
		t.Fatal("must not match non-hex token")
	}
}
