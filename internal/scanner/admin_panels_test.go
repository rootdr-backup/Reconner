package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestClassifyAdminPanelRequiresStrongEvidence(t *testing.T) {
	if _, ok := classifyAdminPanel("https://app.test/admin", 200, "Documentation", []byte(`<p>The admin API is documented here.</p>`), ""); ok {
		t.Fatal("path-only generic page must not become an admin panel")
	}
	if got, ok := classifyAdminPanel("https://app.test/admin/login", 200, "Admin sign in", []byte(`<form><input type="password"></form>`), ""); !ok || got.PanelType != "admin login" {
		t.Fatalf("credential-backed admin login was missed: ok=%v got=%+v", ok, got)
	}
	if got, ok := classifyAdminPanel("https://ops.test/", 200, "Grafana", []byte(`<div class="grafana-app"></div>`), ""); !ok || got.Product != "Grafana" {
		t.Fatalf("strong product fingerprint was missed: ok=%v got=%+v", ok, got)
	}
	if _, ok := classifyAdminPanel("https://admin-host.test/", 200, "Admin Login", nil, ""); !ok {
		t.Fatal("dedicated-host root panel with an exact administrative title was missed")
	}
	if _, ok := classifyAdminPanel("https://app.test/admin", 302, "Admin login", []byte(`<form><input type="password"></form>`), "/auth/login"); ok {
		t.Fatal("an unresolved redirect must never become an admin-panel finding")
	}
	if _, ok := classifyAdminPanel("https://app.test/management", 403, "", nil, ""); !ok {
		t.Fatal("restricted management endpoint must be retained")
	}
}

func TestAdminPanelRedirectMustResolveAndVerify(t *testing.T) {
	db, targetID := testDB(t)
	defer db.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><title>Admin Login</title><form><input type="password"></form></html>`))
		case "/false-admin":
			http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
		default:
			_, _ = w.Write([]byte(`<html><title>Documentation</title><p>Nothing administrative here.</p></html>`))
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	s := NewDirScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"))
	if !s.probeAndStore(context.Background(), targetID, server.URL+"/admin", soft404{}) {
		t.Fatal("verified redirect destination was not stored as a directory result")
	}
	if !s.probeAndStore(context.Background(), targetID, server.URL+"/false-admin", soft404{}) {
		t.Fatal("ordinary redirect destination was not stored as a directory result")
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM admin_panel_findings WHERE target_id=?`, targetID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("admin panel findings=%d, want exactly the verified login destination", count)
	}
	var status int
	var redirect string
	if err := db.QueryRow(`SELECT status_code,redirect_url FROM admin_panel_findings WHERE target_id=?`, targetID).Scan(&status, &redirect); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || redirect != server.URL+"/login" {
		t.Fatalf("stored status/redirect=(%d,%q), want final 200 and followed destination", status, redirect)
	}
}

func TestAdminPanelGroupingCollapsesHostSpecificCopies(t *testing.T) {
	a := []byte(`<html><title>Admin</title><form action="https://one.test/login"><input name="csrf" value="0123456789abcdef"><input type="password"></form></html>`)
	b := []byte(`<html> <title>Admin</title> <form action="https://two.test/login"><input name="csrf" value="fedcba9876543210"><input type="password"></form> </html>`)
	ha, hb := panelContentHash(a), panelContentHash(b)
	if ha == "" || ha != hb {
		t.Fatalf("host/token/whitespace normalization should dedupe equivalent panels: %q != %q", ha, hb)
	}
	sig := panelSignature{Product: "Administrative login"}
	if adminPanelGroupKey(sig, "https://one.test/admin", "", ha, "Admin") != adminPanelGroupKey(sig, "https://two.test/admin", "", hb, "Admin") {
		t.Fatal("equivalent content must produce one group")
	}
}

func TestAdminPanelGroupingUsesRedirectDestination(t *testing.T) {
	sig := panelSignature{Product: "Administrative login"}
	a := adminPanelGroupKey(sig, "https://a.test/admin", "https://login.test/console?state=one", "", "")
	b := adminPanelGroupKey(sig, "https://b.test/admin", "https://login.test/console?state=two", "", "")
	if a != b {
		t.Fatalf("volatile redirect queries should collapse: %q != %q", a, b)
	}
}
