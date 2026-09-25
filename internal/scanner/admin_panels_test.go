package scanner

import "testing"

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
	if _, ok := classifyAdminPanel("https://app.test/admin", 302, "", nil, "/auth/login"); !ok {
		t.Fatal("admin path redirecting to authentication was missed")
	}
	if _, ok := classifyAdminPanel("https://app.test/management", 403, "", nil, ""); !ok {
		t.Fatal("restricted management endpoint must be retained")
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
