package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSPAServesRootPublicFilesAndFallsBackForRoutes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>reconner-shell</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "favicon.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{}

	faviconReq := httptest.NewRequest(http.MethodGet, "/favicon.svg", nil)
	faviconRec := httptest.NewRecorder()
	h.serveSPA(dir).ServeHTTP(faviconRec, faviconReq)
	if faviconRec.Code != http.StatusOK || !strings.Contains(faviconRec.Body.String(), "<svg") {
		t.Fatalf("favicon response status=%d body=%q", faviconRec.Code, faviconRec.Body.String())
	}
	if got := faviconRec.Header().Get("Content-Type"); !strings.Contains(got, "image/svg+xml") {
		t.Fatalf("favicon content type=%q", got)
	}

	routeReq := httptest.NewRequest(http.MethodGet, "/targets/example", nil)
	routeRec := httptest.NewRecorder()
	h.serveSPA(dir).ServeHTTP(routeRec, routeReq)
	if routeRec.Code != http.StatusOK || !strings.Contains(routeRec.Body.String(), "reconner-shell") {
		t.Fatalf("SPA fallback status=%d body=%q", routeRec.Code, routeRec.Body.String())
	}
	if got := routeRec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("SPA content type=%q", got)
	}
}

func TestSPAFallbackDoesNotServeFilesOutsideDist(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "dist")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("safe-shell"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("must-not-leak"), 0o600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/../secret.txt", nil)
	rec := httptest.NewRecorder()
	(&Handler{}).serveSPA(dir).ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "must-not-leak") {
		t.Fatalf("path traversal escaped dist: status=%d body=%q", rec.Code, rec.Body.String())
	}
}
