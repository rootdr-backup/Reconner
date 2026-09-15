package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	ws "github.com/recon-platform/internal/websocket"
)

func TestCredentialedCORSRejectsForeignOrigin(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.hub = ws.NewHub()
	router := h.Router()
	req := httptest.NewRequest(http.MethodPost, "http://reconner.test/api/auth/login",
		bytes.NewBufferString(`{"username":"admin","password":"irrelevant"}`))
	req.Host = "reconner.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign credentialed origin status=%d body=%q, want 403", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("foreign origin was reflected: %q", got)
	}
}

func TestCredentialedCORSPreservesSameOriginAndNonBrowserClients(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.hub = ws.NewHub()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := h.corsMiddleware(next)

	for _, tc := range []struct {
		name       string
		origin     string
		wantOrigin string
	}{
		{name: "same origin", origin: "https://reconner.test", wantOrigin: "https://reconner.test"},
		{name: "non-browser client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "https://reconner.test/api/system/settings", nil)
			req.Host = "reconner.test"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantOrigin {
				t.Fatalf("allow origin=%q want %q", got, tc.wantOrigin)
			}
			if tc.origin != "" && !stringsContainToken(rec.Header().Values("Vary"), "Origin") {
				t.Fatal("same-origin credentialed response must vary on Origin")
			}
		})
	}
}

func stringsContainToken(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
