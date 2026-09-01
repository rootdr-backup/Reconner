package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	ws "github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

func TestHealthRouteIsPublicAndDockerCompatible(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AdminUsername: "health-test-admin",
		AdminPassword: "health-test-password",
		SessionSecret: "health-test-session-secret",
	}
	router := NewRouter(db, ws.NewHub(), nil, cfg, logger.New("error"))
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/health status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health body=%v, want status=ok", body)
	}
}
