package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/models"
)

// TestHandleListAssetsReturnsRowsWithTextTimestamps guards the COALESCE
// timestamp scan bug. COALESCE(updated_at,created_at) has no declared column
// type, so the SQLite driver returns a string. Scanning it straight into
// time.Time failed silently and dropped every row, yielding data:[].
func TestHandleListAssetsReturnsRowsWithTextTimestamps(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('tgt-assets','example.com')`); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		id, value, created, updated string
	}{
		{"a-text", "https://one.example.com", "2026-11-17 17:23:34", "2026-11-18 10:00:00"},
		{"a-null", "https://two.example.com", "2026-11-17 17:23:34", ""},
	}
	for _, row := range rows {
		var updated any
		if row.updated != "" {
			updated = row.updated
		}
		if _, err := h.db.Exec(`INSERT INTO assets
			(id, target_id, name, value, kind, asset_type, source, approval_status, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			row.id, "tgt-assets", row.value, row.value, "web", "url", "bounty:test", "approved",
			row.created, updated); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/targets/tgt-assets/assets", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "tgt-assets"})
	rec := httptest.NewRecorder()
	h.handleListAssets(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var env struct {
		Success bool           `json:"success"`
		Data    []models.Asset `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 2 {
		t.Fatalf("got %d assets, want 2; body=%s", len(env.Data), rec.Body.String())
	}
	for _, a := range env.Data {
		if a.CreatedAt.IsZero() {
			t.Errorf("asset %s has zero created_at", a.ID)
		}
		if a.ID == "a-text" && a.UpdatedAt.IsZero() {
			t.Errorf("asset %s has zero updated_at", a.ID)
		}
	}
}
