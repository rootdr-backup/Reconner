package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/websocket"
)

// TestTargetCatchallOverrideRoundTrip proves the per-target tri-state override
// end to end through the real handlers: GET exposes override + effective state,
// PUT persists 0/1/NULL, invalid values are rejected, and "inherit" tracks the
// global config without touching the column.
func TestTargetCatchallOverrideRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	h.hub = websocket.NewHub()
	h.cfg = &config.Config{HTTPCatchallDetection: true}

	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('ct-target','catchall.example.com')`); err != nil {
		t.Fatal(err)
	}

	getTarget := func() map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/targets/ct-target", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ct-target"})
		rec := httptest.NewRecorder()
		h.handleGetTarget(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET target status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode GET response: %v", err)
		}
		return resp.Data
	}
	putTarget := func(body string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/targets/ct-target", bytes.NewBufferString(body))
		req = mux.SetURLVars(req, map[string]string{"id": "ct-target"})
		rec := httptest.NewRecorder()
		h.handleUpdateTarget(rec, req)
		return rec.Code
	}

	// A new target inherits the global (on).
	data := getTarget()
	if data["catchall_detection"] != "inherit" {
		t.Fatalf("default override = %v, want inherit", data["catchall_detection"])
	}
	if data["catchall_effective"] != true {
		t.Fatalf("inherit with global on effective = %v, want true", data["catchall_effective"])
	}

	// Force off: the override wins over the global.
	if code := putTarget(`{"catchall_detection":"off"}`); code != http.StatusOK {
		t.Fatalf("PUT off status = %d", code)
	}
	data = getTarget()
	if data["catchall_detection"] != "off" || data["catchall_effective"] != false {
		t.Fatalf("after off: %v/%v, want off/false", data["catchall_detection"], data["catchall_effective"])
	}

	// Force on.
	if code := putTarget(`{"catchall_detection":"on"}`); code != http.StatusOK {
		t.Fatalf("PUT on status = %d", code)
	}
	data = getTarget()
	if data["catchall_detection"] != "on" || data["catchall_effective"] != true {
		t.Fatalf("after on: %v/%v, want on/true", data["catchall_detection"], data["catchall_effective"])
	}

	// Clear back to inherit: the column must be NULL again.
	if code := putTarget(`{"catchall_detection":"inherit"}`); code != http.StatusOK {
		t.Fatalf("PUT inherit status = %d", code)
	}
	var stored *int
	if err := h.db.QueryRow(`SELECT catchall_detection FROM targets WHERE id='ct-target'`).Scan(&stored); err != nil {
		t.Fatalf("read catchall_detection column: %v", err)
	}
	if stored != nil {
		t.Fatalf("inherit must store NULL, got %d", *stored)
	}
	data = getTarget()
	if data["catchall_detection"] != "inherit" || data["catchall_effective"] != true {
		t.Fatalf("after inherit: %v/%v, want inherit/true", data["catchall_detection"], data["catchall_effective"])
	}

	// Invalid values are rejected before any write.
	if code := putTarget(`{"catchall_detection":"maybe"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid override status = %d, want 400", code)
	}

	// Flipping the global config changes "inherit" effectiveness without a write.
	h.cfg.HTTPCatchallDetection = false
	data = getTarget()
	if data["catchall_effective"] != false {
		t.Fatalf("inherit with global off effective = %v, want false", data["catchall_effective"])
	}
}
