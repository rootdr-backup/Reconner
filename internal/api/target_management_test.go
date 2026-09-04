package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/websocket"
)

func TestTargetSearchIncludesFriendlyNameAndTags(t *testing.T) {
	h, adminID := newIsoHandler(t)
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,name,tags,owner_id) VALUES
		('named-target','example.com','Payments Production','["quarterly-review"]',?),
		('other-target','other.example','Other Project','[]',?)`, adminID, adminID)

	search := func(value string) []map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/targets?search="+value, nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
		rec := httptest.NewRecorder()
		h.handleListTargets(rec, req)
		var response struct {
			Data []map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	if got := search("Payments"); len(got) != 1 || got[0]["id"] != "named-target" {
		t.Fatalf("friendly-name search returned %#v", got)
	}
	if got := search("quarterly-review"); len(got) != 1 || got[0]["id"] != "named-target" {
		t.Fatalf("tag search returned %#v", got)
	}
}

func TestEnablingMonitorClearsOldRunTime(t *testing.T) {
	h, _ := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,monitor_enabled,monitor_interval_hours,monitor_last_run)
		VALUES('monitor-target','example.com',0,24,CURRENT_TIMESTAMP)`)

	req := httptest.NewRequest(http.MethodPatch, "/api/targets/monitor-target/monitor", bytes.NewBufferString(`{"monitor_enabled":true,"monitor_interval_hours":6}`))
	req = mux.SetURLVars(req, map[string]string{"id": "monitor-target"})
	rec := httptest.NewRecorder()
	h.handleUpdateMonitor(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("monitor update status=%d body=%s", rec.Code, rec.Body.String())
	}
	var enabled, hours int
	var lastRun sql.NullTime
	if err := h.db.QueryRow(`SELECT monitor_enabled,monitor_interval_hours,monitor_last_run FROM targets WHERE id='monitor-target'`).Scan(&enabled, &hours, &lastRun); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 || hours != 6 || lastRun.Valid {
		t.Fatalf("re-enabled monitor state enabled=%d hours=%d last=%v; want 1/6/NULL", enabled, hours, lastRun)
	}
}

func TestDeleteReportsMissingTargetsAccurately(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	_, _ = h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES('delete-me','delete.example',?)`, adminID)

	body, _ := json.Marshal(map[string]any{"ids": []string{"delete-me", "missing-target"}})
	req := httptest.NewRequest(http.MethodPost, "/api/targets/bulk-delete", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
	rec := httptest.NewRecorder()
	h.handleBulkDeleteTarget(rec, req)
	var response struct {
		Data struct {
			Deleted int `json:"deleted"`
			Failed  int `json:"failed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Deleted != 1 || response.Data.Failed != 1 {
		t.Fatalf("bulk delete counts=%+v, want deleted=1 failed=1", response.Data)
	}

	missingReq := httptest.NewRequest(http.MethodDelete, "/api/targets/missing-target", nil)
	missingReq = mux.SetURLVars(missingReq, map[string]string{"id": "missing-target"})
	missingRec := httptest.NewRecorder()
	h.handleDeleteTarget(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("missing delete status=%d body=%s", missingRec.Code, missingRec.Body.String())
	}
}
