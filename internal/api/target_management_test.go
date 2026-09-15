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

func TestDeleteTargetRemovesNonFKLifecycleRows(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES('delete-lifecycle','delete-lifecycle.example',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO candidates(id,target_id,type,fingerprint) VALUES('candidate','delete-lifecycle','xss','fingerprint')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO candidate_transitions(id,candidate_id,target_id,to_state) VALUES('transition','candidate','delete-lifecycle','REJECTED')`); err != nil {
		t.Fatal(err)
	}
	for table, insert := range map[string]string{
		"evidence":          `INSERT INTO evidence(id,finding_id,target_id,kind) VALUES('evidence','finding','delete-lifecycle','http')`,
		"http_interactions": `INSERT INTO http_interactions(id,target_id) VALUES('interaction','delete-lifecycle')`,
		"objects":           `INSERT INTO objects(id,target_id,identifier) VALUES('object','delete-lifecycle','42')`,
	} {
		if _, err := h.db.Exec(insert); err != nil {
			t.Fatalf("insert %s: %v", table, err)
		}
	}

	if err := h.deleteTargetByID("delete-lifecycle"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"evidence", "http_interactions", "objects", "candidate_transitions"} {
		var count int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE target_id='delete-lifecycle'`).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("target deletion left %d row(s) in %s", count, table)
		}
	}
}

func TestWebAPIMutationsRejectUnsupportedNetworkScopesAtomically(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.hub = websocket.NewHub()

	for _, body := range []string{
		`{"domain":"192.0.2.0/24","name":"cidr"}`,
		`{"domain":"example.org,192.0.2.1","name":"mixed"}`,
		`{"domain":"example.org","kind":"network","name":"masquerade"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/targets", bytes.NewBufferString(body))
		req = req.WithContext(context.WithValue(req.Context(), ctxUserIDKey, adminID))
		rec := httptest.NewRecorder()
		h.handleCreateTarget(rec, req)
		if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("network/CIDR")) {
			t.Errorf("network create status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	var count int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&count)
	if count != 0 {
		t.Fatalf("rejected creates persisted %d target(s)", count)
	}

	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,name,kind,owner_id) VALUES('web-target','example.org','original','web',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO assets(id,target_id,value,kind,asset_type) VALUES('web-asset','web-target','example.org','web','domain')`); err != nil {
		t.Fatal(err)
	}
	updateReq := httptest.NewRequest(http.MethodPut, "/api/targets/web-target", bytes.NewBufferString(`{"name":"must-not-commit","domain":"198.51.100.0/24"}`))
	updateReq = mux.SetURLVars(updateReq, map[string]string{"id": "web-target"})
	updateRec := httptest.NewRecorder()
	h.handleUpdateTarget(updateRec, updateReq)
	if updateRec.Code != http.StatusBadRequest {
		t.Fatalf("network update status=%d body=%s", updateRec.Code, updateRec.Body.String())
	}
	var domain, name string
	_ = h.db.QueryRow(`SELECT domain,name FROM targets WHERE id='web-target'`).Scan(&domain, &name)
	if domain != "example.org" || name != "original" {
		t.Fatalf("rejected target update was partial: domain=%q name=%q", domain, name)
	}

	assetReq := httptest.NewRequest(http.MethodPatch, "/api/targets/web-target/assets/web-asset", bytes.NewBufferString(`{"name":"must-not-commit","value":"203.0.113.10"}`))
	assetReq = mux.SetURLVars(assetReq, map[string]string{"id": "web-target", "aid": "web-asset"})
	assetRec := httptest.NewRecorder()
	h.handleUpdateAsset(assetRec, assetReq)
	if assetRec.Code != http.StatusBadRequest {
		t.Fatalf("network asset update status=%d body=%s", assetRec.Code, assetRec.Body.String())
	}
	var assetValue, assetName string
	_ = h.db.QueryRow(`SELECT value,COALESCE(name,'') FROM assets WHERE id='web-asset'`).Scan(&assetValue, &assetName)
	if assetValue != "example.org" || assetName != "" {
		t.Fatalf("rejected asset update was partial: value=%q name=%q", assetValue, assetName)
	}
}
