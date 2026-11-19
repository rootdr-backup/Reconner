package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// TestMonitoringChangesPagination proves the Changes endpoint uses the same
// page/limit envelope as the other list endpoints, so the UI's fetchAllPaged()
// can walk the full history instead of stopping at the newest 500 rows.
func TestMonitoringChangesPagination(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('mc-target','mc.example.com')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := h.db.Exec(`INSERT INTO monitoring_changes
			(id, target_id, url, change_type, old_value, new_value, severity, detected_at)
			VALUES (?, 'mc-target', ?, 'http_change', 'old', ?, 'info', datetime('now', ?))`,
			fmt.Sprintf("mc-%d", i),
			fmt.Sprintf("https://mc.example.com/%d", i),
			fmt.Sprintf("new-%d", i),
			fmt.Sprintf("-%d minutes", i)); err != nil {
			t.Fatal(err)
		}
	}

	type changesPage struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Total int `json:"total"`
		Page  int `json:"page"`
		Limit int `json:"limit"`
	}
	get := func(query string) changesPage {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/targets/mc-target/monitoring-changes"+query, nil)
		req = mux.SetURLVars(req, map[string]string{"id": "mc-target"})
		rec := httptest.NewRecorder()
		h.handleListMonitoringChanges(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var p changesPage
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return p
	}

	first := get("?page=1&limit=2")
	if first.Total != 5 || first.Page != 1 || first.Limit != 2 || len(first.Data) != 2 {
		t.Fatalf("page 1 = %+v", first)
	}
	if first.Data[0].ID != "mc-0" || first.Data[1].ID != "mc-1" {
		t.Fatalf("page 1 order = %q, %q", first.Data[0].ID, first.Data[1].ID)
	}

	second := get("?page=2&limit=2")
	if second.Total != 5 || second.Page != 2 || len(second.Data) != 2 {
		t.Fatalf("page 2 = %+v", second)
	}
	if second.Data[0].ID != "mc-2" || second.Data[1].ID != "mc-3" {
		t.Fatalf("page 2 order = %q, %q", second.Data[0].ID, second.Data[1].ID)
	}

	clamped := get("?page=1&limit=9999")
	if clamped.Limit != 500 || len(clamped.Data) != 5 {
		t.Fatalf("limit clamp = %+v", clamped)
	}

	fallback := get("")
	if fallback.Page != 1 || fallback.Limit != 100 || fallback.Total != 5 || len(fallback.Data) != 5 {
		t.Fatalf("defaults = %+v", fallback)
	}
}

// TestMonitoringChangesPaginationEdges covers the cases that used to corrupt
// the response: an empty target, a page past the end, invalid page/limit
// values, NULL text columns (which used to be dropped silently), and rows that
// share detected_at (id DESC must keep the order stable across pages).
func TestMonitoringChangesPaginationEdges(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets (id, domain) VALUES ('mc-edge','edge.example.com')`); err != nil {
		t.Fatal(err)
	}

	type row struct {
		ID         string `json:"id"`
		OldValue   string `json:"old_value"`
		NewValue   string `json:"new_value"`
		DetectedAt string `json:"detected_at"`
	}
	type changesPage struct {
		Data  []row `json:"data"`
		Total int   `json:"total"`
		Page  int   `json:"page"`
		Limit int   `json:"limit"`
	}
	get := func(query string) changesPage {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/targets/mc-edge/monitoring-changes"+query, nil)
		req = mux.SetURLVars(req, map[string]string{"id": "mc-edge"})
		rec := httptest.NewRecorder()
		h.handleListMonitoringChanges(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var p changesPage
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return p
	}

	empty := get("")
	if empty.Total != 0 || len(empty.Data) != 0 {
		t.Fatalf("empty target = %+v", empty)
	}

	insert := func(id string, detectedAt, oldValue, newValue any) {
		t.Helper()
		if _, err := h.db.Exec(`INSERT INTO monitoring_changes
			(id, target_id, url, change_type, old_value, new_value, severity, detected_at)
			VALUES (?, 'mc-edge', ?, 'http_change', ?, ?, 'info', ?)`,
			id, "https://edge.example.com/"+id, oldValue, newValue, detectedAt); err != nil {
			t.Fatal(err)
		}
	}
	// NULL text columns must not make the row disappear from the response.
	insert("mc-null", nil, nil, nil)
	// Same detected_at: id DESC is the stable tiebreaker.
	insert("mc-aaa", "2026-01-02 00:00:00", "old", "new")
	insert("mc-zzz", "2026-01-02 00:00:00", "old", "new")
	insert("mc-old", "2026-01-01 00:00:00", "old", "new")

	all := get("?limit=10")
	if all.Total != 4 || len(all.Data) != 4 {
		t.Fatalf("all = %+v", all)
	}
	if all.Data[0].ID != "mc-zzz" || all.Data[1].ID != "mc-aaa" {
		t.Fatalf("tie-break order = %q, %q", all.Data[0].ID, all.Data[1].ID)
	}
	var nullRow *row
	for i := range all.Data {
		if all.Data[i].ID == "mc-null" {
			nullRow = &all.Data[i]
		}
	}
	if nullRow == nil {
		t.Fatal("NULL row was dropped from the response")
	}
	if nullRow.OldValue != "" || nullRow.NewValue != "" || nullRow.DetectedAt != "" {
		t.Fatalf("NULL row values = %+v", *nullRow)
	}

	past := get("?page=99&limit=10")
	if past.Total != 4 || len(past.Data) != 0 {
		t.Fatalf("page past end = %+v", past)
	}

	invalid := get("?page=abc&limit=abc")
	if invalid.Page != 1 || invalid.Limit != 100 || invalid.Total != 4 {
		t.Fatalf("invalid params = %+v", invalid)
	}
}
