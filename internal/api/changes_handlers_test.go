package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
)

type changesEnvelope struct {
	Data  []ChangeEntry `json:"data"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
}

type roundsEnvelope struct {
	Data  []WatchRound `json:"data"`
	Total int          `json:"total"`
}

func serveChanges(t *testing.T, h *Handler, sid, path string, vars map[string]string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	h.requireAuth(handler)(rec, req)
	return rec
}

func TestListChangesScopedToOwner(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)

	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc-admin','t-admin','https://a','status_change','403','200','high',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc-bob','t-bob','round-1','https://b','status_change','403 title=Forbidden','200 title=OK','medium','{"old_code":403,"new_code":200}',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity)
		VALUES ('n-global',NULL,'catalog_sync','Catalog synced','ok','info')`)

	rec := serveChanges(t, h, bobSID, "/api/changes", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v; body = %s", err, rec.Body.String())
	}
	ids := map[string]bool{}
	for _, e := range env.Data {
		ids[e.ID] = true
	}
	if ids["mc-admin"] {
		t.Error("member saw another owner's monitoring change")
	}
	if !ids["wc-bob"] {
		t.Error("member did not see own watch change")
	}
	if !ids["n-global"] {
		t.Error("member did not see target-less notice")
	}
	if env.Total != 2 {
		t.Errorf("total = %d, want 2", env.Total)
	}
}

func TestListChangesNotificationMetadataRoundTrip(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,metadata,created_at)
		VALUES ('n-new-hosts','t1','new_subdomain','New host','2 new subdomain(s) found on one.example','medium',
		'{"hosts":["a.example","b.example"],"truncated":false,"total":2}','2026-03-01 00:00:00')`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	rec := serveChanges(t, h, sid, "/api/changes?source=notification&target_id=t1", nil, h.handleListChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 {
		t.Fatalf("rows = %d, want 1", len(env.Data))
	}
	row := env.Data[0]
	hosts, ok := row.Metadata["hosts"].([]any)
	if !ok || len(hosts) != 2 {
		t.Fatalf("metadata hosts = %v, want two entries", row.Metadata["hosts"])
	}
	if hosts[0] != "a.example" || hosts[1] != "b.example" {
		t.Fatalf("hosts = %v, want [a.example b.example]", hosts)
	}
	if row.Metadata["total"] != float64(2) {
		t.Fatalf("total = %v, want 2", row.Metadata["total"])
	}
}

func TestListTargetChangesForcesRoutedTarget(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t2','two.example',?)`, adminID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t1','https://1','status_change','a','b','low',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc2','t2','https://2','status_change','a','b','low',CURRENT_TIMESTAMP)`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/targets/t1/changes?target_id=t2", map[string]string{"id": "t1"}, h.handleListTargetChanges)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "mc1" {
		t.Fatalf("rows = %+v, want only mc1", env.Data)
	}
}

func TestListWatchRoundsChangeCount(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO tasks (id,target_id,type,status,priority,modules,total)
		VALUES ('round-1','t1','watch_scan','finished',1,'[]',2)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc1','t1','round-1','https://1','status_change','a','b','low','{}',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc2','t1','round-1','https://2','page_change','a','b','low','{}',CURRENT_TIMESTAMP)`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/watch/rounds", nil, h.handleListWatchRounds)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env roundsEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "round-1" || env.Data[0].ChangeCount != 2 {
		t.Fatalf("rounds = %+v, want round-1 with 2 changes", env.Data)
	}
}

func TestListChangesFiltersAndPagination(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t1','https://1','status_change','a','b','high','2026-01-01 00:00:00')`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc1','t1','round-1','https://2','js_change','a','b','medium','{}','2026-02-01 00:00:00')`)
	h.db.Exec(`INSERT INTO notifications (id,target_id,type,title,body,severity,created_at)
		VALUES ('n1','t1','watch_failed','Round failed','oops','high','2026-03-01 00:00:00')`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		want []string
	}{
		{"category http", "/api/changes?category=http", []string{"mc1"}},
		{"category scripts", "/api/changes?category=scripts", []string{"wc1"}},
		{"category alerts", "/api/changes?category=alerts", []string{"n1"}},
		{"severity high", "/api/changes?severity=high", []string{"mc1", "n1"}},
		{"source monitor", "/api/changes?source=monitor", []string{"mc1"}},
		{"source watch", "/api/changes?source=watch", []string{"wc1"}},
		{"source notification", "/api/changes?source=notification", []string{"n1"}},
		{"task id", "/api/changes?task_id=round-1", []string{"wc1"}},
		{"since", "/api/changes?since=2026-03-01", []string{"n1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveChanges(t, h, sid, tc.path, nil, h.handleListChanges)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var env changesEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatal(err)
			}
			if len(env.Data) != len(tc.want) {
				t.Fatalf("ids = %+v, want %v", idsOf(env.Data), tc.want)
			}
			got := idsOf(env.Data)
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %q in %v", w, got)
				}
			}
		})
	}

	// Pagination: page 2 must skip the first row and the total must stay 3.
	rec := serveChanges(t, h, sid, "/api/changes?page=2&limit=1", nil, h.handleListChanges)
	var env changesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Total != 3 || len(env.Data) != 1 {
		t.Fatalf("page 2: total = %d, rows = %d, want 3 and 1", env.Total, len(env.Data))
	}
	if env.Data[0].ID == "mc1" {
		t.Error("page 2 repeated the first row")
	}
}

func idsOf(rows []ChangeEntry) map[string]bool {
	ids := make(map[string]bool, len(rows))
	for _, row := range rows {
		ids[row.ID] = true
	}
	return ids
}

func TestListWatchRoundsIncludesOrphanedChanges(t *testing.T) {
	h, adminID := newIsoHandler(t)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t1','one.example',?)`, adminID)
	// No tasks row. The task was pruned at 90 days but the change survives.
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc1','t1','old-round','https://1','status_change','a','b','low','{}','2026-01-01 00:00:00')`)
	h.db.Exec(`INSERT INTO watch_round_changes (id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES ('wc2','t1','old-round','https://2','page_change','a','b','low','{}','2026-01-02 00:00:00')`)
	sid, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}

	rec := serveChanges(t, h, sid, "/api/watch/rounds", nil, h.handleListWatchRounds)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env roundsEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data) != 1 || env.Data[0].ID != "old-round" || env.Data[0].ChangeCount != 2 {
		t.Fatalf("rounds = %+v, want one synthesized old-round with 2 changes", env.Data)
	}
	if env.Data[0].StartedAt != "2026-01-01 00:00:00" {
		t.Errorf("started_at = %q, want the earliest change time", env.Data[0].StartedAt)
	}
}

func postChanges(t *testing.T, h *Handler, sid, path string, body any, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	req.AddCookie(&http.Cookie{Name: "recon_session", Value: sid})
	rec := httptest.NewRecorder()
	h.requireAuth(handler)(rec, req)
	return rec
}

func TestChangesSeenIsPerUserAndHonoursFilters(t *testing.T) {
	h, adminID := newIsoHandler(t)
	bob, err := h.auth.CreateUser("bob", "bobpassword", auth.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bobSID, err := h.auth.Login("bob", "bobpassword")
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := h.auth.Login("admin", config.DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-admin','admin.example',?)`, adminID)
	h.db.Exec(`INSERT INTO targets (id, domain, owner_id) VALUES ('t-bob','bob.example',?)`, bob.ID)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc1','t-admin','https://a','status_change','403','200','high',CURRENT_TIMESTAMP)`)
	h.db.Exec(`INSERT INTO monitoring_changes (id,target_id,url,change_type,old_value,new_value,severity,detected_at)
		VALUES ('mc2','t-bob','https://b','status_change','403','200','high',CURRENT_TIMESTAMP)`)

	// Each user marks only their own change.
	rec := postChanges(t, h, adminSID, "/api/changes/seen", map[string]any{"ids": []string{"mc1"}, "seen": true}, h.handleSetChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin seen status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = postChanges(t, h, bobSID, "/api/changes/seen", map[string]any{"ids": []string{"mc2"}, "seen": true}, h.handleSetChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob seen status = %d, body = %s", rec.Code, rec.Body.String())
	}

	readSeen := func(sid, path string) map[string]bool {
		t.Helper()
		rec := serveChanges(t, h, sid, path, nil, h.handleListChanges)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var env changesEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, e := range env.Data {
			out[e.ID] = e.Seen
		}
		return out
	}

	adminSeen := readSeen(adminSID, "/api/changes")
	if !adminSeen["mc1"] || adminSeen["mc2"] {
		t.Errorf("admin seen = %v, want mc1 read and mc2 unread", adminSeen)
	}
	bobSeen := readSeen(bobSID, "/api/changes")
	if len(bobSeen) != 1 || !bobSeen["mc2"] {
		t.Errorf("bob seen = %v, want only mc2 read", bobSeen)
	}

	// Owner scope, read-state join, and three filters in one query.
	bobFiltered := readSeen(bobSID, "/api/changes?category=http&severity=high&target_id=t-bob")
	if len(bobFiltered) != 1 || !bobFiltered["mc2"] {
		t.Errorf("bob filtered seen = %v, want only mc2 read", bobFiltered)
	}

	// Mark-all honours the target filter: only t-admin rows change.
	rec = postChanges(t, h, adminSID, "/api/changes/seen-all?target_id=t-admin", map[string]any{}, h.handleMarkAllChangesSeen)
	if rec.Code != http.StatusOK {
		t.Fatalf("seen-all status = %d, body = %s", rec.Code, rec.Body.String())
	}
	adminSeen = readSeen(adminSID, "/api/changes")
	if !adminSeen["mc1"] || adminSeen["mc2"] {
		t.Errorf("after filtered mark-all, admin seen = %v, want mc1 read and mc2 unread", adminSeen)
	}
}

func TestParseChangesSince(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"2026-11-18":           "2026-11-18 00:00:00",
		"2026-11-18 10:20:30":  "2026-11-18 10:20:30",
		"2026-11-18T10:20:30Z": "2026-11-18 10:20:30",
	}
	for in, want := range cases {
		if got := parseChangesSince(in); got != want {
			t.Errorf("parseChangesSince(%q) = %q, want %q", in, got, want)
		}
	}
}
