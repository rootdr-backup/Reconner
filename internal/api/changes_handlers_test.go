package api

import (
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

func TestParseChangesSince(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"2026-11-18":          "2026-11-18 00:00:00",
		"2026-11-18 10:20:30": "2026-11-18 10:20:30",
		"2026-11-18T10:20:30Z": "2026-11-18 10:20:30",
	}
	for in, want := range cases {
		if got := parseChangesSince(in); got != want {
			t.Errorf("parseChangesSince(%q) = %q, want %q", in, got, want)
		}
	}
}
