package scheduler

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestDiffWatchHTTPStatusAndTitleChange(t *testing.T) {
	before := map[string]watchHTTPSnapshot{
		"https://a.example": {URL: "https://a.example", StatusCode: 403, Title: "Forbidden"},
	}
	after := map[string]watchHTTPSnapshot{
		"https://a.example": {URL: "https://a.example", StatusCode: 200, Title: "OK"},
	}

	changes := diffWatchHTTP(before, after)
	if len(changes) != 2 {
		t.Fatalf("got %d changes, want status_change + page_change", len(changes))
	}

	var status *watchChange
	for i := range changes {
		if changes[i].ChangeType == "status_change" {
			status = &changes[i]
		}
	}
	if status == nil {
		t.Fatal("status_change not produced")
	}
	if status.Severity != "medium" {
		t.Errorf("severity = %q, want medium", status.Severity)
	}
	if want := "status=403 title=Forbidden"; status.OldValue != want {
		t.Errorf("old_value = %q, want %q", status.OldValue, want)
	}
	if want := "status=200 title=OK"; status.NewValue != want {
		t.Errorf("new_value = %q, want %q", status.NewValue, want)
	}
	var meta struct {
		OldCode int `json:"old_code"`
		NewCode int `json:"new_code"`
	}
	if err := json.Unmarshal([]byte(status.Metadata), &meta); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if meta.OldCode != 403 || meta.NewCode != 200 {
		t.Errorf("metadata codes = %d/%d, want 403/200", meta.OldCode, meta.NewCode)
	}
}

func TestDiffWatchHTTPOtherChanges(t *testing.T) {
	base := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 200, Title: "OK", Server: "nginx", Technologies: "react, jquery"}

	title := base
	title.Title = "Welcome"
	got := diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: title})
	if len(got) != 1 || got[0].ChangeType != "page_change" {
		t.Fatalf("title change: got %+v, want one page_change", got)
	}

	tech := base
	tech.Server = "apache"
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: tech})
	if len(got) != 1 || got[0].ChangeType != "tech_change" {
		t.Fatalf("server change: got %+v, want one tech_change", got)
	}

	redirect := base
	redirect.RedirectURL = "https://b.example"
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: redirect})
	if len(got) != 1 || got[0].ChangeType != "http_change" {
		t.Fatalf("redirect change: got %+v, want one http_change", got)
	}

	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{})
	if len(got) != 1 || got[0].ChangeType != "subdomain_removed" || got[0].Severity != "medium" {
		t.Fatalf("removed url: got %+v, want medium subdomain_removed", got)
	}

	got = diffWatchHTTP(map[string]watchHTTPSnapshot{}, map[string]watchHTTPSnapshot{base.URL: base})
	if len(got) != 0 {
		t.Fatalf("new url: got %+v, want no rows", got)
	}
}

func TestDiffWatchHosts(t *testing.T) {
	before := map[string]bool{"a.example": true, "gone.example": true}
	after := map[string]bool{"a.example": true, "new.example": true}

	got := diffWatchHosts(before, after)
	if len(got) != 2 {
		t.Fatalf("got %d changes, want 2", len(got))
	}
	types := map[string]bool{}
	for _, c := range got {
		types[c.ChangeType] = true
		if c.Severity != "medium" {
			t.Errorf("%s severity = %q, want medium", c.ChangeType, c.Severity)
		}
	}
	if !types["new_subdomain"] || !types["subdomain_removed"] {
		t.Fatalf("types = %v, want new_subdomain and subdomain_removed", types)
	}
}

func TestSnapshotsFromDatabase(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code, title, server, technologies)
		VALUES ('h1','t1','https://a.example',403,'Forbidden','nginx','["react","jquery"]')`); err != nil {
		t.Fatalf("insert http service: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, is_alive)
		VALUES ('s1','t1','a.example',1)`); err != nil {
		t.Fatalf("insert subdomain: %v", err)
	}

	httpSnap, err := snapshotWatchHTTP(ctx, s.db, "t1")
	if err != nil {
		t.Fatalf("snapshotWatchHTTP: %v", err)
	}
	got, ok := httpSnap["https://a.example"]
	if !ok || got.StatusCode != 403 || got.Title != "Forbidden" || got.Server != "nginx" || got.Technologies != "react, jquery" {
		t.Fatalf("http snapshot = %+v", got)
	}

	hosts, err := snapshotWatchHosts(ctx, s.db, "t1")
	if err != nil {
		t.Fatalf("snapshotWatchHosts: %v", err)
	}
	if hosts["a.example"] != true {
		t.Fatalf("host snapshot = %v, want a.example alive", hosts)
	}
}

func TestInsertWatchRoundChangesSurvivesTaskDeletion(t *testing.T) {
	s := newTestScheduler(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status, priority, modules, total)
		VALUES ('round-1','t1','watch_scan','finished',1,'[]',2)`); err != nil {
		t.Fatalf("insert task: %v", err)
	}

	changes := []watchChange{{
		URL: "https://a.example", ChangeType: "status_change",
		OldValue: "status=403 title=Forbidden", NewValue: "status=200 title=OK",
		Severity: "medium", Metadata: `{"old_code":403,"new_code":200}`,
	}}
	s.insertWatchRoundChanges(ctx, "round-1", "t1", changes)

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE task_id='round-1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after insert count = %d, err = %v", count, err)
	}

	if _, err := s.db.Exec(`DELETE FROM tasks WHERE id='round-1'`); err != nil {
		t.Fatalf("delete task: %v", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM watch_round_changes WHERE task_id='round-1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after task delete count = %d, err = %v, want 1 (no FK cascade)", count, err)
	}
}

func TestPruneWatchChangeRowsUsesGlobalWindow(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchChangesRetentionDays = 1
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	insert := func(id, detected string) {
		if _, err := s.db.Exec(`INSERT INTO watch_round_changes
			(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
			VALUES (?,?,?,?,?,?,?,?,?,?)`, id, "t1", "round-1", "https://a.example",
			"status_change", "old", "new", "medium", "{}", detected); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	insert("old", time.Now().AddDate(0, 0, -10).UTC().Format("2006-01-02 15:04:05"))
	insert("new", time.Now().UTC().Format("2006-01-02 15:04:05"))

	s.pruneWatchChangeRows()

	var ids []string
	rows, err := s.db.Query(`SELECT id FROM watch_round_changes ORDER BY id`)
	if err != nil {
		t.Fatalf("query rows: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		ids = append(ids, id)
	}
	if len(ids) != 1 || ids[0] != "new" {
		t.Fatalf("remaining ids = %v, want [new]", ids)
	}
}
