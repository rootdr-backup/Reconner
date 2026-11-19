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

	changes := diffWatchHTTP(before, after, true, false)
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
	got := diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: title}, true, false)
	if len(got) != 1 || got[0].ChangeType != "page_change" {
		t.Fatalf("title change: got %+v, want one page_change", got)
	}

	tech := base
	tech.Server = "apache"
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: tech}, true, false)
	if len(got) != 1 || got[0].ChangeType != "tech_change" {
		t.Fatalf("server change: got %+v, want one tech_change", got)
	}

	redirect := base
	redirect.RedirectURL = "https://b.example"
	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{base.URL: redirect}, true, false)
	if len(got) != 1 || got[0].ChangeType != "http_change" {
		t.Fatalf("redirect change: got %+v, want one http_change", got)
	}

	got = diffWatchHTTP(map[string]watchHTTPSnapshot{base.URL: base}, map[string]watchHTTPSnapshot{}, true, false)
	if len(got) != 1 || got[0].ChangeType != "http_service_removed" || got[0].Severity != "medium" {
		t.Fatalf("removed url: got %+v, want medium http_service_removed", got)
	}

	got = diffWatchHTTP(map[string]watchHTTPSnapshot{}, map[string]watchHTTPSnapshot{base.URL: base}, true, false)
	if len(got) != 0 {
		t.Fatalf("new url on brand-new host: got %+v, want no rows", got)
	}
}

func TestDiffWatchHTTPNewServiceOnKnownHost(t *testing.T) {
	base := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 200, Title: "OK"}
	newPort := watchHTTPSnapshot{URL: "https://a.example:8443/admin", StatusCode: 200, Title: "Admin"}

	before := map[string]watchHTTPSnapshot{base.URL: base}
	after := map[string]watchHTTPSnapshot{base.URL: base, newPort.URL: newPort}

	got := diffWatchHTTP(before, after, true, false)
	if len(got) != 1 || got[0].ChangeType != "new_http_service" || got[0].Severity != "medium" {
		t.Fatalf("new service on known host: got %+v, want one medium new_http_service", got)
	}
	if got[0].NewValue != newPort.URL || got[0].OldValue != "" {
		t.Fatalf("new service values: got old=%q new=%q", got[0].OldValue, got[0].NewValue)
	}
}

func TestDiffWatchHosts(t *testing.T) {
	before := map[string]bool{"a.example": true, "gone.example": true}
	after := map[string]bool{"a.example": true, "new.example": true}

	got := diffWatchHosts(before, after, false)
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

func TestDiffWatchHTTPCappedKeepsStatusFlip(t *testing.T) {
	old := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 403, Title: "Forbidden"}
	cur := watchHTTPSnapshot{URL: "https://a.example", StatusCode: 200, Title: "OK"}
	evicted := watchHTTPSnapshot{URL: "https://zzz.example", StatusCode: 200, Title: "Old"}

	before := map[string]watchHTTPSnapshot{old.URL: old, evicted.URL: evicted}
	after := map[string]watchHTTPSnapshot{cur.URL: cur}

	got := diffWatchHTTP(before, after, true, true)
	types := map[string]bool{}
	for _, c := range got {
		types[c.ChangeType] = true
		if c.ChangeType == "http_service_removed" {
			t.Fatal("capped snapshot must not report evicted URLs as removals")
		}
	}
	if !types["status_change"] {
		t.Fatalf("types = %v, want status_change from the common window", types)
	}
}

func TestDiffWatchHTTPNewServiceWithoutHostDiff(t *testing.T) {
	svc := watchHTTPSnapshot{URL: "https://brand-new.example", StatusCode: 200, Title: "OK"}
	before := map[string]watchHTTPSnapshot{}
	after := map[string]watchHTTPSnapshot{svc.URL: svc}

	got := diffWatchHTTP(before, after, false, false)
	if len(got) != 1 || got[0].ChangeType != "new_http_service" {
		t.Fatalf("without host diff: got %+v, want one new_http_service", got)
	}

	got = diffWatchHTTP(before, after, true, false)
	if len(got) != 0 {
		t.Fatalf("with host diff: got %+v, want no rows", got)
	}
}

func TestDiffWatchHostsCappedSuppressesRemovals(t *testing.T) {
	before := map[string]bool{"a.example": true, "zzz.example": true}
	after := map[string]bool{"a.example": true, "new.example": true}

	got := diffWatchHosts(before, after, true)
	for _, c := range got {
		if c.ChangeType == "subdomain_removed" {
			t.Fatal("capped host snapshot must not report evicted hosts as removals")
		}
	}
	if len(got) != 1 || got[0].ChangeType != "new_subdomain" {
		t.Fatalf("got %+v, want one new_subdomain", got)
	}
}

func TestPruneOrphanChangeSeen(t *testing.T) {
	s := newTestScheduler(t)
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	stmts := []string{
		`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`,
		`INSERT INTO tasks (id, target_id, type, status, priority, modules, total)
			VALUES ('round-1','t1','watch_scan','finished',1,'[]',2)`,
		`INSERT INTO monitoring_changes (id,target_id,url,change_type,detected_at)
			VALUES ('mc-1','t1','https://a.example','status_change','` + now + `')`,
		`INSERT INTO watch_round_changes
			(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
			VALUES ('wc-1','t1','round-1','https://a.example','status_change','old','new','medium','{}','` + now + `')`,
		`INSERT INTO watch_scope_events (id,target_id,identifier,event_type,detected_at)
			VALUES ('we-1','t1','a.example','landed','` + now + `')`,
		`INSERT INTO notifications (id,target_id,type,title,created_at)
			VALUES ('n-1','t1','scope_landed','Landed','` + now + `')`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	for _, id := range []string{"mc-1", "wc-1", "we-1", "n-1", "dead-1"} {
		if _, err := s.db.Exec(`INSERT INTO change_seen (change_id,user_id,seen_at) VALUES (?,1,?)`, id, now); err != nil {
			t.Fatalf("insert seen %s: %v", id, err)
		}
	}

	s.pruneOrphanChangeSeen()

	var ids []string
	rows, err := s.db.Query(`SELECT change_id FROM change_seen ORDER BY change_id`)
	if err != nil {
		t.Fatalf("query seen: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan seen: %v", err)
		}
		ids = append(ids, id)
	}
	want := []string{"mc-1", "n-1", "wc-1", "we-1"}
	if len(ids) != len(want) {
		t.Fatalf("remaining ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("remaining ids = %v, want %v", ids, want)
		}
	}
}

func TestFinishPhaseCancelsPhaseContext(t *testing.T) {
	s := newTestScheduler(t)
	modCtx, finish := s.beginPhase(context.Background(), "task-phase-cancel", time.Minute)
	if err := modCtx.Err(); err != nil {
		t.Fatalf("phase context already done before finish: %v", err)
	}
	_, _ = finish()
	if err := modCtx.Err(); err == nil {
		t.Fatal("finishPhase must cancel the phase context")
	}
}

func TestShouldWriteWatchDiffGates(t *testing.T) {
	if !shouldWriteWatchDiff(watchScanType, false, false, nil, nil, true) {
		t.Fatal("clean watch phase must write a diff")
	}
	// Reading modCtx.Err() after finishPhase returns context.Canceled. The gate
	// must reject that value so it never silently drops a clean diff.
	if shouldWriteWatchDiff(watchScanType, false, false, nil, context.Canceled, true) {
		t.Fatal("cancelled phase context must not write a diff")
	}
	if shouldWriteWatchDiff("monitor_watch", false, false, nil, nil, true) {
		t.Fatal("monitor_watch must not write a watch diff")
	}
	if shouldWriteWatchDiff(watchScanType, true, false, nil, nil, true) {
		t.Fatal("skipped phase must not write a diff")
	}
	if shouldWriteWatchDiff(watchScanType, false, true, nil, nil, true) {
		t.Fatal("timed-out phase must not write a diff")
	}
	if shouldWriteWatchDiff(watchScanType, false, false, context.Canceled, nil, true) {
		t.Fatal("failed phase must not write a diff")
	}
	if shouldWriteWatchDiff(watchScanType, false, false, nil, nil, false) {
		t.Fatal("missing snapshots must not write a diff")
	}
}
