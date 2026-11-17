package bounty

import (
	"context"
	"strings"
	"testing"
)

func TestBulkCreateBreadthProjects(t *testing.T) {
	svc, db := testCatalog(t)
	ctx := context.Background()

	p1 := Program{
		Provider: "hackerone", ExternalID: "bulk-1", Handle: "bulk-one", Name: "Bulk One",
		Status: "live", ProgramType: "bug_bounty",
		Assets: []Asset{
			{ExternalID: "a1", Identifier: "*.one.test", AssetType: "WILDCARD", InScope: true, EligibleSubmission: true, Active: true},
			{ExternalID: "a2", Identifier: "app.one.test", AssetType: "DOMAIN", InScope: true, EligibleSubmission: true, Active: true},
			{ExternalID: "a3", Identifier: "10.0.0.0/24", AssetType: "CIDR", InScope: true, EligibleSubmission: true, Active: true},
			{ExternalID: "a4", Identifier: "com.example.app", AssetType: "ANDROID", InScope: true, EligibleSubmission: true, Active: true},
			{ExternalID: "a5", Identifier: "old.one.test", AssetType: "DOMAIN", InScope: false, EligibleSubmission: false, Active: true},
		},
	}
	p2 := Program{
		Provider: "bugcrowd", ExternalID: "bulk-2", Handle: "bulk-two", Name: "Bulk Two",
		Status: "live", ProgramType: "bug_bounty",
		Assets: []Asset{
			{ExternalID: "b1", Identifier: "www.two.test", AssetType: "DOMAIN", InScope: true, EligibleSubmission: true, Active: true},
		},
	}
	storeTestProgram(t, svc, &p1)
	storeTestProgram(t, svc, &p2)

	results, err := svc.CreateProjectsBulk(ctx, 7, BulkCreateProjectsRequest{
		ProgramIDs:   []string{p1.ID, p2.ID},
		Coverage:     "breadth",
		AssetPolicy:  "all_eligible_web",
		Priority:     "high",
		SkipExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for i, res := range results {
		if !res.OK {
			t.Fatalf("result %d failed: %+v", i, res)
		}
		if res.TargetID == "" {
			t.Fatalf("result %d has no target id", i)
		}
		if res.Assets == 0 {
			t.Fatalf("result %d imported no assets", i)
		}
	}
	if results[0].Assets != 2 || results[0].SkippedNetwork != 1 {
		t.Fatalf("first result assets=%d skipped_network=%d, want 2/1", results[0].Assets, results[0].SkippedNetwork)
	}
	if results[1].Assets != 1 || results[1].SkippedNetwork != 0 {
		t.Fatalf("second result assets=%d skipped_network=%d, want 1/0", results[1].Assets, results[1].SkippedNetwork)
	}

	for _, res := range results {
		var watchOnly, monitor, scheduled int
		if err := db.QueryRow(`SELECT watch_only,monitor_enabled,CASE WHEN watch_next_run IS NULL THEN 0 ELSE 1 END FROM targets WHERE id=?`, res.TargetID).Scan(&watchOnly, &monitor, &scheduled); err != nil {
			t.Fatal(err)
		}
		if watchOnly != 1 || monitor != 0 || scheduled != 1 {
			t.Fatalf("target %s: watch_only=%d monitor=%d scheduled=%d, want 1/0/1", res.TargetID, watchOnly, monitor, scheduled)
		}
		var assets, enabled int
		if err := db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(monitor_enabled),0) FROM assets WHERE target_id=? AND approval_status='approved'`, res.TargetID).Scan(&assets, &enabled); err != nil {
			t.Fatal(err)
		}
		if assets != res.Assets || enabled != 0 {
			t.Fatalf("target %s: assets=%d enabled=%d, want %d/0", res.TargetID, assets, enabled, res.Assets)
		}
	}

	again, err := svc.CreateProjectsBulk(ctx, 7, BulkCreateProjectsRequest{
		ProgramIDs: []string{p1.ID, p2.ID}, Coverage: "breadth", SkipExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, res := range again {
		if res.OK || res.Reason != "already_linked" {
			t.Fatalf("repeat result %d = %+v, want already_linked", i, res)
		}
	}
	var targets int
	if err := db.QueryRow(`SELECT COUNT(*) FROM targets`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if targets != 2 {
		t.Fatalf("repeat import created %d targets, want 2", targets)
	}
}

func TestBulkCreateDeepProjects(t *testing.T) {
	svc, db := testCatalog(t)
	p := Program{
		Provider: "intigriti", ExternalID: "bulk-deep", Handle: "deep-one", Name: "Deep One",
		Status: "live", ProgramType: "bug_bounty",
		Assets: []Asset{
			{ExternalID: "d1", Identifier: "app.deep.test", AssetType: "DOMAIN", InScope: true, EligibleSubmission: true, Active: true},
			{ExternalID: "d2", Identifier: "10.1.0.0/24", AssetType: "CIDR", InScope: true, EligibleSubmission: true, Active: true},
			{ExternalID: "d3", Identifier: "com.example.app", AssetType: "ANDROID", InScope: true, EligibleSubmission: true, Active: true},
		},
	}
	storeTestProgram(t, svc, &p)

	results, err := svc.CreateProjectsBulk(context.Background(), 9, BulkCreateProjectsRequest{
		ProgramIDs:           []string{p.ID},
		Coverage:             "deep",
		AssetPolicy:          "all_eligible",
		Priority:             "critical",
		MonitorEnabled:       true,
		MonitorIntervalHours: 6,
		NameTemplate:         "{provider}/{handle}",
		SkipExisting:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("unexpected results: %+v", results)
	}
	res := results[0]
	if res.Assets != 2 || res.SkippedNetwork != 0 {
		t.Fatalf("assets=%d skipped_network=%d, want 2/0", res.Assets, res.SkippedNetwork)
	}
	var watchOnly, monitor, hours int
	var name, priority, kind string
	if err := db.QueryRow(`SELECT watch_only,monitor_enabled,monitor_interval_hours,name,priority,kind FROM targets WHERE id=?`, res.TargetID).
		Scan(&watchOnly, &monitor, &hours, &name, &priority, &kind); err != nil {
		t.Fatal(err)
	}
	if watchOnly != 0 || monitor != 1 || hours != 6 || name != "intigriti/deep-one" || priority != "critical" || kind != "mixed" {
		t.Fatalf("target = watch=%d monitor=%d hours=%d name=%q priority=%q kind=%q", watchOnly, monitor, hours, name, priority, kind)
	}
	var enabled int
	if err := db.QueryRow(`SELECT COALESCE(SUM(monitor_enabled),0) FROM assets WHERE target_id=?`, res.TargetID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 2 {
		t.Fatalf("enabled assets=%d, want 2", enabled)
	}
}

func TestBulkCreateProjectsValidation(t *testing.T) {
	svc, _ := testCatalog(t)
	ctx := context.Background()
	if _, err := svc.CreateProjectsBulk(ctx, 1, BulkCreateProjectsRequest{}); err == nil {
		t.Fatal("empty program list was accepted")
	}
	if _, err := svc.CreateProjectsBulk(ctx, 1, BulkCreateProjectsRequest{ProgramIDs: []string{"x"}, Coverage: "sideways"}); err == nil || !strings.Contains(err.Error(), "coverage") {
		t.Fatalf("invalid coverage error = %v", err)
	}
	if _, err := svc.CreateProjectsBulk(ctx, 1, BulkCreateProjectsRequest{ProgramIDs: []string{"x"}, Coverage: "breadth", AssetPolicy: "everything"}); err == nil || !strings.Contains(err.Error(), "asset_policy") {
		t.Fatalf("invalid asset policy error = %v", err)
	}
	ids := make([]string, maxBulkProjectCreations+1)
	for i := range ids {
		ids[i] = "p" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if _, err := svc.CreateProjectsBulk(ctx, 1, BulkCreateProjectsRequest{ProgramIDs: ids, Coverage: "breadth"}); err == nil {
		t.Fatal("oversized batch was accepted")
	}
}
