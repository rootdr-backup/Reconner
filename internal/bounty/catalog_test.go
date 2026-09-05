package bounty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/recon-platform/internal/database"
)

func testCatalog(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	return NewService(db, nil), db
}

func storeTestProgram(t *testing.T, svc *Service, p *Program) {
	t.Helper()
	finalizeProgramAssets(p)
	if err := svc.upsertProgram(context.Background(), p, p); err != nil {
		t.Fatal(err)
	}
	if err := svc.replaceAssets(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogFiltersAndProjectScopeLifecycle(t *testing.T) {
	svc, db := testCatalog(t)
	p := Program{
		Provider:       "hackerone",
		ExternalID:     "team-1",
		Handle:         "acme",
		Name:           "Acme",
		URL:            "https://hackerone.com/acme",
		Status:         "live",
		ProgramType:    "bug_bounty",
		Industry:       "software",
		OffersBounties: true,
		SafeHarbor:     "full",
		MaxRewardCents: 500000,
		Assets: []Asset{
			{ExternalID: "scope-1", Identifier: "*.acme.test", AssetType: "WILDCARD", InScope: true, EligibleSubmission: true, EligibleBounty: true, Active: true},
			{ExternalID: "scope-out", Identifier: "old.acme.test", AssetType: "DOMAIN", InScope: false, EligibleSubmission: false, Active: true},
		},
	}
	storeTestProgram(t, svc, &p)

	yes := true
	result, err := svc.ListPrograms(context.Background(), ListOptions{
		Provider: "hackerone", SafeHarbor: "full", HasWildcard: &yes, OffersBounties: &yes,
		MinAssets: 1, MaxAssets: 1, MinRewardCents: 100000, AssetType: "wildcard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Programs) != 1 || result.Programs[0].Handle != "acme" {
		t.Fatalf("catalog filters did not preserve the expected program: %#v", result)
	}

	projectID, err := svc.CreateProject(context.Background(), 0, p.ID, CreateProjectRequest{
		Name: "Acme monitored", AssetIDs: []string{p.Assets[0].ID}, MonitorEnabled: true, MonitorIntervalHours: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	var imported, enabled int
	if err := db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(monitor_enabled),0) FROM assets WHERE target_id=? AND approval_status='approved'`, projectID).Scan(&imported, &enabled); err != nil {
		t.Fatal(err)
	}
	if imported != 1 || enabled != 1 {
		t.Fatalf("project import=%d enabled=%d, want 1/1", imported, enabled)
	}

	// A provider-side addition becomes a pending review event; it must not be
	// inserted into the project's active assets until explicitly approved.
	p.Assets = append(p.Assets, Asset{ExternalID: "scope-2", Identifier: "api.acme.test", AssetType: "DOMAIN", InScope: true, EligibleSubmission: true, Active: true})
	storeTestProgram(t, svc, &p)
	var eventID string
	if err := db.QueryRow(`SELECT id FROM bounty_scope_events WHERE target_id=? AND event_type='added' AND status='pending'`, projectID).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE target_id=?`, projectID).Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if imported != 1 {
		t.Fatalf("new upstream scope was activated without approval: %d assets", imported)
	}
	if err := svc.ResolveScopeEvent(context.Background(), projectID, eventID, "approve"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE target_id=? AND approval_status='approved'`, projectID).Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if imported != 2 {
		t.Fatalf("approved addition was not imported: %d assets", imported)
	}

	// Removal is fail-safe: the old asset is suspended immediately, even before
	// the operator resolves the informational removal event.
	p.Assets = p.Assets[1:]
	storeTestProgram(t, svc, &p)
	var status string
	var monitor int
	if err := db.QueryRow(`SELECT approval_status,monitor_enabled FROM assets WHERE target_id=? AND value='*.acme.test'`, projectID).Scan(&status, &monitor); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" || monitor != 0 {
		t.Fatalf("removed scope remained active: status=%s monitor=%d", status, monitor)
	}

	// If a formerly public program disappears from a successful provider
	// listing, preserve the project but suspend every remaining linked asset.
	if err := svc.markMissingPrograms(context.Background(), "hackerone", map[string]bool{"some-other-public-program": true}); err != nil {
		t.Fatal(err)
	}
	var programStatus string
	if err := db.QueryRow(`SELECT status FROM bounty_programs WHERE id=?`, p.ID).Scan(&programStatus); err != nil {
		t.Fatal(err)
	}
	if programStatus != "unavailable" {
		t.Fatalf("missing program status=%q, want unavailable", programStatus)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE target_id=? AND approval_status='approved'`, projectID).Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if imported != 0 {
		t.Fatalf("missing public program left %d approved assets", imported)
	}
}

func TestResolveRejectsAssetThatBecameIneligible(t *testing.T) {
	svc, db := testCatalog(t)
	p := Program{Provider: "hackerone", ExternalID: "t2", Handle: "safe", Name: "Safe", Status: "live", Assets: []Asset{
		{ExternalID: "one", Identifier: "safe.test", AssetType: "DOMAIN", InScope: true, EligibleSubmission: true, Active: true},
	}}
	storeTestProgram(t, svc, &p)
	projectID, err := svc.CreateProject(context.Background(), 0, p.ID, CreateProjectRequest{AssetIDs: []string{p.Assets[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	p.Assets = append(p.Assets, Asset{ExternalID: "two", Identifier: "new.safe.test", AssetType: "DOMAIN", InScope: true, EligibleSubmission: true, Active: true})
	storeTestProgram(t, svc, &p)
	var eventID, programAssetID string
	if err := db.QueryRow(`SELECT id,program_asset_id FROM bounty_scope_events WHERE target_id=? AND event_type='added' AND status='pending'`, projectID).Scan(&eventID, &programAssetID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE bounty_program_assets SET active=0,in_scope=0,eligible_submission=0 WHERE id=?`, programAssetID); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResolveScopeEvent(context.Background(), projectID, eventID, "approve"); err == nil || !strings.Contains(err.Error(), "no longer active") {
		t.Fatalf("stale scope approval should fail closed, got %v", err)
	}
}

func TestHackerOneProviderContract(t *testing.T) {
	svc, db := testCatalog(t)
	detailCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var request struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if strings.Contains(request.Query, "ReconnerProgramScope") {
			detailCalls++
			_, _ = w.Write([]byte(`{"data":{"team":{"structured_scopes":{"pageInfo":{"hasNextPage":false,"endCursor":""},"nodes":[
				{"id":"scope","asset_identifier":"*.demo.test","asset_type":"WILDCARD","eligible_for_submission":true,"eligible_for_bounty":true}
			]}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"teams":{"pageInfo":{"hasNextPage":false,"endCursor":""},"edges":[{"node":{
			"id":"team","handle":"demo","name":"Demo","state":"public_mode","type":"BugBountyProgram",
			"offers_bounties":true,"launched_at":"2026-01-02T03:04:05Z","last_updated_at":"2026-02-02T03:04:05Z","currency":"usd",
			"declarative_policy":{"protected_by_gold_standard_safe_harbor":true}}}]}}}`))
	}))
	defer server.Close()
	old := hackerOneGraphQLURL
	hackerOneGraphQLURL = server.URL
	t.Cleanup(func() { hackerOneGraphQLURL = old })

	if err := svc.syncHackerOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count, wildcards, eagerAssets int
	var safe string
	if err := db.QueryRow(`SELECT COUNT(*),MAX(wildcard_count),MAX(safe_harbor) FROM bounty_programs WHERE provider='hackerone'`).Scan(&count, &wildcards, &safe); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM bounty_program_assets`).Scan(&eagerAssets); err != nil {
		t.Fatal(err)
	}
	if count != 1 || wildcards != 0 || safe != "full" || eagerAssets != 0 || detailCalls != 0 {
		t.Fatalf("unexpected HackerOne list/lazy contract: count=%d wildcards=%d safe=%q eager=%d detail_calls=%d", count, wildcards, safe, eagerAssets, detailCalls)
	}
	var programID string
	if err := db.QueryRow(`SELECT id FROM bounty_programs WHERE provider='hackerone'`).Scan(&programID); err != nil {
		t.Fatal(err)
	}
	wildcard := true
	indexed, err := svc.ListPrograms(context.Background(), ListOptions{HasWildcard: &wildcard})
	if err != nil {
		t.Fatal(err)
	}
	if !indexed.DetailIndex.Running || indexed.DetailIndex.Total != 1 {
		t.Fatalf("scope-derived filter must start the unopened-program index, got %+v", indexed.DetailIndex)
	}
	deadline := time.Now().Add(2 * time.Second)
	for svc.DetailIndexStatus().Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	indexed, err = svc.ListPrograms(context.Background(), ListOptions{HasWildcard: &wildcard})
	if err != nil {
		t.Fatal(err)
	}
	if indexed.Total != 1 || len(indexed.Programs) != 1 || !indexed.Programs[0].DetailsLoaded {
		t.Fatalf("wildcard filter must include unopened catalog programs after indexing: %+v", indexed)
	}
	p, err := svc.GetProgram(context.Background(), programID)
	if err != nil {
		t.Fatal(err)
	}
	if p.WildcardCount != 1 || len(p.Assets) != 1 || detailCalls != 1 {
		t.Fatalf("unexpected normalized HackerOne detail: wildcards=%d assets=%d calls=%d", p.WildcardCount, len(p.Assets), detailCalls)
	}
}

func TestBugcrowdProviderContractAndRelativeBriefURL(t *testing.T) {
	svc, db := testCatalog(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/engagement_listings":
			w.Header().Set("Content-Type", "application/json")
			level := r.URL.Query().Get("safe_harbor_status")
			engagements := "[]"
			total := 0
			if level == "" || level == "full" {
				engagements = `[{"name":"Acme","briefUrl":"` + server.URL + `/engagements/acme","scopeRank":4,"accessStatus":"open","industryName":"Software","rewardSummary":{"minReward":"$100","maxReward":"$5,000"}}]`
				total = 1
			}
			_, _ = w.Write([]byte(`{"engagements":` + engagements + `,"paginationMeta":{"totalCount":` + string(rune('0'+total)) + `,"limit":24}}`))
		case "/engagements/acme":
			_, _ = w.Write([]byte(`<script>{"getBriefVersionDocument":"/brief/acme"}</script>`))
		case "/brief/acme.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"engagementId":"e1","publishedAt":"2026-01-01T00:00:00Z","statusLabel":"In progress","data":{
				"engagement":{"startsAt":"2026-01-01T00:00:00Z"},"scope":[{"id":"g1","name":"Web","inScope":true,
				"targets":[{"id":"a1","uri":"*.acme.test","category":"website"}]}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	old := bugcrowdBaseURL
	bugcrowdBaseURL = server.URL
	t.Cleanup(func() { bugcrowdBaseURL = old })

	if err := svc.syncBugcrowd(context.Background()); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = db.QueryRow(`SELECT COUNT(*) FROM bounty_program_assets`).Scan(&before)
	if before != 0 {
		t.Fatalf("Bugcrowd catalog sync must be list-only, got %d eager assets", before)
	}
	var programID string
	if err := db.QueryRow(`SELECT id FROM bounty_programs WHERE provider='bugcrowd'`).Scan(&programID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetProgram(context.Background(), programID); err != nil {
		t.Fatal(err)
	}
	var count, wildcards int
	var safe string
	var status string
	if err := db.QueryRow(`SELECT COUNT(*),MAX(wildcard_count),MAX(safe_harbor),MAX(status) FROM bounty_programs WHERE provider='bugcrowd'`).Scan(&count, &wildcards, &safe, &status); err != nil {
		t.Fatal(err)
	}
	if count != 1 || wildcards != 1 || safe != "full" || status != "live" {
		t.Fatalf("unexpected normalized Bugcrowd contract: count=%d wildcards=%d safe=%q status=%q", count, wildcards, safe, status)
	}
}

func TestIntigritiProviderIsListFirstAndScopeLazy(t *testing.T) {
	svc, db := testCatalog(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/core/public/programs":
			_, _ = w.Write([]byte(`[{"programId":"i1","status":3,"confidentialityLevel":4,"companyHandle":"acme","handle":"bbp","name":"Acme","description":"Public program","industry":"software","minBounty":{"value":50,"currency":"EUR"},"maxBounty":{"value":5000,"currency":"EUR"},"createdAt":1760000000,"lastUpdatedAt":1761000000},{"programId":"private","status":3,"confidentialityLevel":2,"companyHandle":"private","handle":"apply","name":"Apply"}]`))
		case "/api/core/public/programs/acme/bbp":
			_, _ = w.Write([]byte(`{"programId":"i1","status":3,"confidentialityLevel":4,"assetsCollection":[{"createdAt":1761000000,"content":{"assetsAndGroups":[{"discriminator":1,"id":"a1","companyAssetId":"stable-a1","typeId":7,"name":"*.acme.test","bountyTierId":3},{"discriminator":2,"id":"g1","name":"Out of scope","assets":[{"discriminator":1,"id":"a2","companyAssetId":"stable-a2","typeId":1,"name":"old.acme.test","bountyTierId":5}]}]}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	old := intigritiCoreURL
	intigritiCoreURL = server.URL + "/api/core"
	t.Cleanup(func() { intigritiCoreURL = old })

	if err := svc.syncIntigriti(context.Background()); err != nil {
		t.Fatal(err)
	}
	var programID string
	var programs, eager int
	_ = db.QueryRow(`SELECT COUNT(*),MIN(id) FROM bounty_programs WHERE provider='intigriti'`).Scan(&programs, &programID)
	_ = db.QueryRow(`SELECT COUNT(*) FROM bounty_program_assets`).Scan(&eager)
	if programs != 1 || eager != 0 {
		t.Fatalf("Intigriti list normalization/lazy boundary: programs=%d eager_assets=%d", programs, eager)
	}
	p, err := svc.GetProgram(context.Background(), programID)
	if err != nil {
		t.Fatal(err)
	}
	if p.AssetCount != 2 || p.InScopeCount != 1 || p.WildcardCount != 1 {
		t.Fatalf("unexpected Intigriti scope normalization: %+v", p)
	}
}

func TestYesWeHackProviderIsListFirstAndScopeLazy(t *testing.T) {
	svc, db := testCatalog(t)
	detailCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/programs" && r.URL.Query().Get("page") == "1":
			_, _ = w.Write([]byte(`{"items":[{"title":"Acme","slug":"acme","activity_area":"Tech","type":"bug-bounty","status":"V","public":true,"bounty":true,"bounty_reward_min":100,"bounty_reward_max":4000,"scopes_count":2,"last_update_at":"2026-01-02T03:04:05Z","thumbnail":{"url":"https://cdn.test/acme.png"},"business_unit":{"currency":"EUR","description":"Acme public program"}}],"pagination":{"page":1,"nb_pages":1}}`))
		case r.URL.Path == "/programs/acme":
			detailCalls++
			_, _ = w.Write([]byte(`{"title":"Acme","slug":"acme","type":"bug-bounty","status":"V","public":true,"bounty":true,"business_unit":{"currency":"EUR"},"scopes":[{"scope":"https://app.acme.test/","scope_type":"web-application","scope_type_name":"Web application","asset_value":"HIGH"},{"scope":"api.acme.test","scope_type":"api","scope_type_name":"API","asset_value":"CRITICAL"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	old := yesWeHackAPIURL
	yesWeHackAPIURL = server.URL
	t.Cleanup(func() { yesWeHackAPIURL = old })

	if err := svc.syncYesWeHack(context.Background()); err != nil {
		t.Fatal(err)
	}
	var programID string
	_ = db.QueryRow(`SELECT id FROM bounty_programs WHERE provider='yeswehack'`).Scan(&programID)
	if detailCalls != 0 {
		t.Fatalf("YesWeHack detail fetched eagerly %d time(s)", detailCalls)
	}
	p, err := svc.GetProgram(context.Background(), programID)
	if err != nil {
		t.Fatal(err)
	}
	if p.InScopeCount != 2 || detailCalls != 1 {
		t.Fatalf("YesWeHack lazy detail mismatch: assets=%d calls=%d", p.InScopeCount, detailCalls)
	}
	if _, err := svc.GetProgram(context.Background(), programID); err != nil || detailCalls != 1 {
		t.Fatalf("cached detail was refetched: err=%v calls=%d", err, detailCalls)
	}
}

// Opt-in contract check against the public provider catalogs. CI stays fully
// deterministic; maintainers can run this before a release to catch an upstream
// schema change that fixture tests cannot predict.
func TestLivePublicCatalogContracts(t *testing.T) {
	if os.Getenv("RECONNER_LIVE_CATALOG_TEST") != "1" {
		t.Skip("set RECONNER_LIVE_CATALOG_TEST=1 to query public provider catalogs")
	}
	svc, db := testCatalog(t)
	if err := svc.syncHackerOne(context.Background()); err != nil {
		t.Fatalf("live HackerOne contract: %v", err)
	}
	if err := svc.syncBugcrowd(context.Background()); err != nil {
		t.Fatalf("live Bugcrowd contract: %v", err)
	}
	if err := svc.syncIntigriti(context.Background()); err != nil {
		t.Fatalf("live Intigriti contract: %v", err)
	}
	if err := svc.syncYesWeHack(context.Background()); err != nil {
		t.Fatalf("live YesWeHack contract: %v", err)
	}
	for _, provider := range []string{"hackerone", "bugcrowd", "intigriti", "yeswehack"} {
		var programs, assets int
		if err := db.QueryRow(`SELECT COUNT(*) FROM bounty_programs WHERE provider=?`, provider).Scan(&programs); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM bounty_program_assets a JOIN bounty_programs p ON p.id=a.program_id WHERE p.provider=? AND a.active=1`, provider).Scan(&assets); err != nil {
			t.Fatal(err)
		}
		if programs > 0 && assets == 0 {
			rows, _ := db.Query(`SELECT id FROM bounty_programs WHERE provider=? AND status='live' LIMIT 8`, provider)
			var ids []string
			for rows != nil && rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			if rows != nil {
				rows.Close()
			}
			for _, id := range ids {
				if _, err := svc.GetProgram(context.Background(), id); err != nil {
					continue
				}
				_ = db.QueryRow(`SELECT COUNT(*) FROM bounty_program_assets a JOIN bounty_programs p ON p.id=a.program_id WHERE p.provider=? AND a.active=1`, provider).Scan(&assets)
				if assets > 0 {
					break
				}
			}
		}
		if programs == 0 || assets == 0 {
			t.Fatalf("%s live catalog normalized programs=%d assets=%d", provider, programs, assets)
		}
		t.Logf("%s: %d programs, %d active declared assets", provider, programs, assets)
	}
}
