package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
)

// The services.ewa.bh false positive: a CNAME to a live AWS ALB was matched as a
// dangling S3 bucket by the old catch-all "amazonaws.com" pattern.
func TestTakeoverFingerprintDoesNotMatchELB(t *testing.T) {
	elb := "customer-service-system-alb-1447939680.eu-west-1.elb.amazonaws.com"
	if fp := matchTakeoverFingerprint(elb); fp != nil {
		t.Fatalf("an ELB/ALB name must not match any takeover fingerprint, matched %q", fp.service)
	}
	if !awsNonTakeoverableInfra(elb) {
		t.Fatal("ELB name must be recognised as non-takeoverable AWS infrastructure")
	}
}

func TestTakeoverFingerprintStillMatchesRealServices(t *testing.T) {
	cases := map[string]string{
		"mybucket.s3.amazonaws.com":                   "AWS S3",
		"mybucket.s3-website-eu-west-1.amazonaws.com": "AWS S3",
		"mybucket.s3.eu-west-1.amazonaws.com":         "AWS S3",
		"someorg.github.io":                           "GitHub Pages",
		"app.herokuapp.com":                           "Heroku",
		"site.azurewebsites.net":                      "Azure",
	}
	for cname, want := range cases {
		fp := matchTakeoverFingerprint(cname)
		if fp == nil {
			t.Errorf("%s: expected a %s match, got nil", cname, want)
			continue
		}
		if fp.service != want {
			t.Errorf("%s: expected %s, got %s", cname, want, fp.service)
		}
		if awsNonTakeoverableInfra(cname) {
			t.Errorf("%s: real claimable service must NOT be treated as non-takeoverable infra", cname)
		}
	}
}

// The core rule: no dangling signal ⇒ score 0 (dropped). This is exactly the
// ewa.bh case (sigMatch=false, nx=false, subzy=false).
func TestTakeoverConfidence(t *testing.T) {
	cases := []struct {
		sig, nx, subzy bool
		want           int
	}{
		{false, false, false, 0},              // live/claimed resource → drop (the FP)
		{true, false, false, ConfEvidence},    // unclaimed-body signature
		{false, true, false, ConfCandidateHi}, // CNAME target NXDOMAIN
		{false, false, true, ConfEvidence},    // subzy confirms
		{true, true, false, ConfMultiTool},    // body + DNS
		{true, false, true, ConfMultiTool},    // body + subzy
	}
	for _, c := range cases {
		if got := takeoverConfidence(c.sig, c.nx, c.subzy); got != c.want {
			t.Errorf("takeoverConfidence(sig=%v nx=%v subzy=%v) = %d, want %d", c.sig, c.nx, c.subzy, got, c.want)
		}
	}
}

func TestSubjackalJSONStreamParsing(t *testing.T) {
	raw := `{
  "Domain": "vuln.target.com",
  "RecordType": "CNAME",
  "CNAMEChain": ["dangling.github.io."],
  "CNAMETarget": "dangling.github.io",
  "ServiceProvider": "GitHub Pages",
  "TakeoverPossible": true,
  "Confidence": "high",
  "Score": { "CNAMEMatch": 70, "NXDOMAINBack": 0, "HTTPMatch": 100, "NSUnregistered": 0 },
  "Fingerprint": "There isn't a GitHub Pages site here",
  "Status": "vulnerable",
  "Note": "CONFIRMED — GitHub Pages fingerprint matched via HTTP (https) — score: 170"
}
{
  "Domain": "suspicious.target.com",
  "RecordType": "CNAME",
  "CNAMEChain": ["old.herokuapp.com."],
  "CNAMETarget": "old.herokuapp.com",
  "ServiceProvider": "Heroku",
  "TakeoverPossible": true,
  "Confidence": "medium",
  "Score": { "CNAMEMatch": 70, "NXDOMAINBack": 20, "HTTPMatch": 0, "NSUnregistered": 0 },
  "Status": "suspicious",
  "Note": "CNAME → Heroku [vulnerable] (backend NXDOMAIN) — score: 90"
}
{
  "Domain": "dismissed.target.com",
  "RecordType": "A",
  "IPs": ["140.82.113.18"],
  "CNAMEChain": ["redirect.github.com."],
  "CNAMETarget": "redirect.github.com",
  "Status": "dismissed",
  "Note": "CNAME chain resolves → redirect.github.com (140.82.113.18) — not dangling"
}
{
  "Domain": "alive.target.com",
  "RecordType": "A",
  "IPs": ["1.2.3.4"],
  "Status": "alive"
}`

	parsed, err := parseSubjackalJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parseSubjackalJSON failed: %v", err)
	}
	if len(parsed) != 4 {
		t.Fatalf("expected 4 parsed records, got %d", len(parsed))
	}
	if parsed[0].Status != "vulnerable" || parsed[0].Domain != "vuln.target.com" {
		t.Errorf("record 0 mismatch: %+v", parsed[0])
	}
	if parsed[1].Status != "suspicious" || parsed[1].ServiceProvider != "Heroku" {
		t.Errorf("record 1 mismatch: %+v", parsed[1])
	}
	if parsed[2].Status != "dismissed" || parsed[2].CNAMETarget != "redirect.github.com" {
		t.Errorf("record 2 mismatch: %+v", parsed[2])
	}
	if parsed[3].Status != "alive" {
		t.Errorf("record 3 mismatch: %+v", parsed[3])
	}
}

func TestSubjackalLifecycleIntegration(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "subjackal_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = database.RunMigrations(db)

	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "target.com")

	ts := NewTakeoverScanner(db, nil, nil, nil, nil)

	var found atomic.Int64
	logFn := func(lvl, mod, msg string) {}

	// 1. Vulnerable -> must become a confirmed finding in vuln_findings
	vuln := subjackalSubdomain{
		Domain:          "takeover.target.com",
		CNAMETarget:     "dangling.github.io",
		ServiceProvider: "GitHub Pages",
		Status:          "vulnerable",
		Note:            "CONFIRMED via HTTP",
	}
	ts.recordSubjackalResult(tid, vuln, &found, logFn)
	if found.Load() != 1 {
		t.Fatalf("expected found count to be 1, got %d", found.Load())
	}

	var findingStatus string
	var conf int
	err = db.QueryRow(`SELECT status, confidence FROM vuln_findings WHERE target_id=? AND url=?`,
		tid, "https://takeover.target.com").Scan(&findingStatus, &conf)
	if err != nil {
		t.Fatalf("vulnerable record must produce a row in vuln_findings: %v", err)
	}
	if findingStatus != StatusFinding || conf < ConfEvidence {
		t.Errorf("vulnerable record status=%q conf=%d, want status=%q conf>=%d",
			findingStatus, conf, StatusFinding, ConfEvidence)
	}

	// 2. Suspicious -> must be projected as a candidate, NOT a finding
	susp := subjackalSubdomain{
		Domain:          "suspicious.target.com",
		CNAMETarget:     "old.herokuapp.com",
		ServiceProvider: "Heroku",
		Status:          "suspicious",
		Note:            "dangling CNAME, probe inconclusive",
	}
	ts.recordSubjackalResult(tid, susp, &found, logFn)

	var candStatus string
	err = db.QueryRow(`SELECT status FROM vuln_findings WHERE target_id=? AND url=?`,
		tid, "https://suspicious.target.com").Scan(&candStatus)
	if err != nil {
		t.Fatalf("suspicious candidate must be projected into vuln_findings as candidate: %v", err)
	}
	if candStatus != StatusCandidate {
		t.Errorf("suspicious record status=%q, want %q", candStatus, StatusCandidate)
	}

	// 3. Dismissed (the Issue #21 false positive fix: CNAME chain resolves to live IP)
	dismissed := subjackalSubdomain{
		Domain:          "live-chain.target.com",
		CNAMETarget:     "redirect.github.com",
		ServiceProvider: "GitHub Pages",
		Status:          "dismissed",
		Note:            "CNAME chain resolves to live IP (not dangling)",
	}
	ts.recordSubjackalResult(tid, dismissed, &found, logFn)

	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND url=?`,
		tid, "https://live-chain.target.com").Scan(&count)
	if count != 0 {
		t.Fatalf("dismissed takeover candidate must NOT create finding row, found %d", count)
	}

	// 4. Alive (HTTP 200/300) -> must NOT create finding row
	alive := subjackalSubdomain{
		Domain: "live.target.com",
		Status: "alive",
	}
	ts.recordSubjackalResult(tid, alive, &found, logFn)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND url=?`,
		tid, "https://live.target.com").Scan(&count)
	if count != 0 {
		t.Fatalf("alive domain must NOT create finding row, found %d", count)
	}
}

func TestTakeoverToolFreeFallback(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "fallback_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = database.RunMigrations(db)

	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "target.com")

	cfg := &config.Config{}
	exec := tools.NewToolFreeExecutor(cfg, nil)
	ts := NewTakeoverScanner(db, exec, cfg, nil, nil)

	if exec.IsToolAvailable("subjackal") {
		t.Fatal("tool-free executor must report subjackal as unavailable")
	}

	err = ts.Run(context.Background(), tid, func(lvl, mod, msg string) {})
	if err != nil {
		t.Fatalf("native fallback Run failed: %v", err)
	}
}

func TestSubjackalNativeLogging(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "logging_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = database.RunMigrations(db)

	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "example.com")
	ts := NewTakeoverScanner(db, nil, nil, nil, nil)

	// 1. Test zero findings -> confirm NO detailed blocks are logged
	t.Run("ZeroFindingsConciseOutput", func(t *testing.T) {
		var logs []string
		logFn := func(lvl, mod, msg string) {
			logs = append(logs, msg)
		}
		var found atomic.Int64
		nonVuln := []subjackalSubdomain{
			{Domain: "alive.example.com", Status: "alive"},
			{Domain: "nx.example.com", Status: "nxdomain"},
			{Domain: "dismissed.example.com", Status: "dismissed", Note: "resolves to live IP"},
		}
		for _, item := range nonVuln {
			ts.recordSubjackalResult(tid, item, &found, logFn)
		}
		if len(logs) != 0 {
			t.Fatalf("expected 0 detailed logs for zero findings, got %d: %v", len(logs), logs)
		}
		if found.Load() != 0 {
			t.Fatalf("expected found count 0, got %d", found.Load())
		}
	})

	// 2. Test one confirmed finding -> confirm detailed Subjackal-style block
	t.Run("OneConfirmedFindingDetailedBlock", func(t *testing.T) {
		var logs []string
		logFn := func(lvl, mod, msg string) {
			logs = append(logs, msg)
		}
		var found atomic.Int64
		vuln := subjackalSubdomain{
			Domain:          "stage-member-experience-api.cld.samsclub.com",
			CNAMETarget:     "stg-omnichanneleng-common-apim.azure-api.net",
			CNAMEChain:      []string{"stg-omnichanneleng-common-apim.azure-api.net"},
			ServiceProvider: "Microsoft Azure",
			Confidence:      "high",
			Status:          "vulnerable",
			Note:            "CONFIRMED — Microsoft Azure CNAME target NXDOMAIN",
			Score: subjackalScore{
				CNAMEMatch:   70,
				NXDOMAINBack: 20,
				HTTPMatch:    100,
			},
		}
		ts.recordSubjackalResult(tid, vuln, &found, logFn)

		expected := []string{
			"[TK] [VULNERABLE] stage-member-experience-api.cld.samsclub.com",
			"[TK]              service    : Microsoft Azure [vulnerable]",
			"[TK]              confidence : high (score: 190)",
			"[TK]              note       : CONFIRMED — Microsoft Azure CNAME target NXDOMAIN",
			"[TK] [VALIDATE] stage-member-experience-api.cld.samsclub.com",
			"[TK]   │",
			"[TK]   ├── CNAME chain",
			"[TK]   │   → stg-omnichanneleng-common-apim.azure-api.net",
			"[TK]   │   → final: stg-omnichanneleng-common-apim.azure-api.net (NXDOMAIN — dangling)",
			"[TK]   │",
		}

		if len(logs) != len(expected) {
			t.Fatalf("expected %d log lines, got %d:\nGot: %v\nWant: %v", len(expected), len(logs), logs, expected)
		}
		for i := range expected {
			if logs[i] != expected[i] {
				t.Errorf("line %d mismatch:\ngot:  %q\nwant: %q", i, logs[i], expected[i])
			}
		}
		if found.Load() != 1 {
			t.Errorf("expected found count 1, got %d", found.Load())
		}
	})

	// 3. Test multiple findings -> confirm each finding gets its own block
	t.Run("MultipleFindingsSeparateBlocks", func(t *testing.T) {
		var logs []string
		logFn := func(lvl, mod, msg string) {
			logs = append(logs, msg)
		}
		var found atomic.Int64
		vuln1 := subjackalSubdomain{
			Domain:          "first.example.com",
			CNAMETarget:     "first.azurewebsites.net",
			CNAMEChain:      []string{"first.azurewebsites.net"},
			ServiceProvider: "Microsoft Azure",
			Status:          "vulnerable",
			Note:            "CONFIRMED",
			Score: subjackalScore{
				CNAMEMatch:   70,
				NXDOMAINBack: 20,
				HTTPMatch:    100,
			},
		}
		vuln2 := subjackalSubdomain{
			Domain:          "second.example.com",
			CNAMETarget:     "second.github.io",
			CNAMEChain:      []string{"second.github.io"},
			ServiceProvider: "GitHub Pages",
			Status:          "vulnerable",
			Note:            "CONFIRMED via HTTP",
			Score: subjackalScore{
				CNAMEMatch: 70,
				HTTPMatch:  100,
			},
		}

		ts.recordSubjackalResult(tid, vuln1, &found, logFn)
		ts.recordSubjackalResult(tid, vuln2, &found, logFn)

		if found.Load() != 2 {
			t.Fatalf("expected found count 2, got %d", found.Load())
		}

		// Verify both finding blocks are present
		firstFound := false
		secondFound := false
		for _, l := range logs {
			if strings.Contains(l, "[VULNERABLE] first.example.com") {
				firstFound = true
			}
			if strings.Contains(l, "[VULNERABLE] second.example.com") {
				secondFound = true
			}
		}
		if !firstFound || !secondFound {
			t.Errorf("expected both finding blocks in logs, got: %v", logs)
		}
	})

	// 4. Test suspicious candidate -> confirm [SUSPICIOUS] format line
	t.Run("SuspiciousCandidateLogging", func(t *testing.T) {
		var logs []string
		logFn := func(lvl, mod, msg string) {
			logs = append(logs, msg)
		}
		var found atomic.Int64
		susp := subjackalSubdomain{
			Domain:          "sub.example.com",
			CNAMETarget:     "app.herokuapp.com",
			ServiceProvider: "Heroku",
			Confidence:      "medium",
			Status:          "suspicious",
			Score: subjackalScore{
				CNAMEMatch:   70,
				NXDOMAINBack: 20,
			},
		}
		ts.recordSubjackalResult(tid, susp, &found, logFn)

		want := "[TK] [SUSPICIOUS] sub.example.com — CNAME → Heroku (medium confidence, score: 90)"
		if len(logs) != 1 || logs[0] != want {
			t.Fatalf("unexpected suspicious log:\ngot:  %v\nwant: [%s]", logs, want)
		}
	})
}
