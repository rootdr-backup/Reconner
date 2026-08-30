package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

func TestCandidateLifecycle(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = database.RunMigrations(db)
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "m.local")
	ctx := context.Background()

	c := VulnerabilityCandidate{TargetID: tid, Type: "sqli", URL: "https://x/api?id=1", Parameter: "id", Confidence: 60}
	id1 := StoreCandidate(ctx, db, c)
	// same fingerprint (same endpoint template + param) → dedup, higher confidence kept
	c.Confidence = 80
	id2 := StoreCandidate(ctx, db, c)
	if id1 != id2 {
		t.Fatal("same candidate must dedup to one row")
	}
	var n, conf int
	_ = db.QueryRow(`SELECT COUNT(*), MAX(confidence) FROM candidates WHERE target_id=?`, tid).Scan(&n, &conf)
	if n != 1 || conf != 80 {
		t.Fatalf("dedup/confidence failed: n=%d conf=%d", n, conf)
	}
	SetCandidateStatus(ctx, db, id1, CandInconclusive, "sqlmap", "WAF", 60)
	var st, reason string
	_ = db.QueryRow(`SELECT status, verification_reason FROM candidates WHERE id=?`, id1).Scan(&st, &reason)
	if st != CandInconclusive || reason != "WAF" {
		t.Fatalf("status update failed: %s %s", st, reason)
	}
}

// stub verifier for orchestrator routing
type stubVerifier struct{ verdict string }

func (s stubVerifier) Name() string                            { return "stub" }
func (s stubVerifier) CanVerify(c VulnerabilityCandidate) bool { return c.Type == "sqli" }
func (s stubVerifier) Verify(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	return VerifyResult{Verdict: s.verdict, Confidence: 90}
}

func TestOrchestratorRouting(t *testing.T) {
	o := NewOrchestrator(stubVerifier{verdict: VerifyVerified})
	if r := o.Verify(context.Background(), VulnerabilityCandidate{Type: "sqli"}); r.Verdict != VerifyVerified || r.Method != "stub" {
		t.Fatalf("must route sqli to stub: %+v", r)
	}
	// unhandled type → INCONCLUSIVE, never a silent confirm
	if r := o.Verify(context.Background(), VulnerabilityCandidate{Type: "xss"}); r.Verdict != VerifyInconclusive {
		t.Fatalf("unhandled type must be INCONCLUSIVE: %+v", r)
	}
}

func TestSQLmapArgsAreStructuredAndSafe(t *testing.T) {
	c := VulnerabilityCandidate{Type: "sqli", URL: "https://x/api?id=1; DROP TABLE users--", Method: "GET", Parameter: "id"}
	args := buildSQLmapArgs(c, "session=abc")
	// URL must be a single argv element (not shell-interpolated) — the ';' stays inert.
	found := false
	for i, a := range args {
		if a == "-u" && i+1 < len(args) && strings.Contains(args[i+1], "DROP TABLE") {
			found = true
		}
	}
	if !found {
		t.Fatal("URL must be passed as a discrete argv element")
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--batch") || !strings.Contains(joined, "-p id") || !strings.Contains(joined, "--cookie session=abc") {
		t.Fatalf("expected conservative structured args: %v", args)
	}
}

func TestSQLmapArgsPreserveInsertionLocationAndAuth(t *testing.T) {
	auth := map[string]string{"Cookie": "session=abc; cart=7", "Authorization": "Bearer token"}
	tests := []struct {
		name string
		c    VulnerabilityCandidate
		want []string
		not  []string
	}{
		{
			name: "form body",
			c:    VulnerabilityCandidate{URL: "https://x.test/save?keep=yes", Method: "POST", Location: "body", Parameter: "title", Payload: "error_based"},
			want: []string{"-u https://x.test/save?keep=yes", "--method=POST", "--data title=1", "-p title", "Authorization: Bearer token"},
			not:  []string{"--data error_based"},
		},
		{
			name: "json body",
			c:    VulnerabilityCandidate{URL: "https://x.test/api", Method: "POST", Location: "json", Parameter: "lookup"},
			want: []string{`--data {"lookup":"1*"}`, "Content-Type: application/json"},
			not:  []string{"-p lookup"},
		},
		{
			name: "multipart body",
			c:    VulnerabilityCandidate{URL: "https://x.test/upload", Method: "POST", Location: "multipart", Parameter: "title"},
			want: []string{"Content-Type: multipart/form-data; boundary=----ReconnerSQLmapBoundary", `name="title"`, "1*"},
			not:  []string{"-p title"},
		},
		{
			name: "xml body marker",
			c:    VulnerabilityCandidate{URL: "https://x.test/xml", Method: "POST", Location: "xml", Parameter: "lookup"},
			want: []string{"Content-Type: application/xml", "<lookup>1*</lookup>"},
			not:  []string{"-p lookup"},
		},
		{
			name: "path marker",
			c:    VulnerabilityCandidate{URL: "https://x.test/orders/847/items?view=full", Method: "GET", Location: "path:1", Parameter: "path1"},
			want: []string{"-u https://x.test/orders/847*/items?view=full"},
			not:  []string{"-p path1"},
		},
		{
			name: "existing cookie marker",
			c:    VulnerabilityCandidate{URL: "https://x.test/account", Method: "GET", Location: "cookie", Parameter: "cart"},
			want: []string{"--cookie session=abc; cart=7*"},
			not:  []string{"-p cart"},
		},
		{
			name: "forwarded header marker",
			c:    VulnerabilityCandidate{URL: "https://x.test/audit", Method: "GET", Location: "header", Parameter: "X-Forwarded-For"},
			want: []string{"X-Forwarded-For: 127.0.0.1, 127.0.0.1*"},
			not:  []string{"-p X-Forwarded-For"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			joined := strings.Join(buildSQLmapArgsWithHeaders(tt.c, auth), " ")
			for _, want := range tt.want {
				if !strings.Contains(joined, want) {
					t.Errorf("args missing %q: %s", want, joined)
				}
			}
			for _, not := range tt.not {
				if strings.Contains(joined, not) {
					t.Errorf("args unexpectedly contain %q: %s", not, joined)
				}
			}
		})
	}
}

func TestParseSQLmapOutput(t *testing.T) {
	pos := `sqlmap identified the following injection point
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
back-end DBMS: MySQL >= 5.0`
	positive, dbms, typ := parseSQLmapOutput(pos)
	if !positive || !strings.Contains(dbms, "MySQL") || !strings.Contains(typ, "boolean") {
		t.Fatalf("must detect positive injection: pos=%v dbms=%q typ=%q", positive, dbms, typ)
	}
	neg := `all tested parameters do not appear to be injectable`
	if p, _, _ := parseSQLmapOutput(neg); p {
		t.Fatal("negative output must not be positive")
	}
	if r := sqlmapInconclusiveReason(neg); !strings.Contains(r, "INCONCLUSIVE") {
		t.Fatalf("negative → inconclusive reason, got %q", r)
	}
}
