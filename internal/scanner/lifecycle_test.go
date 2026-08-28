package scanner

import (
	"context"
	"sync"
	"testing"

	"github.com/recon-platform/internal/database"
)

func mkCandidate(t *testing.T, db *database.DB, tid, typ, url, param string) string {
	t.Helper()
	return StoreCandidate(context.Background(), db, VulnerabilityCandidate{
		TargetID: tid, Type: typ, URL: url, Parameter: param, Location: "query",
		DetectionSource: "test", Confidence: 80,
	})
}

func candState(t *testing.T, db *database.DB, id string) string {
	t.Helper()
	var s string
	_ = db.QueryRow(`SELECT status FROM candidates WHERE id=?`, id).Scan(&s)
	return s
}

func TestLifecycleHappyPath(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()
	id := mkCandidate(t, db, tid, "sqli", "https://x.com/a?id=1", "id")

	steps := []struct {
		to   string
		want bool
	}{
		{CandTriaged, true},
		{CandVerifying, true},
		{CandVerified, true},
		{CandConfirmed, true},
	}
	for _, s := range steps {
		applied, state := TransitionCandidate(ctx, db, id, s.to, "test", "m", "r", 90)
		if applied != s.want || state != s.to {
			t.Fatalf("→%s: applied=%v state=%s", s.to, applied, state)
		}
	}
}

func TestLifecycleVerifyingBranches(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()
	for _, to := range []string{CandRejected, CandInconclusive, CandConfirmed} {
		id := mkCandidate(t, db, tid, "sqli", "https://x.com/b/"+to+"?id=1", "id")
		TransitionCandidate(ctx, db, id, CandVerifying, "t", "m", "r", 80)
		if applied, st := TransitionCandidate(ctx, db, id, to, "t", "m", "r", 0); !applied || st != to {
			t.Fatalf("VERIFYING→%s failed: applied=%v st=%s", to, applied, st)
		}
	}
}

func TestLifecycleStaleGuards(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()

	// CONFIRMED then stale REJECTED must NOT downgrade.
	c1 := mkCandidate(t, db, tid, "sqli", "https://x.com/c1?id=1", "id")
	TransitionCandidate(ctx, db, c1, CandVerifying, "t", "m", "r", 80)
	TransitionCandidate(ctx, db, c1, CandConfirmed, "t", "sqlmap", "positive", 100)
	applied, st := TransitionCandidate(ctx, db, c1, CandRejected, "t", "sqlmap", "stale", 0)
	if applied || st != CandConfirmed {
		t.Fatalf("stale REJECTED downgraded CONFIRMED: applied=%v st=%s", applied, st)
	}

	// REJECTED then stale CONFIRMED must NOT overwrite.
	c2 := mkCandidate(t, db, tid, "sqli", "https://x.com/c2?id=1", "id")
	TransitionCandidate(ctx, db, c2, CandVerifying, "t", "m", "r", 80)
	TransitionCandidate(ctx, db, c2, CandRejected, "t", "sqlmap", "negative", 0)
	applied, st = TransitionCandidate(ctx, db, c2, CandConfirmed, "t", "x", "stale", 100)
	if applied || st != CandRejected {
		t.Fatalf("stale CONFIRMED overwrote REJECTED: applied=%v st=%s", applied, st)
	}
}

func TestLifecycleIllegalAndIdempotent(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()
	id := mkCandidate(t, db, tid, "sqli", "https://x.com/d?id=1", "id")

	// Illegal: DETECTED → VERIFIED (must go through VERIFYING) is not legal.
	if applied, _ := TransitionCandidate(ctx, db, id, CandVerified, "t", "m", "r", 0); applied {
		t.Fatal("illegal DETECTED→VERIFIED was applied")
	}
	// Idempotent: DETECTED → DETECTED is a no-op success (applied=false).
	if applied, st := TransitionCandidate(ctx, db, id, CandDetected, "t", "m", "r", 0); applied || st != CandDetected {
		t.Fatalf("idempotent self-transition wrong: applied=%v st=%s", applied, st)
	}
}

func TestLifecycleDuplicateFromAny(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()
	// CONFIRMED can still be superseded by DUPLICATE.
	id := mkCandidate(t, db, tid, "xss", "https://x.com/e?q=1", "q")
	TransitionCandidate(ctx, db, id, CandVerifying, "t", "m", "r", 80)
	TransitionCandidate(ctx, db, id, CandConfirmed, "t", "m", "r", 100)
	if applied, st := TransitionCandidate(ctx, db, id, CandDuplicate, "t", "corr", "dup", 0); !applied || st != CandDuplicate {
		t.Fatalf("CONFIRMED→DUPLICATE failed: applied=%v st=%s", applied, st)
	}
}

func TestLifecycleFindingProjection(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()

	// A confirmed candidate projects onto a matching finding.
	cc := mkCandidate(t, db, tid, "sqli", "https://x.com/f?id=1", "id")
	_, _ = db.Exec(`INSERT INTO vuln_findings (id,target_id,type,severity,url,parameter,status,confidence)
		VALUES ('vf1',?,'sqli','high','https://x.com/f?id=1','id','finding',92)`, tid)
	TransitionCandidate(ctx, db, cc, CandVerifying, "t", "m", "r", 92)
	TransitionCandidate(ctx, db, cc, CandConfirmed, "t", "sqlmap", "positive", 100)
	var lc, status, candID string
	_ = db.QueryRow(`SELECT COALESCE(lifecycle,''),COALESCE(status,''),COALESCE(candidate_id,'') FROM vuln_findings WHERE id='vf1'`).Scan(&lc, &status, &candID)
	if lc != CandConfirmed || status != StatusFinding || candID != cc {
		t.Fatalf("confirmed projection wrong: lc=%s status=%s candID=%s", lc, status, candID)
	}

	// A rejected candidate demotes its surfaced finding out of the confirmed view.
	cr := mkCandidate(t, db, tid, "sqli", "https://x.com/g?id=1", "id")
	_, _ = db.Exec(`INSERT INTO vuln_findings (id,target_id,type,severity,url,parameter,status,confidence)
		VALUES ('vf2',?,'sqli','high','https://x.com/g?id=1','id','finding',92)`, tid)
	TransitionCandidate(ctx, db, cr, CandVerifying, "t", "m", "r", 92)
	TransitionCandidate(ctx, db, cr, CandRejected, "t", "sqlmap", "negative", 0)
	_ = db.QueryRow(`SELECT COALESCE(status,'') FROM vuln_findings WHERE id='vf2'`).Scan(&status)
	if status != "rejected" {
		t.Fatalf("rejected finding still status=%s (should be 'rejected')", status)
	}
}

func TestLifecycleLegacyDefault(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	// A finding inserted the legacy way (no candidate) defaults to LEGACY.
	_, _ = db.Exec(`INSERT INTO vuln_findings (id,target_id,type,severity,url,parameter,status)
		VALUES ('leg',?,'xss','high','https://x.com/h?q=1','q','finding')`, tid)
	var lc, candID string
	_ = db.QueryRow(`SELECT COALESCE(lifecycle,''),COALESCE(candidate_id,'') FROM vuln_findings WHERE id='leg'`).Scan(&lc, &candID)
	if lc != LifecycleLegacy || candID != "" {
		t.Fatalf("legacy row wrong: lc=%s candID=%s", lc, candID)
	}
}

func TestLifecycleConcurrentSingleWinner(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ctx := context.Background()
	id := mkCandidate(t, db, tid, "sqli", "https://x.com/i?id=1", "id")
	TransitionCandidate(ctx, db, id, CandVerifying, "t", "m", "r", 80)

	var wg sync.WaitGroup
	var winners int
	var mu sync.Mutex
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if applied, _ := TransitionCandidate(ctx, db, id, CandConfirmed, "t", "m", "r", 100); applied {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("expected exactly one winning transition, got %d", winners)
	}
	if candState(t, db, id) != CandConfirmed {
		t.Fatalf("final state not CONFIRMED")
	}
	var trans int
	_ = db.QueryRow(`SELECT COUNT(*) FROM candidate_transitions WHERE candidate_id=? AND to_state=?`, id, CandConfirmed).Scan(&trans)
	if trans != 1 {
		t.Fatalf("expected exactly 1 CONFIRMED transition row, got %d", trans)
	}
}
