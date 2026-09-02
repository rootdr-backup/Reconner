package database

import (
	"path/filepath"
	"testing"
)

func TestBrowserlessXSSConfirmationMigrationDowngradesDifferentialOnlyProof(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "xss-proof.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('t1','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO candidates
		(id,target_id,type,subtype,url,method,parameter,location,detection_source,detection_method,severity,confidence,status,verification_method,verification_reason,fingerprint,state_version)
		VALUES('c1','t1','xss','reflected','https://example.test/?q=x','GET','q','query','dast','context:quoted_attribute/differential','high',95,'CONFIRMED','dast-differential','raw markup survived','fp1',2)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_findings
		(id,target_id,type,severity,url,parameter,confidence,priority,status,candidate_id,lifecycle)
		VALUES('f1','t1','xss','high','https://example.test/?q=x','q',95,95,'finding','c1','CONFIRMED')`); err != nil {
		t.Fatal(err)
	}
	if err := migrateBrowserlessXSSConfirmations(db); err != nil {
		t.Fatal(err)
	}
	var candidateStatus, method, findingStatus, lifecycle string
	var candidateConfidence, findingConfidence int
	if err := db.QueryRow(`SELECT status,verification_method,confidence FROM candidates WHERE id='c1'`).Scan(&candidateStatus, &method, &candidateConfidence); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT status,lifecycle,confidence FROM vuln_findings WHERE id='f1'`).Scan(&findingStatus, &lifecycle, &findingConfidence); err != nil {
		t.Fatal(err)
	}
	if candidateStatus != "INCONCLUSIVE" || method != "xss-runtime-required" || candidateConfidence != 85 {
		t.Fatalf("candidate not repaired: status=%s method=%s confidence=%d", candidateStatus, method, candidateConfidence)
	}
	if findingStatus != "candidate" || lifecycle != "INCONCLUSIVE" || findingConfidence != 85 {
		t.Fatalf("finding projection not repaired: status=%s lifecycle=%s confidence=%d", findingStatus, lifecycle, findingConfidence)
	}
	var transitions int
	_ = db.QueryRow(`SELECT COUNT(*) FROM candidate_transitions WHERE candidate_id='c1' AND method='runtime-proof-policy'`).Scan(&transitions)
	if transitions != 1 {
		t.Fatalf("expected one migration audit transition, got %d", transitions)
	}
	if err := migrateBrowserlessXSSConfirmations(db); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}
}
