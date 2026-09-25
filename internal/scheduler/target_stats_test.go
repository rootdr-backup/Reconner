package scheduler

import "testing"

func TestUpdateTargetStatsCountsOnlyActionableMediumPlus(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('t-stats','stats.test')`); err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`INSERT INTO backup_findings (id,target_id,url) VALUES ('b1','t-stats','https://stats.test/.env')`,
		`INSERT INTO nuclei_findings (id,target_id,template_id,severity,matched_url,verification) VALUES ('n1','t-stats','info-tech','info','https://stats.test','unverified')`,
		`INSERT INTO nuclei_findings (id,target_id,template_id,severity,matched_url,verification) VALUES ('n2','t-stats','real-medium','medium','https://stats.test/a','verified')`,
		`INSERT INTO nuclei_findings (id,target_id,template_id,severity,matched_url,verification) VALUES ('n3','t-stats','real-medium','medium','https://stats.test/b','verified')`,
		`INSERT INTO nuclei_findings (id,target_id,template_id,severity,matched_url,verification) VALUES ('n4','t-stats','rejected-high','high','https://stats.test/c','rejected')`,
		`INSERT INTO open_redirect_findings (id,target_id,url,status) VALUES ('r1','t-stats','https://stats.test/r','finding')`,
		`INSERT INTO vuln_findings (id,target_id,type,severity,url,status,triage) VALUES ('v1','t-stats','xss','medium','https://stats.test/x','finding','confirmed')`,
		`INSERT INTO vuln_findings (id,target_id,type,severity,url,status,triage) VALUES ('v2','t-stats','cors','low','https://stats.test/cors','finding','')`,
		`INSERT INTO vuln_findings (id,target_id,type,severity,url,status,triage) VALUES ('v3','t-stats','sqli','critical','https://stats.test/sql','finding','false_positive')`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	s.updateTargetStats("t-stats")
	var got int
	if err := s.db.QueryRow(`SELECT finding_count FROM targets WHERE id='t-stats'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 3 { // one distinct Nuclei template + redirect + confirmed vuln
		t.Fatalf("finding_count=%d, want 3", got)
	}
}
