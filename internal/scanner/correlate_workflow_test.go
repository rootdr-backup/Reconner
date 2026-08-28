package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

func testDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "m.local")
	return db, tid
}

func TestCorrelationKey(t *testing.T) {
	a := CorrelationKey("bola", "https://x.com/api/projects/1")
	b := CorrelationKey("bola", "https://x.com/api/projects/2")
	if a != b {
		t.Fatalf("same type + endpoint template must correlate: %q vs %q", a, b)
	}
	if a == CorrelationKey("bola", "https://x.com/api/orders/1") {
		t.Fatal("different endpoints must not correlate")
	}
	if a == CorrelationKey("idor", "https://x.com/api/projects/1") {
		t.Fatal("different types must not correlate")
	}
}

func TestCorrelateFindings(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ins := func(url, sev string, conf int) string {
		id := uuid.New().String()
		_, _ = db.Exec(`INSERT INTO vuln_findings (id,target_id,type,severity,url,parameter,confidence,status) VALUES (?,?, 'bola',?,?,?,?, 'finding')`,
			id, tid, sev, url, "p", conf)
		return id
	}
	ins("https://x.com/api/projects/1", "high", 80)
	root := ins("https://x.com/api/projects/2", "critical", 95) // strongest → root
	ins("https://x.com/api/projects/3", "high", 70)
	ins("https://x.com/api/orders/9", "medium", 60) // different group

	groups := CorrelateFindings(context.Background(), db, tid)
	if groups != 2 {
		t.Fatalf("expected 2 root groups, got %d", groups)
	}
	// all 3 project findings must point at the strongest as root
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND root_finding_id=?`, tid, root).Scan(&n)
	if n != 3 {
		t.Fatalf("expected 3 members under the root, got %d", n)
	}
}

func TestBuildWorkflowGraph(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline) VALUES (?,?, 'user-a','user','{}',1)`, uuid.New().String(), tid)
	_, _ = db.Exec(`INSERT INTO object_relationships (id,target_id,object_type,object_id,identity_label,role,provenance) VALUES (?,?, 'project','1','user-a','CREATOR','seed')`, uuid.New().String(), tid)
	_, _ = db.Exec(`INSERT INTO actions (id,target_id,identity_label,verb,method,object_type,object_id,status,source) VALUES (?,?, 'user-a','UPDATE','PATCH','project','1',200,'seed')`, uuid.New().String(), tid)

	g := BuildWorkflowGraph(context.Background(), db, tid)
	var hasIdentity, hasObject bool
	for _, n := range g.Nodes {
		if n.Type == "identity" && n.Label == "user-a" {
			hasIdentity = true
		}
		if n.Type == "object" && n.Label == "project#1" {
			hasObject = true
		}
	}
	if !hasIdentity || !hasObject {
		t.Fatalf("graph must contain the identity and object nodes: %+v", g.Nodes)
	}
	var ownership, action bool
	for _, e := range g.Edges {
		if e.Kind == "ownership" && e.Label == "CREATOR" {
			ownership = true
		}
		if e.Kind == "action" && e.Label == "UPDATE" {
			action = true
		}
	}
	if !ownership || !action {
		t.Fatalf("graph must have ownership + action edges: %+v", g.Edges)
	}
}
