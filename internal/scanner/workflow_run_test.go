package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/pkg/logger"
)

func TestExtractJSONField(t *testing.T) {
	if extractJSONField(`{"id":"abc123","name":"x"}`, "id") != "abc123" {
		t.Fatal("must extract id")
	}
	if extractJSONField(`{"name":"x"}`, "id") != "" {
		t.Fatal("missing field → empty")
	}
}

func TestRunWorkflowPropagationAndAbort(t *testing.T) {
	withLoopbackAllowed(t)
	// app: POST /projects returns {"id":"P7"}; GET /projects/{id} returns it.
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", 200) + `{"id":"P7","owner":"user-a"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("x", 200) + `{"id":"P7"}`))
	}))
	defer app.Close()

	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = database.RunMigrations(db)
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "127.0.0.1")

	steps := []WorkflowStep{
		{Method: "POST", URL: app.URL + "/projects", Extract: map[string]string{"project.id": "id"}},
		{Method: "GET", URL: app.URL + "/projects/${project.id}"},
	}
	res := RunWorkflow(context.Background(), db, tid, nil, steps, nil)
	if res.Aborted {
		t.Fatalf("should not abort: %s", res.AbortReason)
	}
	if res.Vars["project.id"] != "P7" {
		t.Fatalf("variable propagation failed: %+v", res.Vars)
	}
	if !strings.HasSuffix(res.Steps[1].URL, "/projects/P7") {
		t.Fatalf("step 2 URL must resolve ${project.id}: %q", res.Steps[1].URL)
	}

	// missing prerequisite must abort BEFORE running the dependent step
	bad := []WorkflowStep{{Method: "GET", URL: app.URL + "/projects/${missing.id}"}}
	r2 := RunWorkflow(context.Background(), db, tid, nil, bad, nil)
	if !r2.Aborted || r2.Steps[0].Verdict != "PREREQUISITE_MISSING" {
		t.Fatalf("must abort on missing prerequisite: %+v", r2)
	}
}

// A workflow prerequisite/authorization bypass: user-b completes a step that
// should be denied (they weren't invited) → flagged + finding.
func TestRunWorkflowBypassFinding(t *testing.T) {
	withLoopbackAllowed(t)
	var mu sync.Mutex
	invited := map[string]bool{} // token → invited to project
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/accept"):
			// VULNERABLE: anyone can accept, invited or not.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", 200) + `{"id":"MEMBER1","status":"member"}`))
			_ = who
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", 200) + `{"id":"INV1"}`))
		}
	}))
	defer app.Close()
	_ = invited

	db, _ := database.New(filepath.Join(t.TempDir(), "t.db"))
	defer db.Close()
	_ = database.RunMigrations(db)
	cfg := &config.Config{SessionSecret: "s"}
	box := secret.New(cfg.SessionSecret)
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "127.0.0.1")
	hb, _ := json.Marshal(map[string]string{"Authorization": "Bearer tok-b"})
	_, _ = db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline,status) VALUES (?,?, 'user-b','user',?,0,'authenticated')`,
		uuid.New().String(), tid, box.Encrypt(string(hb)))

	ids := LoadIdentities(context.Background(), db, tid, box)
	eng := NewAuthzEngine(db, nil, cfg, logger.New("error"), nil)
	steps := []WorkflowStep{
		// user-b (never invited) accepts an invitation — expected DENIED.
		{IdentityLabel: "user-b", Method: "POST", URL: app.URL + "/invitations/INV1/accept", ExpectDenied: true},
	}
	res := eng.RunWorkflow(context.Background(), tid, ids, steps, nil)
	if res.FlaggedStep != 0 {
		t.Fatalf("bypass step must be flagged: %+v", res)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='workflow_authz_bypass'`, tid).Scan(&n)
	if n == 0 {
		t.Fatal("a flagged workflow bypass must create a finding")
	}
}
