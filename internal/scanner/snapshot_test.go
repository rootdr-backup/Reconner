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

func TestDiffSnapshots(t *testing.T) {
	before := StateSnapshot{Status: 200, Fingerprint: "a", Fields: map[string]string{"role": "viewer"}}
	after := StateSnapshot{Status: 200, Fingerprint: "b", Fields: map[string]string{"role": "admin"}}
	d := DiffSnapshots(before, after)
	if !d.Changed || d.Fields["role"] != [2]string{"viewer", "admin"} {
		t.Fatalf("role escalation must be detected: %+v", d)
	}
	// deletion
	del := DiffSnapshots(StateSnapshot{Status: 200}, StateSnapshot{Status: 404})
	if !del.Changed || del.Existence != "deleted" {
		t.Fatalf("deletion must be detected: %+v", del)
	}
	// no change
	same := DiffSnapshots(StateSnapshot{Status: 200, Fingerprint: "a", Fields: map[string]string{"role": "viewer"}},
		StateSnapshot{Status: 200, Fingerprint: "a", Fields: map[string]string{"role": "viewer"}})
	if same.Changed {
		t.Fatalf("identical snapshots must NOT report a change: %+v", same)
	}
}

// End-to-end BFLA: a member escalates their role via a write only an admin should
// perform; the owner's before/after view proves the side effect → verified finding.
// A secure app rejects the write → no finding.
func TestVerifyWriteEndToEnd(t *testing.T) {
	withLoopbackAllowed(t)
	run := func(vulnerable bool) (findings int) {
		// mutable app state: object 1's role, owned by user-a
		var mu sync.Mutex
		role := "viewer"
		app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if who == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch r.Method {
			case "GET": // owner (or anyone authed) can read object 1
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.Repeat("x", 200) + `{"id":"1","owner":"user-a","role":"` + role + `"}`))
			case "PATCH":
				// vulnerable: any authed user can change the role. secure: only user-a.
				if vulnerable || who == "tok-a" {
					role = "admin"
					w.WriteHeader(200)
				} else {
					http.Error(w, "forbidden", http.StatusForbidden)
				}
			}
		}))
		defer app.Close()

		dir := t.TempDir()
		db, _ := database.New(filepath.Join(dir, "t.db"))
		defer db.Close()
		_ = database.RunMigrations(db)
		cfg := &config.Config{SessionSecret: "s"}
		box := secret.New(cfg.SessionSecret)
		tid := uuid.New().String()
		_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "m.local")
		add := func(label, tok string) {
			hb, _ := json.Marshal(map[string]string{"Authorization": "Bearer " + tok})
			_, _ = db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline,status) VALUES (?,?,?, 'user',?,0,'authenticated')`,
				uuid.New().String(), tid, label, box.Encrypt(string(hb)))
		}
		add("user-a", "tok-a")
		add("user-b", "tok-b")
		// user-a owns object 1; user-b has NO relationship.
		endpoint := NormalizeURL(app.URL + "/obj/1")
		_, _ = db.Exec(`INSERT INTO object_relationships (id,target_id,object_type,object_id,endpoint_template,identity_label,role,provenance) VALUES (?,?,?,?,?,?, 'OWNER','seed')`,
			uuid.New().String(), tid, "obj", "1", endpoint, "user-a")

		ids := LoadIdentities(context.Background(), db, tid, box)
		eng := NewAuthzEngine(db, nil, cfg, logger.New("error"), nil)
		res := eng.VerifyWrite(context.Background(), tid, ids, WriteVerifySpec{
			OwnerLabel: "user-a", AttackerLabel: "user-b", ObjectType: "obj", ObjectID: "1",
			ReadURL: app.URL + "/obj/1", WriteMethod: "PATCH", WriteURL: app.URL + "/obj/1", WriteBody: `{"role":"admin"}`,
		})
		_ = res
		_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='bfla'`, tid).Scan(&findings)
		return
	}

	if run(true) == 0 {
		t.Fatal("vulnerable app: member role-escalation must be a verified BFLA finding")
	}
	if run(false) != 0 {
		t.Fatal("secure app: rejected write must produce NO finding")
	}
}
