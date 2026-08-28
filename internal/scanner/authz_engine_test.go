package scanner

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/pkg/logger"
)

// End-to-end: seed two identities + an owned object, point it at a mock app, and
// confirm the AuthzEngine produces a BOLA finding on the vulnerable app and NONE
// on the secure app — with a persisted hypothesis in each case.
func TestAuthzEngineEndToEnd(t *testing.T) {
	withLoopbackAllowed(t)
	run := func(vulnerable bool) (findings int, verified bool) {
		dir := t.TempDir()
		db, err := database.New(filepath.Join(dir, "t.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := database.RunMigrations(db); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{SessionSecret: "test-secret"}
		box := secret.New(cfg.SessionSecret)

		app := mockApp(vulnerable)
		defer app.Close()
		url := app.URL + "/api/objects/1" // owned by user-a
		endpoint := NormalizeURL(url)

		tid := uuid.New().String()
		_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "mock.local")

		// identities (encrypted headers, like the API stores them)
		addIdentity := func(label, token string, baseline bool) {
			hb, _ := json.Marshal(map[string]string{"Authorization": "Bearer " + token})
			b := 0
			if baseline {
				b = 1
			}
			_, _ = db.Exec(`INSERT INTO identities (id, target_id, label, role, headers_json, is_baseline, status)
			   VALUES (?,?,?,?,?,?, 'authenticated')`,
				uuid.New().String(), tid, label, "user", box.Encrypt(string(hb)), b)
		}
		addIdentity("user-a", "tok-a", true)
		addIdentity("user-b", "tok-b", false)

		// object owned by user-a (strong ownership) + the object row w/ source_url
		_, _ = db.Exec(`INSERT INTO object_relationships (id, target_id, object_type, object_id, endpoint_template, identity_label, role, provenance)
		   VALUES (?,?,?,?,?,?, 'CREATOR', 'seed')`, uuid.New().String(), tid, "object", "1", endpoint, "user-a")
		_, _ = db.Exec(`INSERT INTO objects (id, target_id, obj_type, identifier, source_url, endpoint_template, param, owner_identity)
		   VALUES (?,?,?,?,?,?, '', 'user-a')`, uuid.New().String(), tid, "object", "1", url, endpoint)
		_, _ = db.Exec(`INSERT INTO actions (id, target_id, identity_label, verb, method, url, endpoint_template, object_type, object_id, status, source)
		   VALUES (?,?,?, 'READ','GET',?,?, 'object','1',200,'seed')`, uuid.New().String(), tid, "user-a", url, endpoint)

		eng := NewAuthzEngine(db, nil, cfg, logger.New("error"), nil)
		_ = eng.Run(context.Background(), tid, "mock.local", func(_, _, _ string) {})

		_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='bola'`, tid).Scan(&findings)
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM hypotheses WHERE target_id=? AND status='VERIFIED'`, tid).Scan(&n)
		verified = n > 0
		return
	}

	if f, v := run(true); f == 0 || !v {
		t.Fatalf("vulnerable app must yield a verified BOLA finding (findings=%d verified=%v)", f, v)
	}
	if f, _ := run(false); f != 0 {
		t.Fatalf("secure app must yield NO BOLA finding, got %d", f)
	}
}
