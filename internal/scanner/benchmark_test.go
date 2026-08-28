package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/pkg/logger"
)

// saasApp models a small multi-identity SaaS: object "1" is owned by user-a.
// Behaviour is controlled per-case to exercise TRUE positives and the
// FALSE-POSITIVE traps (public data, membership, non-protected resources).
type saasCase struct {
	name       string
	vulnerable bool            // any authed user can read object 1
	public     bool            // unauthenticated can read object 1 (not auth-protected)
	members    map[string]bool // tokens with a legitimate relationship to object 1
	wantFlaw   bool            // expected: a verified BOLA finding
}

func saasServer(c saasCase) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		body := strings.Repeat("x", 200) + `{"id":"1","owner":"user-a","secret":"a-private-data"}`
		if tok == "" {
			if c.public {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		owner := tok == "tok-a"
		if owner || c.vulnerable || c.members[tok] {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
}

// TestDetectionBenchmark is the measurable TP/FP/FN baseline (Phases 8–10).
func TestDetectionBenchmark(t *testing.T) {
	withLoopbackAllowed(t)
	cases := []saasCase{
		{name: "vulnerable-BOLA-read", vulnerable: true, wantFlaw: true},
		{name: "secure-BOLA", vulnerable: false, wantFlaw: false},
		{name: "public-endpoint (FP trap)", public: true, vulnerable: true, wantFlaw: false}, // not auth-protected → not a BOLA
		{name: "shared-object member (FP trap)", vulnerable: true, members: map[string]bool{"tok-b": true}, wantFlaw: false},
	}

	var tp, fp, fn int
	for _, c := range cases {
		app := saasServer(c)
		db, _ := database.New(filepath.Join(t.TempDir(), "b.db"))
		_ = database.RunMigrations(db)
		cfg := &config.Config{SessionSecret: "s"}
		box := secret.New(cfg.SessionSecret)
		tid := uuid.New().String()
		_, _ = db.Exec(`INSERT INTO targets (id,domain,priority) VALUES (?,?, 'medium')`, tid, "m.local")
		add := func(label, tok string, base bool) {
			hb, _ := json.Marshal(map[string]string{"Authorization": "Bearer " + tok})
			b := 0
			if base {
				b = 1
			}
			_, _ = db.Exec(`INSERT INTO identities (id,target_id,label,role,headers_json,is_baseline,status) VALUES (?,?,?, 'user',?,?, 'authenticated')`,
				uuid.New().String(), tid, label, box.Encrypt(string(hb)), b)
		}
		add("user-a", "tok-a", true)
		add("user-b", "tok-b", false)

		url := app.URL + "/api/objects/1"
		endpoint := NormalizeURL(url)
		_, _ = db.Exec(`INSERT INTO object_relationships (id,target_id,object_type,object_id,endpoint_template,identity_label,role,provenance) VALUES (?,?,?,?,?,?, 'OWNER','seed')`,
			uuid.New().String(), tid, "object", "1", endpoint, "user-a")
		_, _ = db.Exec(`INSERT INTO objects (id,target_id,obj_type,identifier,source_url,endpoint_template,param,owner_identity) VALUES (?,?,?,?,?,?, '','user-a')`,
			uuid.New().String(), tid, "object", "1", url, endpoint)
		_, _ = db.Exec(`INSERT INTO actions (id,target_id,identity_label,verb,method,url,endpoint_template,object_type,object_id,status,source) VALUES (?,?, 'user-a','READ','GET',?,?, 'object','1',200,'seed')`,
			uuid.New().String(), tid, url, endpoint)
		// the FP-trap where user-b is a legitimate MEMBER of the object
		if c.members["tok-b"] {
			_, _ = db.Exec(`INSERT INTO object_relationships (id,target_id,object_type,object_id,endpoint_template,identity_label,role,provenance) VALUES (?,?,?,?,?,?, 'MEMBER','seed')`,
				uuid.New().String(), tid, "object", "1", endpoint, "user-b")
		}

		eng := NewAuthzEngine(db, nil, cfg, logger.New("error"), nil)
		_ = eng.Run(context.Background(), tid, "m.local", func(_, _, _ string) {})

		var found int
		_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='bola'`, tid).Scan(&found)
		detected := found > 0

		switch {
		case c.wantFlaw && detected:
			tp++
		case c.wantFlaw && !detected:
			fn++
			t.Errorf("FALSE NEGATIVE: %s — expected a BOLA finding, got none", c.name)
		case !c.wantFlaw && detected:
			fp++
			t.Errorf("FALSE POSITIVE: %s — flagged a finding on legitimate behaviour", c.name)
		}
		db.Close()
		app.Close()
	}

	t.Logf("Detection baseline: TP=%d FP=%d FN=%d (of %d cases)", tp, fp, fn, len(cases))
	if fp != 0 {
		t.Fatalf("benchmark requires ZERO false positives, got %d", fp)
	}
}
