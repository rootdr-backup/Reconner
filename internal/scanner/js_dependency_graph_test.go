package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

func TestJSDependencyGraphTraversesDepthOnceAndRejectsEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `import "./nested/b.js"; const root=true;`)
	})
	mux.HandleFunc("/nested/b.js", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `import("../deep/c.mjs"); import "../a.js";`)
	})
	mux.HandleFunc("/deep/c.mjs", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `const value=location.hash; document.body.innerHTML=value;`)
	})
	mux.HandleFunc("/empty.js", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/fake.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<!doctype html><html><body>soft 404</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, tid := testDB(t)
	defer db.Close()
	parsed, _ := url.Parse(srv.URL)
	// Keep targetScope empty so the static DOM guard does not interpret the local
	// loopback test host as a third-party registrable domain.
	_, _ = db.Exec(`UPDATE targets SET domain='' WHERE id=?`, tid)
	cfg := &config.Config{Workers: config.WorkerConfig{JSAnalysis: 4}}
	s := &JSScanner{db: db, cfg: cfg, logger: logger.NewWithWriter("error", io.Discard)}
	analyzed := s.analyzeJSGraph(context.Background(), tid, parsed.Hostname(),
		[]string{srv.URL + "/a.js", srv.URL + "/empty.js", srv.URL + "/fake.js"}, func(_, _, _ string) {})
	if analyzed != 3 {
		t.Fatalf("expected a,b,c exactly once and empty rejected; analyzed=%d", analyzed)
	}
	var files int
	_ = db.QueryRow(`SELECT COUNT(*) FROM js_files WHERE target_id=?`, tid).Scan(&files)
	if files != 3 {
		t.Fatalf("dependency cycle duplicated or missed JS files: %d", files)
	}
	var conf int
	if err := db.QueryRow(`SELECT confidence FROM candidates WHERE target_id=? AND type='dom_xss' AND subtype='static-flow'`, tid).Scan(&conf); err != nil {
		t.Fatalf("deep DOM source/sink lead was not discovered: %v", err)
	}
	if conf >= ConfHiddenCutoff {
		t.Fatalf("static DOM lead must remain internal until runtime proof, confidence=%d", conf)
	}
	var projected int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='dom_xss'`, tid).Scan(&projected)
	if projected != 0 {
		t.Fatalf("unexecuted static DOM lead leaked into UI findings/candidates: %d", projected)
	}
}

func TestJSScopeSupportsMultiAssetTargetsWithoutThirdPartyExpansion(t *testing.T) {
	scope := "https://app.example.com/path, api.second.test"
	if !isTargetDomainHost("cdn.example.com", scope) || !isTargetDomainHost("v2.api.second.test", scope) {
		t.Fatal("multi-asset first-party JS host was rejected")
	}
	if isTargetDomainHost("example.com.attacker.test", scope) ||
		jsDependencyInScope("https://evil.invalid/x.js", "https://cdn.example.com/a.js", scope) {
		t.Fatal("third-party JS dependency escaped target scope")
	}
}
