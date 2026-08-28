package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// End-to-end verification of the reconstructed pipeline: auto-discovery → dual
// crawl → ownership → cross-user pairing → confirmed finding (vulnerable) / zero
// (secure), plus a couple of unit anchors for the mutation/confidence layer.

func TestAuthzUnitAnchors(t *testing.T) {
	if classifyIDKind("100") != "int" || classifyIDKind("550e8400-e29b-41d4-a716-446655440000") != "uuid" {
		t.Fatal("kind classification broken")
	}
	base := authzSignals{unauthDenied: true, ownerHasObject: true, attackerGotObject: true}
	if authzConfidence(base) != 55 {
		t.Fatal("bare protected must be candidate 55")
	}
	md := base
	md.methodDifferential = true
	if authzConfidence(md) != 70 {
		t.Fatal("accepted-but-unverified write must be candidate 70 (no 200==vuln)")
	}
	if !ParseAuthzProfile("balanced").allowsWrite() || ParseAuthzProfile("balanced").allowsDelete(true) {
		t.Fatal("balanced profile gating wrong")
	}
	if !looksLikeOpenAPI(`{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}`) {
		t.Fatal("openapi detection broken")
	}
}

type vfix struct {
	mu       sync.Mutex
	orderVal map[string]string
	vuln     bool
}

func newVerifyApp(vulnerable bool) *httptest.Server {
	f := &vfix{orderVal: map[string]string{"500": "a", "600": "b"}, vuln: vulnerable}
	tok := map[string]string{"tok-a": "user-a", "tok-b": "user-b"}
	uo := map[string]string{"100": "user-a", "200": "user-b"}
	oo := map[string]string{"500": "user-a", "600": "user-b"}
	self := map[string][2]string{"user-a": {"100", "500"}, "user-b": {"200", "600"}}
	pad := strings.Repeat("X", 200)
	obj := func(k, id, o, extra string) string {
		return pad + fmt.Sprintf(`{"kind":%q,"id":%q,"owner":%q,"d":"r-%s-%s"%s}`, k, id, o, k, id, extra)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := tok[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>` + pad + `<a href="/api/me">me</a></body></html>`))
		case r.URL.Path == "/api/me":
			if who == "" {
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(pad + fmt.Sprintf(`{"user_id":%s,"self":"/api/users/%s","orders":["/api/orders/%s"]}`, self[who][0], self[who][0], self[who][1])))
		case strings.HasPrefix(r.URL.Path, "/api/users/"):
			if who == "" {
				http.Error(w, "unauthorized", 401)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/users/")
			o, ok := uo[id]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			if o != who && !f.vuln {
				http.Error(w, "forbidden", 403)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(obj("user", id, o, "")))
		case strings.HasPrefix(r.URL.Path, "/api/orders/"):
			if who == "" {
				http.Error(w, "unauthorized", 401)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
			o, ok := oo[id]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			cross := o != who
			f.mu.Lock()
			defer f.mu.Unlock()
			switch r.Method {
			case http.MethodGet:
				if cross && !f.vuln {
					http.Error(w, "forbidden", 403)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(obj("order", id, o, `,"v":"`+f.orderVal[id]+`"`)))
			case http.MethodPatch:
				if cross && !f.vuln {
					http.Error(w, "forbidden", 403)
					return
				}
				f.orderVal[id] = "patched-by-" + who
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(obj("order", id, o, `,"v":"`+f.orderVal[id]+`"`)))
			default:
				http.Error(w, "method not allowed", 405)
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func runVerify(t *testing.T, vulnerable bool) AuthzPipelineResult {
	t.Helper()
	withLoopbackAllowed(t)
	srv := newVerifyApp(vulnerable)
	t.Cleanup(srv.Close)
	a := &Identity{ID: "a", Label: "user-a", IsBaseline: true, Origin: srv.URL, Headers: map[string]string{"Authorization": "Bearer tok-a"}}
	b := &Identity{ID: "b", Label: "user-b", Origin: srv.URL, Headers: map[string]string{"Authorization": "Bearer tok-b"}}
	res := RunAuthzPipeline(context.Background(), AuthzPipelineInput{
		TargetDomain: "127.0.0.1", Origins: []string{srv.URL}, Seeds: []string{srv.URL},
		IdentityA: a, IdentityB: b, Profile: AuthzBalanced})
	t.Logf("(%s) stats=%+v", map[bool]string{true: "vuln", false: "secure"}[vulnerable], res.Stats)
	return res
}

func TestPipelineVulnerable(t *testing.T) {
	res := runVerify(t, true)
	if res.Stats.Ownerships < 4 || res.Stats.PairsGenerated < 4 {
		t.Fatalf("discovery/ownership weak: %+v", res.Stats)
	}
	readOK, patchOK := false, false
	for _, f := range res.Findings {
		if f.Type == "idor" && f.Method == "GET" && strings.HasSuffix(f.URL, "/api/orders/500") && f.AttackerLabel == "user-b" && f.Status == StatusFinding {
			readOK = true
		}
		if f.Type == "bfla" && f.Method == "PATCH" && strings.HasSuffix(f.URL, "/api/orders/500") && f.AttackerLabel == "user-b" && f.Status == StatusFinding {
			patchOK = true
		}
		if strings.Contains(f.Evidence+f.Repro, "tok-a") || strings.Contains(f.Evidence+f.Repro, "tok-b") {
			t.Errorf("token leaked in finding: %+v", f)
		}
	}
	if !readOK || !patchOK {
		t.Fatalf("expected confirmed cross-user READ+PATCH of order 500; read=%v patch=%v", readOK, patchOK)
	}
}

func TestPipelineSecure(t *testing.T) {
	res := runVerify(t, false)
	if res.Stats.PairsGenerated < 4 {
		t.Fatalf("secure app must still discover+pair: %+v", res.Stats)
	}
	if res.Stats.Findings != 0 {
		t.Fatalf("secure app must yield ZERO findings, got %d", res.Stats.Findings)
	}
}
