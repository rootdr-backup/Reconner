package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestWebBehaviorV33_403TechniqueMatrix(t *testing.T) {
	withLoopbackAllowed(t)
	cases := []struct {
		name  string
		allow func(*http.Request) bool
		want  string
	}{
		{"forwarded-uri", func(r *http.Request) bool { return r.Header.Get("X-Forwarded-Uri") == "/admin" }, "X-Forwarded-Uri"},
		{"true-client-ip", func(r *http.Request) bool { return r.Header.Get("True-Client-IP") == "127.0.0.1" }, "True-Client-IP"},
		{"forwarded-chain", func(r *http.Request) bool { return strings.Contains(r.Header.Get("X-Forwarded-For"), ",") }, "proxy"},
		{"matrix-path", func(r *http.Request) bool { return strings.Contains(r.RequestURI, ";/") }, "path_suffix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.allow(r) {
					fmt.Fprint(w, `{"admin":true,"secret":"stable-local-proof","navigation":"audit events and settings"}`)
					return
				}
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "forbidden access control wall for local matrix validation")
			}))
			defer srv.Close()
			method, evidence, _, _ := check403Bypass(context.Background(), srv.URL+"/admin")
			if !strings.Contains(method, tc.want) || !strings.Contains(evidence, "403/403") {
				t.Fatalf("technique=%q evidence=%q, want %q with stable proof", method, evidence, tc.want)
			}
		})
	}
}

func TestWebBehaviorV33_HostOverrideAndSinkMatrix(t *testing.T) {
	withLoopbackAllowed(t)
	cases := []struct {
		name string
		host func(*http.Request) string
		sink func(http.ResponseWriter, string)
	}{
		{"http-host-override-content-location", func(r *http.Request) string { return r.Header.Get("X-HTTP-Host-Override") }, func(w http.ResponseWriter, h string) { w.Header().Set("Content-Location", "https://"+h+"/reset") }},
		{"original-host-link", func(r *http.Request) string { return r.Header.Get("X-Original-Host") }, func(w http.ResponseWriter, h string) { w.Header().Set("Link", "<https://"+h+"/reset>; rel=canonical") }},
		{"forwarded-refresh", func(r *http.Request) string { return strings.TrimPrefix(r.Header.Get("Forwarded"), "host=") }, func(w http.ResponseWriter, h string) { w.Header().Set("Refresh", "0; url=https://"+h+"/login") }},
		{"original-url-structured-body", func(r *http.Request) string { p, _ := url.Parse(r.Header.Get("X-Original-URL")); return p.Host }, func(w http.ResponseWriter, h string) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"reset_url":"https://%s/reset"}`, h)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := tc.host(r)
				if strings.HasPrefix(host, "rcnhh") && strings.HasSuffix(host, ".example") {
					tc.sink(w, host)
					return
				}
				fmt.Fprint(w, "normal local response")
			}))
			defer srv.Close()
			evidence, _, _ := checkHostHeaderWithAuth(context.Background(), srv.URL+"/forgot-password", nil)
			if evidence == "" {
				t.Fatal("host override sink was missed")
			}
		})
	}
}

func TestWebBehaviorV33_CRLFDecodeChainMatrix(t *testing.T) {
	withLoopbackAllowed(t)
	for _, signature := range []string{"%250d%250a", "%25250d%25250a"} {
		t.Run(signature, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(strings.ToLower(r.RequestURI), signature) {
					fmt.Fprint(w, "no split")
					return
				}
				value := r.URL.Query().Get("next")
				for i := 0; i < 3 && !strings.Contains(value, "\n"); i++ {
					value, _ = url.QueryUnescape(value)
				}
				if i := strings.IndexByte(value, '\n'); i >= 0 {
					parts := strings.SplitN(strings.TrimSpace(value[i+1:]), ":", 2)
					if len(parts) == 2 && strings.HasPrefix(parts[0], "X-Recon-") {
						w.Header().Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
					}
				}
				fmt.Fprint(w, "ok")
			}))
			defer srv.Close()
			db, targetID := newV3ScannerDB(t)
			seedV3Parameter(t, db, targetID, srv.URL+"/download?next=home", "next", "home", "GET", "", "query")
			cfg := &config.Config{}
			if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
				RunCRLF(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
				t.Fatal(err)
			}
			var count int
			_ = db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='crlf' AND status='CONFIRMED'`, targetID).Scan(&count)
			if count != 1 {
				t.Fatalf("confirmed CRLF findings=%d, want 1", count)
			}
		})
	}
}

func TestWebBehaviorV33_PrototypeUsesAuthenticatedParameterRoutes(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-v33" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"query":%q}`, r.URL.RawQuery)
	}))
	defer srv.Close()
	db, targetID := newV3ScannerDB(t)
	_, _ = db.Exec(`UPDATE targets SET auth_headers='{"Authorization":"Bearer local-v33"}' WHERE id=?`, targetID)
	seedV3Parameter(t, db, targetID, srv.URL+"/merge?source=local", "source", "local", "GET", "", "query")
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		RunPrototypePollution(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var candidates int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='prototype_pollution' AND status='candidate'`, targetID).Scan(&candidates)
	if candidates != 1 {
		t.Fatalf("authenticated parameter-only prototype candidates=%d, want 1", candidates)
	}
}

func TestWebBehaviorV33_PrototypeJSONTopLevelDualProof(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer local-json" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response := map[string]any{"saved": true}
		if proto, ok := body["__proto__"].(map[string]any); ok {
			for key, value := range proto {
				response[key] = value // local fixture models inherited top-level enumeration
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()
	db, targetID := newV3ScannerDB(t)
	_, _ = db.Exec(`UPDATE targets SET auth_headers='{"Authorization":"Bearer local-json"}' WHERE id=?`, targetID)
	seedV3Parameter(t, db, targetID, srv.URL+"/profile", "displayName", "alice", "POST", "application/json", "json")
	seedV3Parameter(t, db, targetID, srv.URL+"/profile", "tenant", "local", "POST", "application/json", "json")
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		RunPrototypePollution(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var confirmed int
	_ = db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='prototype_pollution' AND status='CONFIRMED'`, targetID).Scan(&confirmed)
	if confirmed != 1 {
		t.Fatalf("confirmed JSON prototype findings=%d, want 1", confirmed)
	}
}

func TestWebBehaviorV33_CacheDelimiterAndJSONProof(t *testing.T) {
	withLoopbackAllowed(t)
	var cached sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "notreal") {
			http.NotFound(w, r)
			return
		}
		isDelimiter := strings.Contains(r.RequestURI, ";rcndeception") && strings.HasSuffix(r.URL.Path, ".css")
		_, wasCached := cached.Load(r.RequestURI)
		if r.Header.Get("Cookie") != "session=v33" && !(isDelimiter && wasCached) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"login required"}`)
			return
		}
		if !isDelimiter && r.URL.Path != "/account" {
			http.NotFound(w, r)
			return
		}
		if isDelimiter && r.Header.Get("Cookie") == "session=v33" {
			cached.Store(r.RequestURI, true)
		}
		if isDelimiter && r.Header.Get("Cookie") == "" && wasCached {
			w.Header().Set("Cache-Status", "local-cache; hit")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"account":"alice","token":"local-sensitive-value"}`)
	}))
	defer srv.Close()
	s := newCacheDecScanner(t)
	_, _ = s.db.Exec(`INSERT INTO targets (id,domain,auth_headers) VALUES ('v33','local.test','{"Cookie":"session=v33"}')`)
	_, _ = s.db.Exec(`INSERT INTO http_services (id,target_id,url,status_code) VALUES (?,?,?,200)`, uuid.NewString(), "v33", srv.URL+"/account")
	if err := s.RunCacheDeception(context.Background(), "v33", func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if findings := cacheDecFindings(t, s, "v33"); len(findings) != 1 {
		t.Fatalf("delimiter/JSON cache deception findings=%v, want exactly one", findings)
	}
}

func TestWebBehaviorV33_ParallelLatencyGate(t *testing.T) {
	withLoopbackAllowed(t)
	var active, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "stable local negative control")
	}))
	defer srv.Close()
	db, targetID := newV3ScannerDB(t)
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,200,'probe')`, uuid.NewString(), targetID, srv.URL+"/route")
	seedV3Parameter(t, db, targetID, srv.URL+"/route?q=local", "q", "local", "GET", "", "query")
	cfg := &config.Config{}
	start := time.Now()
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, "local.test", func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if peak.Load() < 8 {
		t.Fatalf("peak request concurrency=%d, want >=8", peak.Load())
	}
	if elapsed > 350*time.Millisecond {
		t.Fatalf("parallel local behavior matrix took %s, want <=350ms", elapsed)
	}
}

func TestWebBehaviorV33_NegativeControls(t *testing.T) {
	withLoopbackAllowed(t)
	t.Run("bare-host-reflection-is-not-a-sink", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "debug host=%s forwarded=%s", r.Host, r.Header.Get("X-Forwarded-Host"))
		}))
		defer srv.Close()
		if evidence, _, _ := checkHostHeaderWithAuth(context.Background(), srv.URL, nil); evidence != "" {
			t.Fatalf("bare diagnostic reflection promoted: %s", evidence)
		}
	})

	t.Run("cache-hit-for-pass-and-miss-are-not-hits", func(t *testing.T) {
		for _, header := range []http.Header{
			{"X-Cache": {"HIT-FOR-PASS"}},
			{"Cache-Status": {"edge; fwd=uri-miss"}},
			{"CF-Cache-Status": {"DYNAMIC"}},
			{"Age": {"0"}},
		} {
			if cacheServedFromCache(header) {
				t.Fatalf("non-hit cache signal accepted: %v", header)
			}
		}
	})

	t.Run("unstable-forbidden-baseline-is-rejected", func(t *testing.T) {
		var baselines atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
				fmt.Fprint(w, "stable private content that is deliberately longer than thirty two bytes")
				return
			}
			w.WriteHeader(http.StatusForbidden)
			isControl := r.RequestURI == "/admin" && r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("X-Real-IP") == "" &&
				r.Header.Get("X-Original-URL") == "" && r.Header.Get("X-Rewrite-URL") == "" &&
				r.Header.Get("X-Forwarded-Uri") == "" && r.Header.Get("X-Custom-IP-Authorization") == "" &&
				r.Header.Get("X-Originating-IP") == "" && r.Header.Get("X-Client-IP") == "" &&
				r.Header.Get("Forwarded") == "" && r.Header.Get("True-Client-IP") == ""
			if isControl && baselines.Add(1) > 1 {
				fmt.Fprint(w, strings.Repeat("changed-wall-", 20))
				return
			}
			fmt.Fprint(w, "first forbidden wall")
		}))
		defer srv.Close()
		if method, _, _, _ := check403Bypass(context.Background(), srv.URL+"/admin"); method != "" {
			t.Fatalf("unstable baseline promoted via %s", method)
		}
	})

	t.Run("route-value-variants-are-deduplicated", func(t *testing.T) {
		got := dedupeWebBehaviorURLs([]string{
			"https://example.test/search?q=one&page=1",
			"https://example.test/search?page=2&q=two",
			"https://example.test/search?q=three",
		})
		if len(got) != 2 {
			t.Fatalf("deduped routes=%v, want two distinct query shapes", got)
		}
	})

	t.Run("cache-variants-preserve-query-and-mutate-path", func(t *testing.T) {
		variants := cacheDeceptionVariants("https://example.test/account/view?tab=billing", "abc")
		if len(variants) != 6 {
			t.Fatalf("cache variants=%d, want 6", len(variants))
		}
		for _, raw := range variants {
			parsed, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("invalid cache variant %q: %v", raw, err)
			}
			if parsed.Query().Get("tab") != "billing" {
				t.Fatalf("cache variant lost original query: %q", raw)
			}
			if !strings.Contains(strings.ToLower(parsed.EscapedPath()), "rcndeceptionabc.css") {
				t.Fatalf("cache variant did not mutate path: %q", raw)
			}
		}
	})
}
