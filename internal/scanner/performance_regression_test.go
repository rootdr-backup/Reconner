package scanner

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMeasureVolatilityReusesFetchedBaseline(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("stable"))
	}))
	defer srv.Close()
	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Value: "1", Method: "GET", Location: "query"}
	volCache.Delete(volKey(ip, "1", nil))
	body, status, elapsed := sendInjectedFull(context.Background(), sqliHTTPClient, ip, "1", nil)
	p := measureVolatilitySeeded(context.Background(), sqliHTTPClient, ip, nil, "1", body, status, elapsed, true)
	if !p.valid || requests.Load() != volSamples {
		t.Fatalf("seeded volatility must keep %d total samples, requests=%d profile=%+v", volSamples, requests.Load(), p)
	}
}

func TestSemanticRouteIdentityKeepsTwoRepresentativesAndQueryShapes(t *testing.T) {
	a := insertionPoint{URL: "https://app.test/orders/1001?id=1&mode=view", Param: "id", Method: "GET", Location: "query"}
	b := insertionPoint{URL: "https://app.test/orders/1002?id=2&mode=view", Param: "id", Method: "GET", Location: "query"}
	c := insertionPoint{URL: "https://app.test/orders/1003?id=3&mode=edit", Param: "id", Method: "GET", Location: "query"}
	ka, na := semanticRouteIdentity(a)
	kb, nb := semanticRouteIdentity(b)
	kc, nc := semanticRouteIdentity(c)
	if !na || !nb || !nc || ka != kb || kb != kc {
		t.Fatalf("numeric value variants with the same query-field shape must share a semantic route: %q %q %q", ka, kb, kc)
	}
	d := insertionPoint{URL: "https://app.test/orders/1004?id=4&action=delete", Param: "id", Method: "GET", Location: "query"}
	kd, _ := semanticRouteIdentity(d)
	if kd == ka {
		t.Fatal("distinct query-field contracts must not be compacted together")
	}

	db, tid := testDB(t)
	defer db.Close()
	for i, ip := range []insertionPoint{a, b, c} {
		_, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,method,content_type,location)
			VALUES (?,?,?,?,?,'GET','','query')`, uuid.New().String(), tid, ip.URL, ip.Param, string(rune('1'+i)))
		if err != nil {
			t.Fatal(err)
		}
	}
	got := loadXSSInsertionPoints(context.Background(), db, tid, 20)
	if len(got) != 2 {
		t.Fatalf("semantic route compaction must retain two representatives, got %d: %+v", len(got), got)
	}
}

func TestContextAwareBrowserPayloadSelection(t *testing.T) {
	full := xssBrowserPayloads()
	double := xssBrowserPayloadsForAnalysis(&ReflectionAnalysis{Context: CtxQuotedAttr, Quote: '"'})
	single := xssBrowserPayloadsForAnalysis(&ReflectionAnalysis{Context: CtxQuotedAttr, Quote: '\''})
	js := xssBrowserPayloadsForAnalysis(&ReflectionAnalysis{Context: CtxJSString, JSQuote: '`'})
	if len(double) >= len(full) || len(single) >= len(full) || len(js) >= len(full) {
		t.Fatalf("classified contexts must use a smaller ladder: full=%d double=%d single=%d js=%d", len(full), len(double), len(single), len(js))
	}
	if !strings.HasPrefix(double[0], `"><`) || !strings.HasPrefix(single[0], `'><`) {
		t.Fatalf("attribute ladder must honor the opening quote: double=%q single=%q", double[0], single[0])
	}
	if !strings.Contains(strings.Join(js, "\n"), "${") {
		t.Fatalf("template-literal context lost its relevant execution vector: %v", js)
	}
}

func TestHostRequestGateBoundsCrossModuleBurst(t *testing.T) {
	host := "performance-gate.test"
	hostThrottles.Delete(host)
	var current, maximum atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < hostMaxInFlight*3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, ok := hostRequestAcquire(context.Background(), host)
			if !ok {
				t.Error("request slot acquisition unexpectedly cancelled")
				return
			}
			cur := current.Add(1)
			for {
				old := maximum.Load()
				if cur <= old || maximum.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			current.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if maximum.Load() > hostMaxInFlight || maximum.Load() < 2 {
		t.Fatalf("shared host burst was not bounded/useful: max=%d ceiling=%d", maximum.Load(), hostMaxInFlight)
	}
}

func TestSecondOrderSQLiBatchesReadback(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	var writes, reads atomic.Int64
	var mu sync.Mutex
	var tokens []string
	hexToken := regexp.MustCompile(`(?i)0x([0-9a-f]{20,})`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/write-a", "/write-b":
			writes.Add(1)
			_ = r.ParseForm()
			payload := r.FormValue(strings.TrimPrefix(r.URL.Path, "/write-"))
			matches := hexToken.FindAllStringSubmatch(payload, -1)
			if len(matches) > 0 {
				raw, _ := hex.DecodeString(matches[len(matches)-1][1])
				mu.Lock()
				tokens = append(tokens, string(raw))
				mu.Unlock()
			}
			_, _ = w.Write([]byte("saved"))
		case "/read":
			reads.Add(1)
			mu.Lock()
			defer mu.Unlock()
			_, _ = w.Write([]byte("XPATH syntax error: '~" + strings.Join(tokens, "~8.0 XPATH syntax error: '~") + "~8.0'"))
		}
	}))
	defer srv.Close()
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,content_type) VALUES (?,?,?,?,?)`, uuid.New().String(), tid, srv.URL+"/read", 200, "text/html")
	candidates := []insertionPoint{
		{URL: srv.URL + "/write-a", Param: "a", Method: "POST", ContentType: "application/x-www-form-urlencoded", Location: "body"},
		{URL: srv.URL + "/write-b", Param: "b", Method: "POST", ContentType: "application/x-www-form-urlencoded", Location: "body"},
	}
	s := &SQLiScanner{db: db}
	var found atomic.Int64
	s.secondOrderChecks(context.Background(), tid, candidates, nil, &found, func(string, string, string) {})
	if found.Load() != 2 {
		t.Fatalf("unique batch tokens must attribute both writes, found=%d", found.Load())
	}
	if writes.Load() != 2 || reads.Load() != 1 {
		t.Fatalf("batching regressed to nested readback: writes=%d reads=%d", writes.Load(), reads.Load())
	}
}
