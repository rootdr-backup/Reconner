package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// Network assets (ip/cidr) are not web pages. The page monitor must never build
// a pseudo-URL from one and fetch it — the counting server proves no request is
// made. A regression here means every monitored network range gets a bogus
// https://<range> GET on each watch pass.
func TestMonitorProjectAssetsSkipsNetworkAssets(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>ok</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets(id,target_id,value,kind,asset_type,approval_status,monitor_enabled)
		VALUES(?,?,?,?,?,?,1)`,
		uuid.NewString(), targetID, strings.TrimPrefix(srv.URL, "http://"), "network", "ip", "approved"); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	changed, err := s.monitorProjectAssets(context.Background(), targetID, "", nil,
		map[string]bool{}, map[string]bool{}, logFn)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := hits
	mu.Unlock()
	if changed != 0 || got != 0 {
		t.Fatalf("network asset was monitored: changed=%d requests=%d", changed, got)
	}
}

// The counterpart: a web asset IS monitored (so the kind filter above cannot
// silently starve the whole project-asset monitor path).
func TestMonitorProjectAssetsStillMonitorsWebAssets(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>ok</title></head><body>ok</body></html>`))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets(id,target_id,value,kind,asset_type,approval_status,monitor_enabled)
		VALUES(?,?,?,?,?,?,1)`,
		uuid.NewString(), targetID, srv.URL, "web", "url", "approved"); err != nil {
		t.Fatal(err)
	}

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	if _, err := s.monitorProjectAssets(context.Background(), targetID, "", nil,
		map[string]bool{}, map[string]bool{}, logFn); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := hits
	mu.Unlock()
	if got == 0 {
		t.Fatal("web asset was never fetched — the kind filter is too broad")
	}
}
