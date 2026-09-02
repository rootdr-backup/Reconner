package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMonitorDoesNotFollowCrossHostRedirect(t *testing.T) {
	var externalHits atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalHits.Add(1)
		_, _ = w.Write([]byte("out of scope"))
	}))
	defer external.Close()
	externalURL := strings.Replace(external.URL, "127.0.0.1", "localhost", 1)
	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, externalURL+"/login", http.StatusFound)
	}))
	defer inScope.Close()

	s := &MonitorScanner{}
	status, _, _, _, err := s.fetchBody(context.Background(), inScope.URL)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusFound {
		t.Fatalf("status=%d, want original redirect", status)
	}
	if got := externalHits.Load(); got != 0 {
		t.Fatalf("monitor followed an out-of-scope redirect %d time(s)", got)
	}
}
