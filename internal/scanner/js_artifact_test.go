package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchJSArtifactIncludesInScopeContentAndRejectsRedirectEscape(t *testing.T) {
	withLoopbackAllowed(t)
	var escaped atomic.Bool
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		escaped.Store(true)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("window.outside=true"))
	}))
	defer external.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chunk.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("window.inside=true"))
		case "/escape.js":
			http.Redirect(w, r, external.URL+"/outside.js", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()

	// Scope and target use localhost while the redirect destination deliberately
	// uses 127.0.0.1. They reach the same loopback interface but are distinct
	// security hosts, so the redirect must be refused before the second request.
	base := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	body, finalURL, err := FetchJSArtifact(context.Background(), "localhost", base+"/chunk.js")
	if err != nil || string(body) != "window.inside=true" || finalURL != base+"/chunk.js" {
		t.Fatalf("in-scope artifact body=%q final=%q err=%v", body, finalURL, err)
	}
	if _, _, err := FetchJSArtifact(context.Background(), "localhost", base+"/escape.js"); err == nil {
		t.Fatal("out-of-scope JavaScript redirect was accepted")
	}
	if escaped.Load() {
		t.Fatal("redirect escape reached the out-of-scope server")
	}
}
