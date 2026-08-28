package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetaRefreshOpenRedirectDetected(t *testing.T) {
	// Server that redirects to the injected `url` value via a meta-refresh tag
	// (no 3xx Location) — the classic case the header-only walk misses.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0; url=%s"></head></html>`, v)
	}))
	defer ts.Close()
	res, ok := checkOpenRedirectURL(ts.URL+"/?url=x", "url")
	if !ok || res.class != redirectExternal {
		t.Fatalf("expected external meta-refresh redirect, got ok=%v class=%v", ok, res.class)
	}
}

func TestJSLocationOpenRedirectDetected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><script>window.location.href = "%s";</script></body></html>`, v)
	}))
	defer ts.Close()
	res, ok := checkOpenRedirectURL(ts.URL+"/?next=x", "next")
	if !ok || res.class != redirectExternal {
		t.Fatalf("expected external JS redirect, got ok=%v class=%v", ok, res.class)
	}
}

func TestReflectedURLNotAFalsePositive(t *testing.T) {
	// Reflects the injected value in a plain <a href> (NOT a redirect construct)
	// and in visible text — must NOT be flagged as an open redirect.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>You searched for <a href="/local">%s</a></body></html>`, v)
	}))
	defer ts.Close()
	if _, ok := checkOpenRedirectURL(ts.URL+"/?url=x", "url"); ok {
		t.Fatal("reflected-but-not-redirected URL must not be an open-redirect finding")
	}
}

func TestJSONReflectionNotHTMLRedirect(t *testing.T) {
	// A JSON API echoing the value must not be treated as a client-side redirect.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"next":"%s","location":"%s"}`, v, v)
	}))
	defer ts.Close()
	if _, ok := checkOpenRedirectURL(ts.URL+"/?url=x", "url"); ok {
		t.Fatal("JSON reflection must not be an open-redirect finding")
	}
}

func TestRedirectRegexes(t *testing.T) {
	if m := metaRefreshRe.FindSubmatch([]byte(`<meta http-equiv="refresh" content="0;url=https://evil.com/x">`)); m == nil || string(m[1]) != "https://evil.com/x" {
		t.Fatalf("meta refresh regex failed: %v", m)
	}
	for _, js := range []string{
		`window.location.href = "https://evil.com"`,
		`location.replace("//evil.com")`,
		`location = 'https://evil.com/p'`,
	} {
		if m := jsRedirectRe.FindSubmatch([]byte(js)); m == nil {
			t.Fatalf("js redirect regex missed: %s", js)
		}
	}
}
