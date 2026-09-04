package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// scopedBrowserHeaderSession applies auth/compliance headers to existing
// headless-browser traffic without exposing them to third-party scripts,
// iframes, analytics, redirect targets, or the local XSS loader page. The
// returned cleanup must run while the long-lived tab still exists.
func scopedBrowserHeaderSession(runCtx, tabCtx, identityCtx context.Context, scopeURLs []string, explicit map[string]string) ([]chromedp.Action, func()) {
	id, hasIdentity := identityCtx.Value(requestIdentityKey{}).(requestIdentity)
	if !hasIdentity {
		id.headers = make(http.Header)
		for _, rawURL := range scopeURLs {
			id.hosts = appendScopeHosts(id.hosts, rawURL)
		}
	}
	if len(id.hosts) == 0 || (id.userAgent == "" && len(id.headers) == 0 && len(explicit) == 0) {
		return nil, func() {}
	}

	chromedp.ListenTarget(runCtx, func(event any) {
		paused, ok := event.(*fetch.EventRequestPaused)
		if !ok || paused.Request == nil {
			return
		}
		go func() {
			continueRequest := fetch.ContinueRequest(paused.RequestID)
			if entries, apply := scopedBrowserHeaderEntries(id, paused.Request.URL, paused.Request.Headers, explicit); apply {
				continueRequest = continueRequest.WithHeaders(entries)
			}
			_ = chromedp.Run(runCtx, continueRequest)
		}()
	})

	enable := fetch.Enable().WithPatterns([]*fetch.RequestPattern{{
		URLPattern:   "*",
		RequestStage: fetch.RequestStageRequest,
	}})
	cleanup := func() { _ = chromedp.Run(tabCtx, fetch.Disable()) }
	return []chromedp.Action{enable}, cleanup
}

func scopedBrowserHeaderEntries(id requestIdentity, rawURL string, existing network.Headers, explicit map[string]string) ([]*fetch.HeaderEntry, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	req := &http.Request{URL: u}
	if !requestIdentityApplies(id, req) {
		return nil, false
	}

	headers := make(map[string]string, len(existing)+len(explicit)+len(id.headers)+1)
	for rawName, rawValue := range existing {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rawName))
		value := strings.TrimSpace(fmt.Sprint(rawValue))
		if validScanHeader(name, value) {
			headers[name] = value
		}
	}
	// Auth/detector headers deliberately win over browser-generated values.
	for rawName, rawValue := range explicit {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rawName))
		value := strings.TrimSpace(rawValue)
		if strings.EqualFold(name, "Content-Type") || !validScanHeader(name, value) {
			continue
		}
		headers[name] = value
	}
	// Configured custom headers fill gaps; they do not replace an explicit or
	// application-generated header. The dedicated User-Agent override is the one
	// intentional exception and must identify every in-scope browser request.
	for name, values := range id.headers {
		if _, exists := headers[name]; !exists && len(values) > 0 {
			headers[name] = values[0]
		}
	}
	if id.userAgent != "" {
		headers["User-Agent"] = id.userAgent
	}

	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sortStrings(names)
	entries := make([]*fetch.HeaderEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, &fetch.HeaderEntry{Name: name, Value: headers[name]})
	}
	return entries, true
}
