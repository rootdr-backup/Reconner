package scanner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"golang.org/x/net/http/httpguts"
)

type requestIdentityKey struct{}
type skipRequestIdentityKey struct{}

type requestIdentity struct {
	userAgent string
	headers   http.Header
	hosts     []string
}

// WithTargetRequestIdentity loads the effective global + per-target request
// identity once per module. Target settings override global settings. Approved
// assets are also loaded so credentials/compliance headers are never forwarded
// to an unrelated host reached through a redirect or passive-intel API.
func WithTargetRequestIdentity(ctx context.Context, db *database.DB, cfg *config.Config, targetID string) context.Context {
	id := requestIdentity{headers: make(http.Header)}
	if cfg != nil {
		id.userAgent = strings.TrimSpace(cfg.ScanUserAgent)
		mergeIdentityHeaders(id.headers, cfg.ScanHeaders)
	}
	var domain, targetUA, rawHeaders string
	if db != nil {
		err := db.QueryRowContext(ctx, `SELECT domain,COALESCE(scan_user_agent,''),COALESCE(scan_headers,'{}') FROM targets WHERE id=?`, targetID).
			Scan(&domain, &targetUA, &rawHeaders)
		if err != nil {
			// Compatibility with a database opened before the new migration.
			_ = db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)
		} else {
			if strings.TrimSpace(targetUA) != "" {
				id.userAgent = strings.TrimSpace(targetUA)
			}
			var targetHeaders map[string]string
			if json.Unmarshal([]byte(rawHeaders), &targetHeaders) == nil {
				mergeIdentityHeaders(id.headers, targetHeaders)
			}
		}
		rows, err := db.QueryContext(ctx, `SELECT value FROM assets WHERE target_id=? AND COALESCE(approval_status,'approved')='approved'`, targetID)
		if err == nil {
			for rows.Next() {
				var value string
				if rows.Scan(&value) == nil {
					id.hosts = appendScopeHosts(id.hosts, value)
				}
			}
			rows.Close()
		}
	}
	id.hosts = appendScopeHosts(id.hosts, domain)
	return context.WithValue(ctx, requestIdentityKey{}, id)
}

func mergeIdentityHeaders(dst http.Header, src map[string]string) {
	for name, value := range src {
		name, value = http.CanonicalHeaderKey(strings.TrimSpace(name)), strings.TrimSpace(value)
		if validScanHeader(name, value) {
			dst.Set(name, value)
		}
	}
}

func validScanHeader(name, value string) bool {
	if name == "" || value == "" || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
		return false
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-authenticate", "proxy-connection", "keep-alive", "te", "trailer", "upgrade":
		return false
	}
	return true
}

func appendScopeHosts(dst []string, scope string) []string {
	seen := make(map[string]bool, len(dst)+1)
	for _, host := range dst {
		seen[host] = true
	}
	appendToken := func(token string) {
		token = strings.TrimSpace(strings.TrimPrefix(token, "*."))
		if u, err := url.Parse(token); err == nil && u.Hostname() != "" {
			token = u.Hostname()
		} else if host, _, err := net.SplitHostPort(token); err == nil {
			token = host
		} else {
			token = strings.Trim(token, "[]")
		}
		token = strings.ToLower(strings.TrimSuffix(token, "."))
		if token != "" && net.ParseIP(token) == nil && strings.Contains(token, "/") {
			return // CIDRs are not HTTP host identities.
		}
		if token != "" && !seen[token] {
			seen[token] = true
			dst = append(dst, token)
		}
	}

	trimmed := strings.TrimSpace(scope)
	if isSingleHTTPURLSeed(trimmed) {
		appendToken(trimmed)
		return dst
	}
	for _, token := range strings.FieldsFunc(scope, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		appendToken(token)
	}
	return dst
}

func requestIdentityApplies(id requestIdentity, req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	hosts := []string{req.URL.Hostname()}
	// Direct-origin and virtual-host probes intentionally dial an IP while using
	// the approved target as the HTTP Host. Treat that explicit Host as the scope
	// identity so compliant headers are not silently dropped from those probes.
	if req.Host != "" {
		if u, err := url.Parse("//" + req.Host); err == nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	for _, candidate := range hosts {
		host := strings.ToLower(strings.TrimSuffix(candidate, "."))
		for _, allowed := range id.hosts {
			if host == allowed || (net.ParseIP(host) == nil && net.ParseIP(allowed) == nil && strings.HasSuffix(host, "."+allowed)) {
				return true
			}
		}
	}
	return false
}

// requestURLInTargetScope is the non-credential-leaking scope predicate used by
// code that must attach explicit auth headers before the transport runs. It
// understands multi-asset targets and exact URL seeds; URLInScope historically
// accepted only one domain string and therefore rejected every comma-separated
// project (or could not safely protect a direct module invocation).
func requestURLInTargetScope(ctx context.Context, fallbackScope, rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return false
	}
	if id, ok := ctx.Value(requestIdentityKey{}).(requestIdentity); ok && len(id.hosts) > 0 {
		return requestIdentityApplies(id, &http.Request{URL: u})
	}
	fallback := requestIdentity{hosts: appendScopeHosts(nil, fallbackScope)}
	return requestIdentityApplies(fallback, &http.Request{URL: u})
}

// ApplyRequestIdentity returns a safe clone with the configured identity. It is
// also useful for the few custom transports which cannot use scanHTTPTransport.
func ApplyRequestIdentity(req *http.Request) *http.Request {
	if req == nil {
		return req
	}
	if skip, _ := req.Context().Value(skipRequestIdentityKey{}).(bool); skip {
		return req
	}
	id, ok := req.Context().Value(requestIdentityKey{}).(requestIdentity)
	if !ok || !requestIdentityApplies(id, req) {
		return req
	}
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	if id.userAgent != "" {
		clone.Header.Set("User-Agent", id.userAgent)
	}
	for name, values := range id.headers {
		if clone.Header.Get(name) != "" || strings.EqualFold(name, "User-Agent") {
			continue // detector/auth-specific headers deliberately win.
		}
		for _, value := range values {
			clone.Header.Add(name, value)
		}
	}
	return clone
}

// SkipRequestIdentity preserves probes where User-Agent itself is the payload
// (header SQLi and Shellshock). Other requests must not bypass compliance.
func SkipRequestIdentity(req *http.Request) *http.Request {
	if req == nil {
		return req
	}
	return req.WithContext(context.WithValue(req.Context(), skipRequestIdentityKey{}, true))
}

type identityRoundTripper struct{ base http.RoundTripper }

func (t identityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(ApplyRequestIdentity(req))
}

// ToolRequestIdentityArgs maps the effective identity to each target-facing
// subprocess. Arguments are individual argv entries, never shell fragments.
func ToolRequestIdentityArgs(ctx context.Context, tool string) []string {
	headers := RequestIdentityHeaders(ctx, nil)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sortStrings(names)
	serialized := make([]string, 0, len(names))
	for _, name := range names {
		value := headers[name]
		if !validScanHeader(name, value) {
			continue
		}
		serialized = append(serialized, name+": "+value)
	}
	if len(serialized) == 0 {
		return nil
	}

	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "hakrawler" {
		// hakrawler accepts all custom headers in one argument separated by (;;).
		return []string{"-h", strings.Join(serialized, ";;")}
	}
	var flag string
	switch tool {
	case "httpx", "nuclei", "katana", "feroxbuster":
		flag = "-H"
	case "dalfox", "dirsearch":
		flag = "--header"
	default:
		return nil // Never send target identity to passive provider tools.
	}
	args := make([]string, 0, len(serialized)*2)
	for _, header := range serialized {
		args = append(args, flag, header)
	}
	return args
}

// RequestIdentityHeaders returns a copy suitable for subprocesses which accept
// a single combined header block (notably sqlmap). Explicit detector/auth
// headers win, except the dedicated compliance User-Agent override.
func RequestIdentityHeaders(ctx context.Context, explicit map[string]string) map[string]string {
	out := make(map[string]string, len(explicit)+4)
	for name, value := range explicit {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if validScanHeader(name, value) {
			out[name] = value
		}
	}
	id, ok := ctx.Value(requestIdentityKey{}).(requestIdentity)
	if !ok {
		return out
	}
	for name, values := range id.headers {
		if _, exists := out[name]; !exists && len(values) > 0 {
			out[name] = values[0]
		}
	}
	if id.userAgent != "" {
		out["User-Agent"] = id.userAgent
	}
	return out
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// BrowserRequestHeaders merges compliance identity into headless-browser
// headers without overwriting an explicit detector/auth header.
func BrowserRequestHeaders(ctx context.Context, explicit map[string]string) map[string]any {
	out := make(map[string]any, len(explicit)+4)
	for k, v := range explicit {
		if validScanHeader(k, v) && !strings.EqualFold(k, "content-type") {
			out[k] = v
		}
	}
	id, ok := ctx.Value(requestIdentityKey{}).(requestIdentity)
	if !ok {
		return out
	}
	if id.userAgent != "" {
		out["User-Agent"] = id.userAgent
	}
	for k, values := range id.headers {
		if _, exists := out[k]; !exists && len(values) > 0 {
			out[k] = values[0]
		}
	}
	return out
}
