package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OpenAPI / Swagger ingestion.
//
// A documented API describes its ENTIRE surface — every path, method, query
// parameter, and request-body field — in one file. Bug-bounty targets expose
// these far more often than people expect (framework defaults: springdoc,
// FastAPI, Swashbuckle, go-swagger, Django REST). Parsing one turns hundreds of
// endpoints a link-following crawler would never reach into testable insertion
// points, feeding the existing parameter pipeline (DAST / reflection / nuclei).

// apiSpecPaths are the conventional locations these documents live at.
var apiSpecPaths = []string{
	"/swagger.json", "/openapi.json",
	"/v2/api-docs", "/v3/api-docs", "/api-docs",
	"/swagger/v1/swagger.json", "/swagger/doc.json",
	"/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
	"/openapi/v3/api-docs", "/api-docs/swagger.json",
}

var pathParamRE = regexp.MustCompile(`\{[^}]+\}`)

// apiEndpoint is one documented operation reduced to what the scanner tests.
type apiEndpoint struct {
	Method string
	URL    string // absolute; path templates ({id}) substituted with a sample value
	Query  []string
	Body   []string
	JSON   bool
}

// harvestAPISpecs probes each in-scope origin for an OpenAPI/Swagger document,
// parses it, and stores its documented query + body parameters so the active
// modules test the real API surface. Returns the number of endpoints ingested.
func (s *ParamScanner) harvestAPISpecs(ctx context.Context, targetID string, targetURLs []string, logFn LogFunc) int {
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: sharedHTTPTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	origins := map[string]bool{}
	for _, u := range targetURLs {
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			origins[p.Scheme+"://"+p.Host] = true
		}
	}

	endpoints, stored := 0, 0
	for origin := range origins {
		if ctx.Err() != nil {
			break
		}
		for _, sp := range apiSpecPaths {
			body := s.fetchSpec(ctx, client, origin+sp)
			if body == nil {
				continue
			}
			eps := parseAPISpec(body, origin)
			if len(eps) == 0 {
				continue
			}
			logFn("info", "param_discovery", fmt.Sprintf("OpenAPI/Swagger spec found at %s%s — %d endpoint(s).", origin, sp, len(eps)))
			for _, ep := range eps {
				endpoints++
				for _, q := range ep.Query {
					sep := "?"
					if strings.Contains(ep.URL, "?") {
						sep = "&"
					}
					if s.storeParameter(targetID, paramEntry{URL: ep.URL + sep + q + "=", Param: q, Value: "", Source: "openapi"}) == nil {
						stored++
					}
				}
				if len(ep.Body) > 0 {
					ct := "application/x-www-form-urlencoded"
					if ep.JSON {
						ct = "application/json"
					}
					method := ep.Method
					if method == "" || method == "GET" {
						method = "POST"
					}
					for _, b := range ep.Body {
						if s.storeFormParameter(targetID, ep.URL, b, method, ct) {
							stored++
						}
					}
				}
			}
			break // one spec per origin is plenty
		}
	}
	if endpoints > 0 {
		logFn("info", "param_discovery", fmt.Sprintf("API-spec harvest: %d endpoint(s) → %d parameter(s) stored.", endpoints, stored))
	}
	return endpoints
}

// fetchSpec GETs a candidate spec URL and returns the body only if it actually
// looks like an OpenAPI/Swagger JSON document (guards against SPA catch-all HTML).
func (s *ParamScanner) fetchSpec(ctx context.Context, client *http.Client, u string) []byte {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	// Must carry a spec marker AND a paths object — otherwise it's not a spec.
	if !bytes.Contains(b, []byte(`"paths"`)) {
		return nil
	}
	if !bytes.Contains(b, []byte(`"swagger"`)) && !bytes.Contains(b, []byte(`"openapi"`)) {
		return nil
	}
	return b
}

// parseAPISpec parses a Swagger 2.0 or OpenAPI 3.x JSON document into endpoints.
// It navigates generic maps defensively (never panics on an unexpected shape) and
// does NOT resolve $ref chains — it extracts what's inline, which covers the vast
// majority of real specs and keeps the parser bounded.
func parseAPISpec(body []byte, origin string) []apiEndpoint {
	var doc map[string]interface{}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	paths := asMap(doc["paths"])
	if paths == nil {
		return nil
	}
	isV3 := strings.HasPrefix(asStr(doc["openapi"]), "3")
	bases := specBaseURLs(doc, origin, isV3)
	methods := map[string]bool{"get": true, "post": true, "put": true, "delete": true, "patch": true}

	var eps []apiEndpoint
	for rawPath, pv := range paths {
		pathItem := asMap(pv)
		if pathItem == nil {
			continue
		}
		// path-level (shared) query parameters
		var sharedQuery []string
		for _, p := range asSlice(pathItem["parameters"]) {
			if pm := asMap(p); pm != nil && asStr(pm["in"]) == "query" {
				if n := asStr(pm["name"]); n != "" {
					sharedQuery = append(sharedQuery, n)
				}
			}
		}
		for m, ov := range pathItem {
			m = strings.ToLower(m)
			if !methods[m] {
				continue
			}
			op := asMap(ov)
			if op == nil {
				continue
			}
			query := append([]string{}, sharedQuery...)
			var body []string
			isJSON := false
			for _, p := range asSlice(op["parameters"]) {
				pm := asMap(p)
				if pm == nil {
					continue
				}
				name := asStr(pm["name"])
				if name == "" {
					continue
				}
				switch asStr(pm["in"]) {
				case "query":
					query = append(query, name)
				case "formData":
					body = append(body, name)
				case "body": // Swagger 2.0 body: schema.properties
					body = append(body, schemaProps(pm["schema"])...)
					isJSON = true
				}
			}
			// OpenAPI 3.x request body
			if rb := asMap(op["requestBody"]); rb != nil {
				for mt, c := range asMap(rb["content"]) {
					if cm := asMap(c); cm != nil {
						body = append(body, schemaProps(cm["schema"])...)
						if strings.Contains(mt, "json") {
							isJSON = true
						}
					}
				}
			}
			for _, base := range bases {
				eps = append(eps, apiEndpoint{
					Method: strings.ToUpper(m),
					URL:    joinAPIURL(base, rawPath),
					Query:  dedupeStrings(query),
					Body:   dedupeStrings(body),
					JSON:   isJSON,
				})
			}
		}
	}
	return eps
}

// specBaseURLs computes the base URL(s) a spec's paths are relative to.
func specBaseURLs(doc map[string]interface{}, origin string, isV3 bool) []string {
	if isV3 {
		var out []string
		for _, sv := range asSlice(doc["servers"]) {
			if u := asStr(asMap(sv)["url"]); u != "" {
				out = append(out, resolveSpecBase(origin, u))
			}
		}
		if len(out) > 0 {
			return out
		}
		return []string{strings.TrimRight(origin, "/")}
	}
	// Swagger 2.0: schemes + host + basePath.
	basePath := strings.TrimRight(asStr(doc["basePath"]), "/")
	host := asStr(doc["host"])
	if host == "" {
		return []string{strings.TrimRight(origin, "/") + basePath}
	}
	scheme := "https"
	if sl := asSlice(doc["schemes"]); len(sl) > 0 {
		if sc := asStr(sl[0]); sc != "" {
			scheme = sc
		}
	}
	return []string{scheme + "://" + host + basePath}
}

func resolveSpecBase(origin, server string) string {
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		return strings.TrimRight(server, "/")
	}
	return strings.TrimRight(origin, "/") + "/" + strings.TrimLeft(server, "/")
}

// joinAPIURL builds a concrete URL, substituting {path-params} with a sample "1"
// so the stored endpoint is fetchable (real IDOR path-param testing is a later
// phase; here we just need a valid URL for query/body parameter testing).
func joinAPIURL(base, path string) string {
	path = pathParamRE.ReplaceAllString(path, "1")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(base, "/") + path
}

func schemaProps(v interface{}) []string {
	sc := asMap(v)
	if sc == nil {
		return nil
	}
	props := asMap(sc["properties"])
	if props == nil {
		return nil
	}
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	return out
}

// small defensive accessors over decoded JSON.
func asMap(v interface{}) map[string]interface{} { m, _ := v.(map[string]interface{}); return m }
func asSlice(v interface{}) []interface{}         { s, _ := v.([]interface{}); return s }
func asStr(v interface{}) string                  { s, _ := v.(string); return s }

func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
