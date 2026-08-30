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

	"github.com/google/uuid"
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
	Method      string
	URL         string // absolute; path templates ({id}) substituted with a sample value
	Query       []string
	Body        []string
	Path        []apiPathParameter
	JSON        bool
	ContentType string
	BodyTypes   map[string]string
}

type apiPathParameter struct {
	Name  string
	Index int // 0-based segment index in the final absolute URL path
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
				for _, p := range ep.Path {
					method := ep.Method
					if method == "" {
						method = "GET"
					}
					if s.storeParameter(targetID, paramEntry{URL: ep.URL, Param: p.Name, Value: "1", Source: "openapi", Method: method, Location: "path:" + itoa(p.Index)}) == nil {
						stored++
					}
				}
				for _, q := range ep.Query {
					sep := "?"
					if strings.Contains(ep.URL, "?") {
						sep = "&"
					}
					method := ep.Method
					if method == "" {
						method = "GET"
					}
					if s.storeParameter(targetID, paramEntry{URL: ep.URL + sep + q + "=", Param: q, Value: "", Source: "openapi", Method: method, Location: "query"}) == nil {
						stored++
					}
				}
				if len(ep.Body) > 0 {
					ct := ep.ContentType
					if ct == "" {
						ct = "application/x-www-form-urlencoded"
					}
					if ep.JSON && ep.ContentType == "" {
						ct = "application/json"
					}
					method := ep.Method
					if method == "" || method == "GET" {
						method = "POST"
					}
					for _, b := range ep.Body {
						storedOK := false
						if strings.Contains(ct, "json") {
							storedOK = s.storeJSONParameter(targetID, ep.URL, b, ep.BodyTypes[b], method, ct)
						} else {
							storedOK = s.storeFormParameter(targetID, ep.URL, b, method, ct)
						}
						if storedOK {
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
// It navigates generic maps defensively and resolves bounded LOCAL $ref chains
// (#/components/schemas or Swagger #/definitions), which is where most real specs
// keep their request-body properties.
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
	docConsumes := stringSlice(doc["consumes"])
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
			bodyTypes := map[string]string{}
			isJSON := false
			contentType := ""
			consumes := stringSlice(op["consumes"])
			if len(consumes) == 0 {
				consumes = docConsumes
			}
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
					bodyTypes[name] = strings.ToLower(asStr(pm["type"]))
					contentType = preferredRequestContentType(consumes, "application/x-www-form-urlencoded")
				case "body": // Swagger 2.0 body: schema.properties
					body = append(body, schemaPropsResolved(doc, pm["schema"])...)
					mergeStringMap(bodyTypes, schemaPropTypesResolved(doc, pm["schema"], "", 0))
					isJSON = true
					contentType = preferredRequestContentType(consumes, "application/json")
				}
			}
			// OpenAPI 3.x request body
			if rb := asMap(op["requestBody"]); rb != nil {
				for mt, c := range asMap(rb["content"]) {
					if cm := asMap(c); cm != nil {
						props := schemaPropsResolved(doc, cm["schema"])
						body = append(body, props...)
						mergeStringMap(bodyTypes, schemaPropTypesResolved(doc, cm["schema"], "", 0))
						if len(props) > 0 {
							contentType = preferContentType(contentType, mt)
						}
						if strings.Contains(mt, "json") {
							isJSON = true
						}
					}
				}
			}
			for _, base := range bases {
				concreteURL, pathParams := joinAPIURLWithParams(base, rawPath)
				eps = append(eps, apiEndpoint{
					Method:      strings.ToUpper(m),
					URL:         concreteURL,
					Query:       dedupeStrings(query),
					Body:        dedupeStrings(body),
					Path:        pathParams,
					JSON:        isJSON,
					ContentType: contentType,
					BodyTypes:   bodyTypes,
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
	u, _ := joinAPIURLWithParams(base, path)
	return u
}

func joinAPIURLWithParams(base, path string) (string, []apiPathParameter) {
	basePathSegments := 0
	if u, err := url.Parse(base); err == nil {
		basePathSegments = len(nonEmptyPathSegments(u.Path))
	}
	var params []apiPathParameter
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2 {
			name := strings.TrimSpace(segment[1 : len(segment)-1])
			if name != "" {
				params = append(params, apiPathParameter{Name: name, Index: basePathSegments + i})
				segments[i] = "1"
			}
		}
	}
	path = strings.Join(segments, "/")
	path = pathParamRE.ReplaceAllString(path, "1")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(base, "/") + path, params
}

func nonEmptyPathSegments(path string) []string {
	var out []string
	for _, s := range strings.Split(strings.Trim(path, "/"), "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func schemaProps(v interface{}) []string {
	return schemaPropPathsResolved(nil, v, "", 0)
}

func schemaPropsResolved(doc map[string]interface{}, v interface{}) []string {
	return schemaPropPathsResolved(doc, v, "", 0)
}

func schemaPropPathsResolved(doc map[string]interface{}, v interface{}, prefix string, depth int) []string {
	if depth > 5 {
		return nil
	}
	sc := resolveLocalSchemaRef(doc, asMap(v), depth)
	if sc == nil {
		return nil
	}
	props := asMap(sc["properties"])
	if props == nil {
		var out []string
		for _, key := range []string{"allOf", "oneOf", "anyOf"} {
			for _, part := range asSlice(sc[key]) {
				out = append(out, schemaPropPathsResolved(doc, part, prefix, depth+1)...)
			}
		}
		return dedupeStrings(out)
	}
	var out []string
	for name, raw := range props {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		nested := schemaPropPathsResolved(doc, raw, path, depth+1)
		if len(nested) > 0 {
			out = append(out, nested...)
		} else {
			out = append(out, path)
		}
	}
	return out
}

func schemaPropTypesResolved(doc map[string]interface{}, v interface{}, prefix string, depth int) map[string]string {
	out := map[string]string{}
	if depth > 5 {
		return out
	}
	sc := resolveLocalSchemaRef(doc, asMap(v), depth)
	if len(asMap(sc["properties"])) == 0 {
		for _, key := range []string{"allOf", "oneOf", "anyOf"} {
			for _, part := range asSlice(sc[key]) {
				mergeStringMap(out, schemaPropTypesResolved(doc, part, prefix, depth+1))
			}
		}
		return out
	}
	for name, raw := range asMap(sc["properties"]) {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		nested := schemaPropTypesResolved(doc, raw, path, depth+1)
		if len(nested) > 0 {
			mergeStringMap(out, nested)
		} else {
			typ := strings.ToLower(asStr(asMap(raw)["type"]))
			if typ == "" {
				typ = "string"
			}
			out[path] = typ
		}
	}
	return out
}

func resolveLocalSchemaRef(doc, schema map[string]interface{}, depth int) map[string]interface{} {
	if schema == nil || doc == nil || depth > 5 {
		return schema
	}
	ref := asStr(schema["$ref"])
	if !strings.HasPrefix(ref, "#/") {
		return schema
	}
	var cur interface{} = doc
	for _, raw := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		m := asMap(cur)
		if m == nil {
			return schema
		}
		cur = m[part]
	}
	resolved := asMap(cur)
	if resolved == nil {
		return schema
	}
	return resolveLocalSchemaRef(doc, resolved, depth+1)
}

func mergeStringMap(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}

func (s *ParamScanner) storeJSONParameter(targetID, endpoint, name, typ, method, contentType string) bool {
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "" {
		typ = "string"
	}
	value := ""
	switch typ {
	case "integer", "number":
		value = "1"
	case "boolean", "bool":
		value = "true"
	case "object":
		value = "{}"
	case "array":
		value = "[]"
	}
	_, err := s.db.Exec(`
		INSERT INTO parameters (id,target_id,url,parameter,value,source,method,content_type,location)
		VALUES (?,?,?,?,?,'openapi',?,?,?)
		ON CONFLICT(target_id,url,parameter,method,location,content_type) DO UPDATE SET value=excluded.value`,
		uuid.New().String(), targetID, endpoint, name, value, method, contentType, "json:"+typ)
	return err == nil
}

// small defensive accessors over decoded JSON.
func asMap(v interface{}) map[string]interface{} { m, _ := v.(map[string]interface{}); return m }
func asSlice(v interface{}) []interface{}        { s, _ := v.([]interface{}); return s }
func asStr(v interface{}) string                 { s, _ := v.(string); return s }

func stringSlice(v interface{}) []string {
	var out []string
	for _, item := range asSlice(v) {
		if s := strings.ToLower(strings.TrimSpace(asStr(item))); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func preferredRequestContentType(values []string, fallback string) string {
	chosen := ""
	for _, v := range values {
		chosen = preferContentType(chosen, v)
	}
	if chosen == "" {
		return fallback
	}
	return chosen
}

func preferContentType(current, candidate string) string {
	candidate = strings.ToLower(candidate)
	rank := func(v string) int {
		switch {
		case strings.Contains(v, "json"):
			return 4
		case strings.Contains(v, "multipart/form-data"):
			return 3
		case strings.Contains(v, "xml"):
			return 2
		case strings.Contains(v, "x-www-form-urlencoded"):
			return 1
		default:
			return 0
		}
	}
	if rank(candidate) > rank(current) {
		return candidate
	}
	return current
}

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
