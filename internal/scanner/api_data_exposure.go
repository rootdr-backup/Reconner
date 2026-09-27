package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// APIDataExposureScanner joins four inventories that used to be isolated:
// JavaScript request parameters, live API endpoints, request contracts and
// unauthenticated response schemas. It is intentionally read-oriented. POST is
// used only when the application advertises/observes it on a read-like route;
// PUT/PATCH/DELETE are never negotiated automatically.
type APIDataExposureScanner struct {
	db        *database.DB
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewAPIDataExposureScanner(db *database.DB, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *APIDataExposureScanner {
	return &APIDataExposureScanner{db: db, cfg: cfg, logger: log, broadcast: broadcast}
}

var apiDataExposureClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type apiDataEndpoint struct {
	URL          string
	Status       int
	ContentType  string
	Source       string
	Methods      map[string]bool
	ContentTypes map[string]bool
	Params       map[string]int
}

type apiDataProbe struct {
	Method      string
	URL         string
	ContentType string
	Parameter   string
	Value       string
}

type apiDataResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type sensitiveSummary struct {
	Classes     map[string]int
	Paths       map[string]int
	Records     int
	Fingerprint string
	Severity    string
}

func (s *APIDataExposureScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	if s.db == nil {
		return fmt.Errorf("api data exposure: nil database")
	}
	cfg := s.cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	ctx = WithTargetRequestIdentity(ctx, s.db, cfg, targetID)
	var domain string
	if err := s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain); err != nil {
		return fmt.Errorf("api data exposure target: %w", err)
	}

	endpoints, globalParams, err := s.loadAPIDataSurface(ctx, targetID, cfg)
	if err != nil {
		return err
	}
	if len(endpoints) == 0 {
		logFn("info", "api_data_exposure", "No eligible API/read endpoints were discovered.")
		return nil
	}
	logFn("info", "api_data_exposure", fmt.Sprintf("Correlating %d API endpoints with %d high-signal JavaScript/request parameters...", len(endpoints), len(globalParams)))

	jobs := make(chan *apiDataEndpoint)
	var wg sync.WaitGroup
	var findingCount, requestCount atomic.Int64
	workers := 6
	if len(endpoints) < workers {
		workers = len(endpoints)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				if ctx.Err() != nil {
					return
				}
				found, sent := s.scanAPIDataEndpoint(ctx, targetID, domain, ep, globalParams)
				requestCount.Add(int64(sent))
				if found {
					findingCount.Add(1)
				}
			}
		}()
	}
	for _, ep := range endpoints {
		select {
		case jobs <- ep:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	logFn("info", "api_data_exposure", fmt.Sprintf("API data-exposure workflow complete: %d bounded requests, %d replay-confirmed findings.", requestCount.Load(), findingCount.Load()))
	return ctx.Err()
}

func (s *APIDataExposureScanner) loadAPIDataSurface(ctx context.Context, targetID string, cfg *config.Config) ([]*apiDataEndpoint, []string, error) {
	limit := cfg.URLLimit()
	if limit > 2000 {
		limit = 2000
	}
	byURL := map[string]*apiDataEndpoint{}
	get := func(raw string) *apiDataEndpoint {
		ep := byURL[raw]
		if ep == nil {
			ep = &apiDataEndpoint{URL: raw, Methods: map[string]bool{}, ContentTypes: map[string]bool{}, Params: map[string]int{}}
			byURL[raw] = ep
		}
		return ep
	}

	rows, err := s.db.QueryContext(ctx, `SELECT url,COALESCE(status_code,0),COALESCE(content_type,''),COALESCE(source,'')
		FROM http_services WHERE target_id=? ORDER BY url LIMIT ?`, targetID, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("api data exposure services: %w", err)
	}
	for rows.Next() {
		var raw, ct, source string
		var status int
		if rows.Scan(&raw, &status, &ct, &source) != nil || !eligibleAPIDataURL(raw, status, ct, source) {
			continue
		}
		ep := get(raw)
		ep.Status, ep.ContentType, ep.Source = status, ct, source
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT url,parameter,COALESCE(source,''),UPPER(COALESCE(method,'GET')),
		COALESCE(content_type,''),COALESCE(location,'query') FROM parameters
		WHERE target_id=? ORDER BY url,parameter LIMIT ?`, targetID, limit*8)
	if err != nil {
		return nil, nil, fmt.Errorf("api data exposure parameters: %w", err)
	}
	for rows.Next() {
		var raw, param, source, method, ct, location string
		if rows.Scan(&raw, &param, &source, &method, &ct, &location) != nil || !validHTTPURL(raw) {
			continue
		}
		if byURL[raw] == nil && !eligibleParameterAPIURL(raw, source, method, ct, location) {
			continue
		}
		ep := get(raw)
		ep.Methods[method] = true
		if normalized := normalizeProbeContentType(ct); normalized != "" {
			ep.ContentTypes[normalized] = true
		}
		ep.Params[param] = maxInt(ep.Params[param], apiParameterScore(param, source, location))
	}
	rows.Close()

	globalScores := map[string]int{}
	rows, err = s.db.QueryContext(ctx, `SELECT value,COALESCE(context,'') FROM js_findings
		WHERE target_id=? AND type IN ('api_param','dom_param') LIMIT 5000`, targetID)
	if err == nil {
		for rows.Next() {
			var name, source string
			if rows.Scan(&name, &source) == nil {
				globalScores[name] = maxInt(globalScores[name], apiParameterScore(name, "js:"+source, "body"))
			}
		}
		rows.Close()
	}

	for _, ep := range byURL {
		for name, score := range ep.Params {
			globalScores[name] = maxInt(globalScores[name], score)
		}
	}
	globalParams := topScoredParams(globalScores, 12)

	endpoints := make([]*apiDataEndpoint, 0, len(byURL))
	for _, ep := range byURL {
		if !requestURLInTargetScope(ctx, "", ep.URL) || isStaticAssetURL(ep.URL) {
			continue
		}
		endpoints = append(endpoints, ep)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpointDataScore(endpoints[i]) > endpointDataScore(endpoints[j])
	})
	if len(endpoints) > limit {
		endpoints = endpoints[:limit]
	}
	return endpoints, globalParams, nil
}

func (s *APIDataExposureScanner) scanAPIDataEndpoint(ctx context.Context, targetID, domain string, ep *apiDataEndpoint, global []string) (bool, int) {
	if !requestURLInTargetScope(ctx, domain, ep.URL) {
		return false, 0
	}
	params := mergeEndpointParams(ep, global, 4)
	sent := 0

	baseline := apiDataProbe{Method: http.MethodGet, URL: ep.URL}
	baseResp, err := s.doAPIDataProbe(ctx, baseline)
	sent++
	if err == nil {
		if s.confirmAndStoreAPIDataExposure(ctx, targetID, baseline, baseResp) {
			return true, sent + 1
		}
	}

	// GET parameter correlation is the cheapest branch and cannot mutate server
	// state. Probe only the top request-vocabulary names and stop after proof.
	if baseResp.Status != http.StatusMethodNotAllowed && baseResp.Status != http.StatusNotImplemented {
		for _, param := range params {
			probe := apiDataProbe{Method: http.MethodGet, URL: ep.URL, Parameter: param, Value: safeAPIProbeValue(param)}
			resp, probeErr := s.doAPIDataProbe(ctx, probe)
			sent++
			if probeErr == nil && s.confirmAndStoreAPIDataExposure(ctx, targetID, probe, resp) {
				return true, sent + 1
			}
		}
	}

	allow := parseMethodSet(baseResp.Header.Get("Allow"))
	postObserved := ep.Methods[http.MethodPost]
	if baseResp.Status == http.StatusMethodNotAllowed && len(allow) == 0 {
		optionsResp, optionsErr := s.doAPIDataProbe(ctx, apiDataProbe{Method: http.MethodOptions, URL: ep.URL})
		sent++
		if optionsErr == nil {
			allow = parseMethodSet(optionsResp.Header.Get("Allow"))
		}
	}
	if (!postObserved && !allow[http.MethodPost]) || !readLikeAPIPath(ep.URL) {
		return false, sent
	}

	contentTypes := orderedProbeContentTypes(ep)
	postParams := append([]string{""}, params...)
	for _, param := range postParams {
		for _, ct := range contentTypes {
			probe := apiDataProbe{Method: http.MethodPost, URL: ep.URL, ContentType: ct, Parameter: param, Value: safeAPIProbeValue(param)}
			resp, probeErr := s.doAPIDataProbe(ctx, probe)
			sent++
			if probeErr != nil {
				continue
			}
			if s.confirmAndStoreAPIDataExposure(ctx, targetID, probe, resp) {
				return true, sent + 1
			}
			if resp.Status == http.StatusUnsupportedMediaType {
				if advertised := advertisedProbeContentType(resp.Header.Get("Accept-Post")); advertised != "" && advertised != ct {
					alt := probe
					alt.ContentType = advertised
					altResp, altErr := s.doAPIDataProbe(ctx, alt)
					sent++
					if altErr == nil && s.confirmAndStoreAPIDataExposure(ctx, targetID, alt, altResp) {
						return true, sent + 1
					}
				}
			}
		}
	}
	return false, sent
}

func (s *APIDataExposureScanner) doAPIDataProbe(ctx context.Context, probe apiDataProbe) (apiDataResponse, error) {
	var out apiDataResponse
	requestURL := probe.URL
	var body io.Reader
	if probe.Method == http.MethodGet && probe.Parameter != "" {
		u, err := url.Parse(requestURL)
		if err != nil {
			return out, err
		}
		q := u.Query()
		q.Set(probe.Parameter, probe.Value)
		u.RawQuery = q.Encode()
		requestURL = u.String()
	} else if probe.Method == http.MethodPost {
		switch probe.ContentType {
		case "application/x-www-form-urlencoded":
			values := url.Values{}
			if probe.Parameter != "" {
				values.Set(probe.Parameter, probe.Value)
			}
			body = strings.NewReader(values.Encode())
		default:
			payload := map[string]string{}
			if probe.Parameter != "" {
				payload[probe.Parameter] = probe.Value
			}
			encoded, _ := json.Marshal(payload)
			body = bytes.NewReader(encoded)
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, probe.Method, requestURL, body)
	if err != nil {
		return out, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner-DataExposure/1.0)")
	req.Header.Set("Accept", "application/json, application/problem+json;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	if probe.Method == http.MethodPost {
		ct := probe.ContentType
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	// Keep non-secret program attribution, but never inherit Cookie,
	// Authorization, session, CSRF or token-like identity headers.
	req = ApplyUnauthenticatedRequestIdentity(req)
	resp, err := apiDataExposureClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if readErr != nil {
		return out, readErr
	}
	return apiDataResponse{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: bodyBytes}, nil
}

func (s *APIDataExposureScanner) confirmAndStoreAPIDataExposure(ctx context.Context, targetID string, probe apiDataProbe, first apiDataResponse) bool {
	if first.Status < 200 || first.Status >= 300 {
		return false
	}
	summary, ok := inspectSensitiveJSON(first.Body, first.Header.Get("Content-Type"), probe.URL)
	if !ok {
		return false
	}
	second, err := s.doAPIDataProbe(ctx, probe)
	if err != nil || second.Status != first.Status {
		return false
	}
	replay, ok := inspectSensitiveJSON(second.Body, second.Header.Get("Content-Type"), probe.URL)
	if !ok || !stableSensitiveSummary(summary, replay) {
		return false
	}

	classes := sortedCountKeys(summary.Classes)
	paths := sortedCountKeys(summary.Paths)
	param := probe.Parameter
	if param == "" {
		param = "(baseline)"
	}
	evidence := fmt.Sprintf("Unauthenticated %s returned replay-stable structured sensitive data: classes=%s; field_paths=%s; records=%d; status=%d; content_type=%s; schema_fingerprint=%s. Raw response values were intentionally not persisted.",
		probe.Method, strings.Join(classes, ","), strings.Join(paths, ","), summary.Records,
		first.Status, safeContentType(first.Header.Get("Content-Type")), summary.Fingerprint[:16])
	ids, err := RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: "api_data_exposure", Subtype: "unauthenticated-sensitive-response",
		Severity: summary.Severity, URL: probe.URL, Method: probe.Method, Parameter: param,
		Location: probeLocation(probe), Payload: "parameter-names-only:" + param,
		Evidence: evidence, Source: "api-data-exposure", DetectionMethod: "stable-structured-replay",
		Confidence: 96, Priority: severityPriority(summary.Severity), Provenance: "js/request-contract-correlation",
		Verdict: VerifyVerified,
	})
	if err != nil || ids.FindingID == "" {
		return false
	}
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"id": ids.FindingID, "target_id": targetID, "type": "api_data_exposure",
			"severity": summary.Severity, "url": probe.URL, "parameter": param,
		})
	}
	return true
}

func eligibleAPIDataURL(raw string, status int, contentType, source string) bool {
	if !validHTTPURL(raw) || status == http.StatusNotFound {
		return false
	}
	u, _ := url.Parse(raw)
	path := strings.ToLower(u.Path)
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "json") || status == http.StatusMethodNotAllowed || source == "js" ||
		strings.Contains(path, "/api/") || strings.HasSuffix(path, "/api") ||
		strings.Contains(path, "/rest/") || strings.Contains(path, "/graphql") ||
		apiVersionPathRE.MatchString(path)
}

func eligibleParameterAPIURL(raw, source, method, contentType, location string) bool {
	if eligibleAPIDataURL(raw, http.StatusOK, contentType, source) {
		return true
	}
	lowerSource := strings.ToLower(source)
	lowerLocation := strings.ToLower(location)
	return strings.Contains(lowerSource, "openapi") || strings.Contains(lowerSource, "swagger") ||
		strings.Contains(lowerSource, "js") || strings.EqualFold(method, http.MethodPost) &&
		(lowerLocation == "json" || strings.Contains(strings.ToLower(contentType), "json"))
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

func endpointDataScore(ep *apiDataEndpoint) int {
	score := len(ep.Params) * 2
	if ep.Source == "js" {
		score += 8
	}
	if strings.Contains(strings.ToLower(ep.ContentType), "json") {
		score += 10
	}
	if ep.Status == http.StatusMethodNotAllowed {
		score += 6
	}
	if readLikeAPIPath(ep.URL) {
		score += 5
	}
	return score
}

func apiParameterScore(name, source, location string) int {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || !safeParameterName(lower) || unsafeAPIProbeParameter(lower) {
		return 0
	}
	score := 1
	for _, token := range []string{"user", "customer", "account", "member", "profile", "contact", "person", "client", "owner", "employee", "patient", "order", "invoice", "record", "id", "email", "phone", "search", "query", "filter", "fields", "include", "expand", "export", "report"} {
		if strings.Contains(lower, token) {
			score += 3
		}
	}
	source = strings.ToLower(source)
	if strings.Contains(source, "js") || strings.Contains(source, "openapi") || strings.Contains(source, "swagger") {
		score += 4
	}
	if location == "json" || location == "body" || location == "form" {
		score += 2
	}
	return score
}

func unsafeAPIProbeParameter(name string) bool {
	for _, token := range []string{"password", "passwd", "token", "secret", "otp", "csrf", "amount", "price", "payment", "delete", "remove", "create", "update", "write", "upload", "file", "role", "admin", "permission", "execute", "command"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func mergeEndpointParams(ep *apiDataEndpoint, global []string, limit int) []string {
	scores := map[string]int{}
	for name, score := range ep.Params {
		if score > 0 {
			scores[name] = score + 4
		}
	}
	for rank, name := range global {
		if !unsafeAPIProbeParameter(strings.ToLower(name)) {
			scores[name] = maxInt(scores[name], len(global)-rank)
		}
	}
	return topScoredParams(scores, limit)
}

func topScoredParams(scores map[string]int, limit int) []string {
	type pair struct {
		name  string
		score int
	}
	items := make([]pair, 0, len(scores))
	for name, score := range scores {
		if score > 0 && safeParameterName(name) {
			items = append(items, pair{name: name, score: score})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].score == items[j].score {
			return strings.ToLower(items[i].name) < strings.ToLower(items[j].name)
		}
		return items[i].score > items[j].score
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		key := strings.ToLower(item.name)
		if !seen[key] {
			seen[key] = true
			out = append(out, item.name)
		}
	}
	return out
}

func safeAPIProbeValue(name string) string {
	name = strings.ToLower(name)
	switch {
	case name == "page" || name == "limit" || name == "offset" || strings.HasSuffix(name, "_id") || name == "id":
		return "1"
	case strings.Contains(name, "fields") || strings.Contains(name, "select"):
		return "id,name,email,phone,address,date_of_birth"
	case strings.Contains(name, "include") || strings.Contains(name, "expand"):
		return "profile"
	case strings.Contains(name, "active") || strings.HasPrefix(name, "is_"):
		return "true"
	default:
		return "reconner-probe"
	}
}

func readLikeAPIPath(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, token := range []string{"create", "update", "delete", "remove", "destroy", "submit", "send", "pay", "checkout", "purchase", "upload", "invite", "reset", "login", "logout", "register", "signup", "write", "mutate", "action"} {
		if strings.Contains(path, token) {
			return false
		}
	}
	for _, token := range []string{"search", "lookup", "list", "query", "filter", "find", "profile", "user", "customer", "account", "member", "directory", "export", "report", "data", "info", "detail", "record", "contact", "people", "person", "patient"} {
		if strings.Contains(path, token) {
			return true
		}
	}
	return false
}

func parseMethodSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		method := strings.ToUpper(strings.TrimSpace(item))
		if method != "" {
			out[method] = true
		}
	}
	return out
}

func normalizeProbeContentType(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
	switch lower {
	case "application/json", "application/problem+json":
		return "application/json"
	case "application/x-www-form-urlencoded":
		return lower
	}
	if strings.HasSuffix(lower, "+json") {
		return "application/json"
	}
	return ""
}

func advertisedProbeContentType(raw string) string {
	for _, item := range strings.Split(raw, ",") {
		if ct := normalizeProbeContentType(item); ct != "" {
			return ct
		}
	}
	return ""
}

func orderedProbeContentTypes(ep *apiDataEndpoint) []string {
	var out []string
	if ep.ContentTypes["application/json"] {
		out = append(out, "application/json")
	}
	if ep.ContentTypes["application/x-www-form-urlencoded"] {
		out = append(out, "application/x-www-form-urlencoded")
	}
	if len(out) == 0 {
		out = append(out, "application/json")
	}
	return out
}

func probeLocation(probe apiDataProbe) string {
	if probe.Method == http.MethodPost {
		if probe.ContentType == "application/x-www-form-urlencoded" {
			return "form"
		}
		return "json"
	}
	return "query"
}

func safeContentType(raw string) string {
	if ct := normalizeProbeContentType(raw); ct != "" {
		return ct
	}
	return "structured-json"
}

func severityPriority(severity string) int {
	switch severity {
	case "critical":
		return 490
	case "high":
		return 420
	default:
		return 300
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var (
	emailValueRE     = regexp.MustCompile(`(?i)^[a-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$`)
	dateValueRE      = regexp.MustCompile(`^(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])$|^(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}$`)
	ibanValueRE      = regexp.MustCompile(`(?i)^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$`)
	apiVersionPathRE = regexp.MustCompile(`/v[0-9]+/`)
)

func inspectSensitiveJSON(body []byte, contentType, endpoint string) (sensitiveSummary, bool) {
	summary := sensitiveSummary{Classes: map[string]int{}, Paths: map[string]int{}}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return summary, false
	}
	ct := strings.ToLower(contentType)
	if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "+json") && !strings.Contains(ct, "javascript") {
		return summary, false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var document any
	if decoder.Decode(&document) != nil {
		return summary, false
	}
	walkSensitiveJSON(document, "$", &summary, 0)
	if len(summary.Classes) == 0 {
		return summary, false
	}

	highImpact := summary.Classes["government_id"] + summary.Classes["payment_card"] +
		summary.Classes["bank_account"] + summary.Classes["health_data"] +
		summary.Classes["credential_material"] + summary.Classes["authentication_secret"]
	classCount := len(summary.Classes)
	ordinaryStrong := summary.Records >= 2 && classCount >= 2
	if highImpact > 0 && (summary.Records >= 2 || highImpact >= 2) {
		summary.Severity = "critical"
	} else if highImpact > 0 || (ordinaryStrong && classCount >= 3) {
		summary.Severity = "high"
	} else if ordinaryStrong || (summary.Records >= 3 && (summary.Classes["date_of_birth"] > 0 || summary.Classes["postal_address"] > 0)) {
		summary.Severity = "medium"
	} else {
		return summary, false
	}

	path := strings.ToLower(endpoint)
	if highImpact == 0 && (strings.Contains(path, "/docs") || strings.Contains(path, "/example") || strings.Contains(path, "/sample") || strings.Contains(path, "/public/contacts")) {
		return summary, false
	}
	parts := append(sortedCountKeys(summary.Classes), sortedCountKeys(summary.Paths)...)
	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	summary.Fingerprint = hex.EncodeToString(hash[:])
	return summary, true
}

func walkSensitiveJSON(node any, path string, summary *sensitiveSummary, depth int) bool {
	if depth > 24 {
		return false
	}
	contains := false
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			childPath := path + "." + strings.ToLower(key)
			if scalar, ok := scalarString(child); ok {
				if class := classifySensitiveField(key, scalar); class != "" {
					summary.Classes[class]++
					summary.Paths[childPath]++
					contains = true
				}
			}
			if walkSensitiveJSON(child, childPath, summary, depth+1) {
				contains = true
			}
		}
	case []any:
		records := 0
		for _, child := range value {
			if walkSensitiveJSON(child, path+"[]", summary, depth+1) {
				records++
				contains = true
			}
		}
		if records > summary.Records {
			summary.Records = records
		}
	}
	if contains && summary.Records == 0 {
		summary.Records = 1
	}
	return contains
}

func scalarString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v), true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}

func classifySensitiveField(key, value string) string {
	k := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimSpace(key)))
	v := strings.TrimSpace(value)
	if v == "" || strings.EqualFold(v, "null") || strings.EqualFold(v, "redacted") || strings.Trim(v, "*xX-") == "" {
		return ""
	}
	if strings.Contains(k, "email") && emailValueRE.MatchString(v) && !placeholderEmail(v) {
		return "email"
	}
	if containsKeyToken(k, "phone", "mobile", "telephone") && plausiblePhone(v) {
		return "phone"
	}
	if containsKeyToken(k, "address", "street_address", "postal_address", "home_address") && len(v) >= 6 {
		return "postal_address"
	}
	if containsKeyToken(k, "dob", "date_of_birth", "birth_date", "birthday") && dateValueRE.MatchString(v) {
		return "date_of_birth"
	}
	if containsKeyToken(k, "ssn", "social_security", "national_id", "government_id", "passport_number", "tax_id") && plausibleIdentifier(v) {
		return "government_id"
	}
	if containsKeyToken(k, "card_number", "credit_card", "pan") && validLuhn(v) {
		return "payment_card"
	}
	if containsKeyToken(k, "iban", "bank_account", "bank_account_number", "routing_number") && plausibleBankIdentifier(v) {
		return "bank_account"
	}
	if containsKeyToken(k, "diagnosis", "medical_record", "health_condition", "patient_notes", "insurance_number") && len(v) >= 3 {
		return "health_data"
	}
	if containsKeyToken(k, "password", "password_hash", "passwd_hash") && looksCredentialMaterial(v) {
		return "credential_material"
	}
	if containsKeyToken(k, "access_token", "refresh_token", "auth_token", "bearer_token", "api_key", "apikey", "client_secret", "secret_key", "session_token", "reset_token", "password_reset_token") && looksCredentialMaterial(v) {
		return "authentication_secret"
	}
	return ""
}

func containsKeyToken(key string, tokens ...string) bool {
	for _, token := range tokens {
		if key == token || strings.Contains(key, token) {
			return true
		}
	}
	return false
}

func placeholderEmail(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range []string{"example.com", "example.org", "example.net", "test.com", "localhost", "invalid", "noreply", "no-reply"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	if at := strings.LastIndex(lower, "@"); at >= 0 {
		domain := lower[at+1:]
		for _, suffix := range []string{".example", ".test", ".invalid", ".localhost"} {
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		}
	}
	return false
}

func plausiblePhone(value string) bool {
	digits := onlyDigits(value)
	return len(digits) >= 7 && len(digits) <= 15 && !allSameDigit(digits)
}

func plausibleIdentifier(value string) bool {
	compact := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			return r
		}
		return -1
	}, value)
	return len(compact) >= 6 && len(compact) <= 24 && !allSameDigit(compact)
}

func validLuhn(value string) bool {
	digits := onlyDigits(value)
	if len(digits) < 12 || len(digits) > 19 || allSameDigit(digits) {
		return false
	}
	sum, parity := 0, len(digits)%2
	for i, r := range digits {
		d := int(r - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func plausibleBankIdentifier(value string) bool {
	compact := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(value, " ", ""), "-", ""))
	if ibanValueRE.MatchString(compact) {
		return true
	}
	digits := onlyDigits(compact)
	return len(digits) >= 6 && len(digits) <= 24 && !allSameDigit(digits)
}

func looksCredentialMaterial(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "redact") || strings.Contains(lower, "masked") || strings.Trim(value, "*xX") == "" {
		return false
	}
	return len(value) >= 12
}

func onlyDigits(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, value)
}

func allSameDigit(value string) bool {
	if len(value) < 2 {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			return false
		}
	}
	return true
}

func stableSensitiveSummary(a, b sensitiveSummary) bool {
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint || a.Severity != b.Severity || a.Records <= 0 || b.Records <= 0 {
		return false
	}
	small, large := a.Records, b.Records
	if small > large {
		small, large = large, small
	}
	return large-small <= maxInt(1, small/2)
}

func sortedCountKeys(values map[string]int) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
