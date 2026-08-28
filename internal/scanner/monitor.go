package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type MonitorScanner struct {
	db     *database.DB
	exec   *tools.Executor
	cfg    *config.Config
	logger *logger.Logger
}

func NewMonitorScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger) *MonitorScanner {
	return &MonitorScanner{db: db, exec: exec, cfg: cfg, logger: log}
}

var monitorClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: sharedHTTPTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Run detects changes in HTTP services since last scan.
func (s *MonitorScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "monitor", "Starting change monitoring...")

	// Check HTTP services for changes
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, url, status_code, title, content_length, hash,
		       COALESCE(norm_hash,''), COALESCE(security_snapshot,'')
		FROM http_services WHERE target_id = ? AND COALESCE(source,'probe')='probe'
	`, targetID)
	if err != nil {
		return err
	}

	type svcRecord struct {
		ID            string
		URL           string
		StatusCode    int
		Title         string
		ContentLength int
		Hash          string
		NormHash      string
		SecSnapshot   string
	}
	var services []svcRecord
	for rows.Next() {
		var r svcRecord
		_ = rows.Scan(&r.ID, &r.URL, &r.StatusCode, &r.Title, &r.ContentLength, &r.Hash, &r.NormHash, &r.SecSnapshot)
		services = append(services, r)
	}
	rows.Close()

	logFn("info", "monitor", fmt.Sprintf("Monitoring %d HTTP services for changes...", len(services)))
	changed := 0

	for _, svc := range services {
		if ctx.Err() != nil {
			break
		}
		newStatus, newTitle, body, hdr, err := s.fetchBody(ctx, svc.URL)
		if err != nil {
			continue
		}
		// NORMALIZED hash: volatile values (UUIDs/timestamps/CSRF/high-entropy)
		// are stripped first, so a dynamic page doesn't false-positive.
		newNormHash := normalizedHash(body)

		// ── Security-attribute change detection (supply-chain / form-hijack) ──
		curSnap := extractSecuritySnapshot(body, hostOf(svc.URL))
		curSnap.Headers = extractSecurityHeaders(hdr.Get)
		if svc.SecSnapshot != "" {
			oldSnap := parseSecuritySnapshot(svc.SecSnapshot)
			for _, ch := range diffSecuritySnapshots(oldSnap, curSnap) {
				sev := securityChangeSeverity(ch)
				desc := fmt.Sprintf("security:%s_%s", ch.attr.Kind, ch.action)
				logFn("warn", "monitor", fmt.Sprintf("[SECURITY CHANGE] %s: %s external %s %q", svc.URL, ch.action, ch.attr.Kind, ch.attr.Value))
				s.recordChange(targetID, svc.URL, desc, "", fmt.Sprintf("%s %s: %s", ch.action, ch.attr.Kind, ch.attr.Value), sev)
				// A NEW external script/iframe or a changed form action is a real
				// finding (supply-chain injection / phishing) — raise it.
				if ch.action == "added" && (sev == "high" || sev == "medium") {
					s.storeSecurityFinding(targetID, svc.URL, ch, sev)
				}
				changed++
			}
			// ── Security-header regression (HSTS/CSP/X-Frame removed) ──
			for _, h := range diffSecurityHeaders(oldSnap.Headers, curSnap.Headers) {
				desc := "security_header_removed"
				logFn("warn", "monitor", fmt.Sprintf("[SECURITY HEADER REMOVED] %s: %s", svc.URL, h))
				s.recordChange(targetID, svc.URL, desc, h+" present", h+" removed", "high")
				s.storeHeaderRegression(targetID, svc.URL, h)
				changed++
			}
		}

		// ── Content / status / title change (normalized) ──
		contentChanged := svc.NormHash != "" && newNormHash != svc.NormHash
		if newStatus != svc.StatusCode || newTitle != svc.Title || contentChanged {
			changeDesc := s.describeChange(svc.StatusCode, newStatus, svc.Title, newTitle, svc.NormHash, newNormHash)
			logFn("warn", "monitor", fmt.Sprintf("[CHANGE] %s: %s", svc.URL, changeDesc))
			// A status-code transition is a stronger signal than a body tweak.
			sev := "low"
			if newStatus != svc.StatusCode {
				sev = classifyChangeSeverity("status")
			}
			s.recordChange(targetID, svc.URL, "http_change",
				fmt.Sprintf("status=%d title=%s", svc.StatusCode, svc.Title),
				fmt.Sprintf("status=%d title=%s", newStatus, newTitle), sev)
			changed++
		}

		// Always update the stored baseline (norm hash + security snapshot).
		_, _ = s.db.Exec(`
			UPDATE http_services SET status_code=?, title=?, content_length=?, norm_hash=?, security_snapshot=?, last_seen=CURRENT_TIMESTAMP
			WHERE id=?
		`, newStatus, newTitle, len(body), newNormHash, curSnap.toJSON(), svc.ID)
	}

	// Monitor JS file changes
	jsRows, err := s.db.QueryContext(ctx, `SELECT id, url, hash FROM js_files WHERE target_id = ?`, targetID)
	if err == nil {
		type jsRecord struct{ ID, URL, Hash string }
		var jsFiles []jsRecord
		for jsRows.Next() {
			var r jsRecord
			_ = jsRows.Scan(&r.ID, &r.URL, &r.Hash)
			jsFiles = append(jsFiles, r)
		}
		jsRows.Close()

		for _, jf := range jsFiles {
			if ctx.Err() != nil {
				break
			}
			newHash, newSize, err := s.fetchHash(ctx, jf.URL)
			if err != nil || newHash == "" {
				continue
			}
			if jf.Hash != "" && newHash != jf.Hash {
				logFn("warn", "monitor", fmt.Sprintf("[JS CHANGE] %s hash changed", jf.URL))
				s.recordChange(targetID, jf.URL, "js_change", jf.Hash, newHash, classifyChangeSeverity("js_change"))
				_, _ = s.db.Exec(`UPDATE js_files SET hash=?, size=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, newHash, newSize, jf.ID)
				changed++
			}
		}
	}

	// New subdomain detection - re-run passive sources and compare
	logFn("info", "monitor", fmt.Sprintf("Change monitoring complete. Detected %d changes.", changed))
	return nil
}

// fetchBody returns status, title and the raw body for normalized-hash and
// security-attribute analysis.
func (s *MonitorScanner) fetchBody(ctx context.Context, url string) (int, string, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := monitorClient.Do(req)
	if err != nil {
		return 0, "", "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
	return resp.StatusCode, extractTitle(string(body)), string(body), resp.Header, nil
}

// recordChange inserts a monitoring_changes row with a severity classification,
// and raises a matching notification so the operator sees it in the bell menu.
func (s *MonitorScanner) recordChange(targetID, url, changeType, oldVal, newVal, severity string) {
	_, _ = s.db.Exec(`
		INSERT INTO monitoring_changes (id, target_id, url, change_type, old_value, new_value, severity, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		uuid.New().String(), targetID, url, changeType, oldVal, newVal, severity)

	title := notificationTitle(changeType)
	body := url
	if newVal != "" {
		body = url + " — " + newVal
	}
	notify(s.db, targetID, changeType, title, body, url, severity)
}

// notificationTitle maps a monitoring change_type to a human, English headline.
func notificationTitle(changeType string) string {
	switch changeType {
	case "js_change":
		return "JavaScript changed"
	case "http_change", "status_change":
		return "HTTP response changed"
	case "new_subdomain":
		return "New subdomain discovered"
	case "header_regression":
		return "Security header removed"
	default:
		return "Change detected"
	}
}

// storeHeaderRegression raises a vuln finding when a security header disappears.
func (s *MonitorScanner) storeHeaderRegression(targetID, url, header string) {
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority)
		VALUES (?, ?, 'security_header_regression', 'high', ?, ?, '', ?, 80, 240)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			evidence = excluded.evidence, severity = excluded.severity`,
		uuid.New().String(), targetID, url, header,
		"Security response header removed since last scan: "+header+
			" — weakens the site's protection (e.g. clickjacking / TLS downgrade / MIME sniffing).")
}

// storeSecurityFinding raises a vuln finding for a dangerous security-attribute
// change picked up by monitoring (e.g. a new external <script src> = possible
// supply-chain compromise / injected malware).
func (s *MonitorScanner) storeSecurityFinding(targetID, url string, ch securityChange, sev string) {
	typ := "content_security_change"
	var title string
	switch ch.attr.Kind {
	case "script":
		title = "New external <script src> appeared — possible supply-chain / malicious JS injection"
	case "iframe":
		title = "New external <iframe src> appeared — possible clickjacking / phishing overlay"
	case "form":
		title = "New/changed <form action> — possible form hijacking (credential theft)"
	case "stylesheet":
		title = "New external stylesheet — possible CSS injection / exfiltration"
	default:
		title = "Security-sensitive HTML change detected"
	}
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority)
		VALUES (?, ?, ?, ?, ?, '', ?, ?, 70, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			evidence = excluded.evidence, severity = excluded.severity`,
		uuid.New().String(), targetID, typ, sev, url, ch.attr.Value,
		title+" — "+ch.attr.Kind+" = "+ch.attr.Value, severityWeightIDOR(sev)*70)
}

func (s *MonitorScanner) fetchHash(ctx context.Context, url string) (hash string, size int, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

	resp, err := monitorClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	h := fmt.Sprintf("%x", sha256.Sum256(body))
	return h, len(body), nil
}

func (s *MonitorScanner) describeChange(oldStatus, newStatus int, oldTitle, newTitle, oldHash, newHash string) string {
	var parts []string
	if oldStatus != newStatus {
		parts = append(parts, fmt.Sprintf("status %d→%d", oldStatus, newStatus))
	}
	if oldTitle != newTitle {
		old := oldTitle
		if len(old) > 30 {
			old = old[:30]
		}
		nw := newTitle
		if len(nw) > 30 {
			nw = nw[:30]
		}
		parts = append(parts, fmt.Sprintf("title '%s'→'%s'", old, nw))
	}
	if oldHash != "" && newHash != "" && oldHash != newHash {
		parts = append(parts, "content changed")
	}
	return strings.Join(parts, ", ")
}
