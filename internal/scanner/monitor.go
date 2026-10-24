package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
	// broadcast is optional so focused unit tests can construct MonitorScanner
	// directly. In production it lets the bell refresh as soon as drift is saved.
	broadcast BroadcastFunc
}

func NewMonitorScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *MonitorScanner {
	return &MonitorScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var monitorClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: sharedHTTPTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		// A monitored in-scope page can redirect to login, payments or another
		// third party. Never turn that redirect into an out-of-scope GET. Same-host
		// HTTP→HTTPS and path redirects remain useful and are still followed.
		if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Run detects changes in HTTP services since last scan.
func (s *MonitorScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "monitor", "Starting change monitoring...")
	var targetScope, rawAuth string
	_ = s.db.QueryRowContext(ctx, `SELECT domain,COALESCE(auth_headers,'') FROM targets WHERE id=?`, targetID).Scan(&targetScope, &rawAuth)
	authHeaders := map[string]string{}
	_ = json.Unmarshal([]byte(rawAuth), &authHeaders)
	headersFor := func(rawURL string) map[string]string {
		// Never forward cookies or bearer tokens to a third-party JS/CDN URL.
		if len(authHeaders) == 0 || !requestURLInTargetScope(ctx, targetScope, rawURL) {
			return nil
		}
		return authHeaders
	}

	// Check HTTP services for changes
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, url, status_code, title, content_length, hash,
		       COALESCE(norm_hash,''), COALESCE(security_snapshot,''), COALESCE(server,'')
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
		Server        string
	}
	var services []svcRecord
	for rows.Next() {
		var r svcRecord
		if err := rows.Scan(&r.ID, &r.URL, &r.StatusCode, &r.Title, &r.ContentLength, &r.Hash, &r.NormHash, &r.SecSnapshot, &r.Server); err != nil {
			rows.Close()
			return err
		}
		if urlHostInScope(ctx, r.URL) {
			services = append(services, r)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	logFn("info", "monitor", fmt.Sprintf("Monitoring %d HTTP services for changes...", len(services)))
	changed := 0
	harvested := 0
	knownHTTP := map[string]bool{}
	knownJS := map[string]bool{}
	knownCSS := map[string]bool{}
	cssKeyRows, err := s.db.QueryContext(ctx, `SELECT url FROM css_files WHERE target_id = ?`, targetID)
	if err == nil {
		for cssKeyRows.Next() {
			var u string
			if cssKeyRows.Scan(&u) == nil {
				knownCSS[monitorURLKey(u)] = true
			}
		}
		cssKeyRows.Close()
	}

	for _, svc := range services {
		knownHTTP[monitorURLKey(svc.URL)] = true
		if ctx.Err() != nil {
			break
		}
		newStatus, newTitle, body, hdr, err := s.fetchBodyWithHeaders(ctx, svc.URL, headersFor(svc.URL))
		if err != nil {
			continue
		}
		// NORMALIZED hash: volatile values (UUIDs/timestamps/CSRF/high-entropy)
		// are stripped first, so a dynamic page doesn't false-positive.
		newNormHash := normalizedHash(body)
		harvested += s.harvestStylesheets(ctx, targetID, svc.URL, body, knownCSS)

		// ── Security-attribute change detection (supply-chain / form-hijack) ──
		curSnap := extractSecuritySnapshot(body, hostOf(svc.URL))
		curSnap.Headers = extractSecurityHeaders(hdr.Get)
		securityChanges := []securityChange{}
		removedHeaders := []string{}
		if svc.SecSnapshot != "" {
			oldSnap := parseSecuritySnapshot(svc.SecSnapshot)
			securityChanges = diffSecuritySnapshots(oldSnap, curSnap)
			removedHeaders = diffSecurityHeaders(oldSnap.Headers, curSnap.Headers)
		}
		contentChanged := svc.NormHash != "" && newNormHash != svc.NormHash
		potentialChange := newStatus != svc.StatusCode || newTitle != svc.Title || contentChanged || len(securityChanges) > 0 || len(removedHeaders) > 0
		if potentialChange {
			// Confirm only suspicious drift. A one-off 500/WAF challenge, rotating
			// edge page, or half-written deploy must not mutate the baseline or ring
			// the bell. Two matching fresh observations are required.
			confirmStatus, confirmTitle, confirmBody, confirmHeader, confirmErr := s.fetchBodyWithHeaders(ctx, svc.URL, headersFor(svc.URL))
			if confirmErr != nil {
				continue
			}
			confirmHash := normalizedHash(confirmBody)
			confirmSnap := extractSecuritySnapshot(confirmBody, hostOf(svc.URL))
			confirmSnap.Headers = extractSecurityHeaders(confirmHeader.Get)
			if confirmStatus != newStatus || confirmTitle != newTitle || confirmHash != newNormHash || confirmSnap.toJSON() != curSnap.toJSON() {
				logFn("info", "monitor", fmt.Sprintf("Ignoring unstable one-off response from %s", svc.URL))
				continue
			}
			body, hdr = confirmBody, confirmHeader
		}

		if svc.SecSnapshot != "" {
			for _, ch := range securityChanges {
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
			for _, h := range removedHeaders {
				desc := "security_header_removed"
				logFn("warn", "monitor", fmt.Sprintf("[SECURITY HEADER REMOVED] %s: %s", svc.URL, h))
				s.recordChange(targetID, svc.URL, desc, h+" present", h+" removed", "high")
				s.storeHeaderRegression(targetID, svc.URL, h)
				changed++
			}
		}

		// ── Content / status / title change (normalized) ──
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

		// ── Technology-stack change ──
		// The Server banner is the cheapest, most reliable tech-stack signal and is
		// already in the fresh response headers. A change (nginx → cloudflare, a
		// version bump, an added WAF/CDN fronting the origin) is a real
		// infrastructure change worth surfacing — it was invisible before because
		// the monitor only ever compared status/title/body/security, never the
		// detected technology.
		newServer := strings.TrimSpace(hdr.Get("Server"))
		oldServer := strings.TrimSpace(svc.Server)
		serverChanged := newServer != "" && oldServer != "" && !strings.EqualFold(newServer, oldServer)
		if serverChanged {
			logFn("info", "monitor", fmt.Sprintf("[TECH CHANGE] %s: Server %q → %q", svc.URL, oldServer, newServer))
			s.recordChange(targetID, svc.URL, "tech_change",
				"Server: "+oldServer, "Server: "+newServer, classifyChangeSeverity("tech_change"))
			changed++
		}

		// Always update the stored baseline (norm hash + security snapshot + server).
		storeServer := oldServer
		if newServer != "" {
			storeServer = newServer
		}
		_, _ = s.db.Exec(`
			UPDATE http_services SET status_code=?, title=?, content_length=?, norm_hash=?, security_snapshot=?, server=?, last_seen=CURRENT_TIMESTAMP
			WHERE id=?
		`, newStatus, newTitle, len(body), newNormHash, curSnap.toJSON(), storeServer, svc.ID)
	}

	if harvested > 0 {
		logFn("info", "monitor", fmt.Sprintf("Tracking %d new stylesheet URL(s) for content changes", harvested))
	}

	// Monitor JS file changes — hash AND the capped content body, so a js_change
	// row can render a real line-diff in the dashboard instead of two hashes.
	jsRows, err := s.db.QueryContext(ctx, `SELECT id, url, hash, COALESCE(body,'') FROM js_files WHERE target_id = ?`, targetID)
	if err == nil {
		type jsRecord struct{ ID, URL, Hash, Body string }
		var jsFiles []jsRecord
		for jsRows.Next() {
			var r jsRecord
			if err := jsRows.Scan(&r.ID, &r.URL, &r.Hash, &r.Body); err != nil {
				jsRows.Close()
				return err
			}
			if urlHostInScope(ctx, r.URL) {
				jsFiles = append(jsFiles, r)
			}
		}
		if err := jsRows.Err(); err != nil {
			jsRows.Close()
			return err
		}
		jsRows.Close()

		for _, jf := range jsFiles {
			knownJS[monitorURLKey(jf.URL)] = true
			if ctx.Err() != nil {
				break
			}
			newHash, newSize, newBody, err := s.fetchFileWithBody(ctx, jf.URL, headersFor(jf.URL))
			if err != nil || newHash == "" {
				continue
			}
			if jf.Hash != "" && newHash != jf.Hash {
				confirmHash, _, _, confirmErr := s.fetchFileWithBody(ctx, jf.URL, headersFor(jf.URL))
				if confirmErr != nil || confirmHash != newHash {
					logFn("info", "monitor", fmt.Sprintf("Ignoring unstable one-off JavaScript response from %s", jf.URL))
					continue
				}
				logFn("warn", "monitor", fmt.Sprintf("[JS CHANGE] %s hash changed", jf.URL))
				s.recordChange(targetID, jf.URL, "js_change", jf.Hash, newHash, classifyChangeSeverity("js_change"))
				// Roll the previous content into old_* for the diff drawer, then
				// publish the new baseline in one go.
				_, _ = s.db.ExecContext(ctx, `UPDATE js_files SET hash=?, size=?, body=?, old_hash=?, old_body=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`,
					newHash, newSize, newBody, jf.Hash, jf.Body, jf.ID)
				changed++
				continue
			}
			// Always establish/refresh the baseline. Previously an empty initial hash
			// was never written, so that JS file could change forever undetected.
			// The content capture is written alongside it on the first pass only —
			// rewriting unchanged 256KB bodies every pass is pure write churn.
			if jf.Body == "" {
				_, _ = s.db.ExecContext(ctx, `UPDATE js_files SET hash=?, size=?, body=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, newHash, newSize, newBody, jf.ID)
			} else {
				_, _ = s.db.ExecContext(ctx, `UPDATE js_files SET hash=?, size=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, newHash, newSize, jf.ID)
			}
		}
	}

	// Monitor stylesheet content changes. css_files tracks every
	// <link rel="stylesheet" href> harvested from page bodies (same-origin AND
	// cross-origin), so a version bump is judged by CONTENT, not by the link
	// attribute: changed bytes → one css_change row (with a real line-diff in
	// the drawer); a cache-buster rename with unchanged bytes → silence.
	cssRows, err := s.db.QueryContext(ctx, `SELECT id, url, hash, COALESCE(body,''), COALESCE(size,0) FROM css_files WHERE target_id = ?`, targetID)
	if err == nil {
		type cssRecord struct {
			ID, URL, Hash, Body string
			Size                int
		}
		var cssFiles []cssRecord
		for cssRows.Next() {
			var r cssRecord
			if err := cssRows.Scan(&r.ID, &r.URL, &r.Hash, &r.Body, &r.Size); err != nil {
				cssRows.Close()
				return err
			}
			cssFiles = append(cssFiles, r)
		}
		if err := cssRows.Err(); err != nil {
			cssRows.Close()
			return err
		}
		cssRows.Close()

		for _, cf := range cssFiles {
			knownCSS[monitorURLKey(cf.URL)] = true
			if ctx.Err() != nil {
				break
			}
			newHash, newSize, newBody, err := s.fetchFileWithBody(ctx, cf.URL, headersFor(cf.URL))
			if err != nil || newHash == "" {
				continue
			}
			if cf.Hash != "" && newHash != cf.Hash {
				confirmHash, _, _, confirmErr := s.fetchFileWithBody(ctx, cf.URL, headersFor(cf.URL))
				if confirmErr != nil || confirmHash != newHash {
					logFn("info", "monitor", fmt.Sprintf("Ignoring unstable one-off stylesheet response from %s", cf.URL))
					continue
				}
				logFn("warn", "monitor", fmt.Sprintf("[CSS CHANGE] %s hash changed", cf.URL))
				s.recordChange(targetID, cf.URL, "css_change", cf.Hash, newHash, classifyChangeSeverity("css_change"))
				_, _ = s.db.ExecContext(ctx, `UPDATE css_files SET hash=?, size=?, body=?, old_hash=?, old_body=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`,
					newHash, newSize, newBody, cf.Hash, cf.Body, cf.ID)
				changed++
				continue
			}
			if cf.Hash == "" {
				// Establish the baseline without ringing the bell (same as JS).
				_, _ = s.db.ExecContext(ctx, `UPDATE css_files SET hash=?, size=?, body=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, newHash, newSize, newBody, cf.ID)
			} else if cf.Body == "" {
				// Legacy row that predates capture: backfill the content snapshot
				// so the next real change has a "before" side to diff against.
				_, _ = s.db.ExecContext(ctx, `UPDATE css_files SET body=?, size=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, newBody, newSize, cf.ID)
			} else {
				_, _ = s.db.ExecContext(ctx, `UPDATE css_files SET size=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, newSize, cf.ID)
			}
		}
	}

	// Explicit Project assets can be a full page/API URL or a JavaScript file
	// that has not yet entered http_services/js_files. Monitor those seeds
	// directly so a project is useful before (or without) a full recon scan.
	assetChanges, err := s.monitorProjectAssets(ctx, targetID, targetScope, authHeaders, knownHTTP, knownJS, logFn)
	if err != nil {
		logFn("warn", "monitor", "Some explicit project assets could not be monitored: "+err.Error())
	}
	changed += assetChanges

	// New subdomain detection - re-run passive sources and compare
	logFn("info", "monitor", fmt.Sprintf("Change monitoring complete. Detected %d changes.", changed))
	return nil
}

func monitorAssetURL(value, assetType string) string {
	v := strings.TrimSpace(value)
	if v == "" || assetType == "wildcard" || assetType == "cidr" || assetType == "ip" ||
		assetType == "android" || assetType == "ios" || assetType == "hardware" || assetType == "source_code" || assetType == "other" {
		return ""
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			return u.String()
		}
		return ""
	}
	if strings.ContainsAny(v, " \t\r\n,") {
		return ""
	}
	return "https://" + strings.TrimPrefix(v, "//")
}

// monitorURLKey canonicalizes only for comparison/deduplication. It preserves
// path and query semantics while folding host/scheme case, fragments and default
// ports, and treating an empty path as "/".
func monitorURLKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return strings.TrimSpace(raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func monitorAssetCandidates(value, assetType, lastURL string) []string {
	if u := monitorAssetURL(value, assetType); u == "" {
		return nil
	} else if strings.HasPrefix(strings.TrimSpace(value), "http://") || strings.HasPrefix(strings.TrimSpace(value), "https://") {
		return []string{u}
	} else {
		out := []string{}
		if lastURL != "" {
			out = append(out, lastURL)
		}
		out = append(out, u, "http://"+strings.TrimPrefix(strings.TrimSpace(value), "//"))
		seen := map[string]bool{}
		uniq := out[:0]
		for _, candidate := range out {
			key := monitorURLKey(candidate)
			if key != "" && !seen[key] {
				seen[key] = true
				uniq = append(uniq, candidate)
			}
		}
		return uniq
	}
}

func (s *MonitorScanner) monitorProjectAssets(ctx context.Context, targetID, targetScope string, authHeaders map[string]string, knownHTTP, knownJS map[string]bool, logFn LogFunc) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,value,COALESCE(asset_type,'domain'),COALESCE(metadata,'{}')
		FROM assets WHERE target_id=? AND COALESCE(approval_status,'approved')='approved' AND COALESCE(monitor_enabled,1)=1`, targetID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	type record struct{ id, value, typ, metadata string }
	var assets []record
	for rows.Next() {
		var a record
		if rows.Scan(&a.id, &a.value, &a.typ, &a.metadata) == nil {
			assets = append(assets, a)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	changed := 0
	for _, a := range assets {
		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
		meta := map[string]any{}
		_ = json.Unmarshal([]byte(a.metadata), &meta)
		lastURL, _ := meta["monitor_url"].(string)
		candidates := monitorAssetCandidates(a.value, a.typ, lastURL)
		if len(candidates) == 0 {
			continue
		}
		isJS := a.typ == "js" || strings.HasSuffix(strings.ToLower(strings.Split(candidates[0], "?")[0]), ".js")
		alreadyCovered := false
		for _, candidate := range candidates {
			key := monitorURLKey(candidate)
			if (isJS && knownJS[key]) || (!isJS && knownHTTP[key]) {
				alreadyCovered = true
				break
			}
		}
		if alreadyCovered {
			continue
		}
		oldHash, _ := meta["monitor_hash"].(string)
		var u string
		headersFor := func(candidate string) map[string]string {
			if len(authHeaders) > 0 && requestURLInTargetScope(ctx, targetScope, candidate) {
				return authHeaders
			}
			return nil
		}
		if isJS {
			var newHash string
			var size int
			for _, candidate := range candidates {
				var fetchErr error
				newHash, size, fetchErr = s.fetchHashWithHeaders(ctx, candidate, headersFor(candidate))
				if fetchErr == nil && newHash != "" {
					u = candidate
					break
				}
			}
			if u == "" {
				continue
			}
			if oldHash != "" && oldHash != newHash {
				confirmHash, _, confirmErr := s.fetchHashWithHeaders(ctx, u, headersFor(u))
				if confirmErr != nil || confirmHash != newHash {
					logFn("info", "monitor", fmt.Sprintf("Ignoring unstable one-off JavaScript response from %s", u))
					continue
				}
				s.recordChange(targetID, u, "js_change", oldHash, newHash, classifyChangeSeverity("js_change"))
				logFn("warn", "monitor", fmt.Sprintf("[PROJECT JS CHANGE] %s", u))
				changed++
			}
			meta["monitor_hash"] = newHash
			meta["monitor_size"] = size
			meta["monitor_checked_at"] = time.Now().UTC().Format(time.RFC3339)
		} else {
			var status int
			var title, body string
			var hdr http.Header
			for _, candidate := range candidates {
				var fetchErr error
				status, title, body, hdr, fetchErr = s.fetchBodyWithHeaders(ctx, candidate, headersFor(candidate))
				if fetchErr == nil {
					u = candidate
					break
				}
			}
			if u == "" {
				continue
			}
			newHash := normalizedHash(body)
			oldStatus, _ := meta["monitor_status"].(float64)
			oldTitle, _ := meta["monitor_title"].(string)
			curSnap := extractSecuritySnapshot(body, hostOf(u))
			curSnap.Headers = extractSecurityHeaders(hdr.Get)
			securityChanges := []securityChange{}
			removedHeaders := []string{}
			if oldRaw, _ := meta["monitor_security_snapshot"].(string); oldRaw != "" {
				oldSnap := parseSecuritySnapshot(oldRaw)
				securityChanges = diffSecuritySnapshots(oldSnap, curSnap)
				removedHeaders = diffSecurityHeaders(oldSnap.Headers, curSnap.Headers)
			}
			potentialChange := oldHash != "" && (oldHash != newHash || int(oldStatus) != status || oldTitle != title)
			potentialChange = potentialChange || len(securityChanges) > 0 || len(removedHeaders) > 0
			if potentialChange {
				confirmStatus, confirmTitle, confirmBody, confirmHeader, confirmErr := s.fetchBodyWithHeaders(ctx, u, headersFor(u))
				if confirmErr != nil {
					continue
				}
				confirmHash := normalizedHash(confirmBody)
				confirmSnap := extractSecuritySnapshot(confirmBody, hostOf(u))
				confirmSnap.Headers = extractSecurityHeaders(confirmHeader.Get)
				if confirmStatus != status || confirmTitle != title || confirmHash != newHash || confirmSnap.toJSON() != curSnap.toJSON() {
					logFn("info", "monitor", fmt.Sprintf("Ignoring unstable one-off response from %s", u))
					continue
				}
				body, hdr = confirmBody, confirmHeader
			}
			if oldRaw, _ := meta["monitor_security_snapshot"].(string); oldRaw != "" {
				for _, ch := range securityChanges {
					severity := securityChangeSeverity(ch)
					s.recordChange(targetID, u, fmt.Sprintf("security:%s_%s", ch.attr.Kind, ch.action), "", fmt.Sprintf("%s %s: %s", ch.action, ch.attr.Kind, ch.attr.Value), severity)
					if ch.action == "added" && (severity == "high" || severity == "medium") {
						s.storeSecurityFinding(targetID, u, ch, severity)
					}
					changed++
				}
				for _, header := range removedHeaders {
					s.recordChange(targetID, u, "security_header_removed", header+" present", header+" removed", "high")
					s.storeHeaderRegression(targetID, u, header)
					changed++
				}
			}
			if oldHash != "" && (oldHash != newHash || int(oldStatus) != status || oldTitle != title) {
				severity := "low"
				if int(oldStatus) != status {
					severity = classifyChangeSeverity("status")
				}
				s.recordChange(targetID, u, "page_change", fmt.Sprintf("status=%d title=%s", int(oldStatus), oldTitle), fmt.Sprintf("status=%d title=%s", status, title), severity)
				logFn("warn", "monitor", fmt.Sprintf("[PROJECT PAGE CHANGE] %s", u))
				changed++
			}
			meta["monitor_hash"] = newHash
			meta["monitor_status"] = status
			meta["monitor_title"] = title
			meta["monitor_content_type"] = hdr.Get("Content-Type")
			meta["monitor_security_snapshot"] = curSnap.toJSON()
			meta["monitor_checked_at"] = time.Now().UTC().Format(time.RFC3339)
		}
		meta["monitor_url"] = u
		encoded, _ := json.Marshal(meta)
		_, _ = s.db.ExecContext(ctx, `UPDATE assets SET metadata=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(encoded), a.id)
	}
	return changed, nil
}

// fetchBody returns status, title and the raw body for normalized-hash and
// security-attribute analysis.
func (s *MonitorScanner) fetchBody(ctx context.Context, url string) (int, string, string, http.Header, error) {
	return s.fetchBodyWithHeaders(ctx, url, nil)
}

func (s *MonitorScanner) fetchBodyWithHeaders(ctx context.Context, url string, headers map[string]string) (int, string, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	for k, v := range headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := monitorClient.Do(req)
	if err != nil {
		return 0, "", "", nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
	if err != nil {
		return 0, "", "", nil, err
	}
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
	if s.broadcast != nil {
		s.broadcast("notification_created", map[string]any{"target_id": targetID, "type": changeType, "severity": severity})
	}
}

// notificationTitle maps a monitoring change_type to a human, English headline.
func notificationTitle(changeType string) string {
	switch changeType {
	case "js_change":
		return "JavaScript changed"
	case "css_change":
		return "Stylesheet content changed"
	case "security:stylesheet_added":
		return "External stylesheet added"
	case "security:stylesheet_removed":
		return "External stylesheet removed"
	case "http_change", "status_change":
		return "HTTP response changed"
	case "page_change":
		return "Monitored project page changed"
	case "tech_change":
		return "Technology / server changed"
	case "new_subdomain":
		return "New subdomain discovered"
	case "header_regression", "security_header_removed":
		return "Security header removed"
	default:
		return "Change detected"
	}
}

// storeHeaderRegression raises a vuln finding when a security header disappears.
func (s *MonitorScanner) storeHeaderRegression(targetID, url, header string) {
	evidence := "Security response header removed since last scan: " + header +
		" — weakens the site's protection (e.g. clickjacking / TLS downgrade / MIME sniffing)."
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "security_header_regression", Severity: "high", URL: url,
		Method: "MONITOR", Parameter: header, Location: "header", Evidence: evidence,
		Source: "monitor", DetectionMethod: "snapshot-diff", Confidence: 80,
		Priority: 240, Verdict: CandDetected,
	})
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
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: typ, Subtype: ch.attr.Kind, Severity: sev, URL: url,
		Method: "MONITOR", Location: "html", Payload: ch.attr.Value,
		Evidence: title + " — " + ch.attr.Kind + " = " + ch.attr.Value,
		Source:   "monitor", DetectionMethod: "snapshot-diff", Confidence: 70,
		Priority: severityWeightIDOR(sev) * 70, Verdict: CandDetected,
	})
}

func (s *MonitorScanner) fetchHash(ctx context.Context, url string) (hash string, size int, err error) {
	return s.fetchHashWithHeaders(ctx, url, nil)
}

func (s *MonitorScanner) fetchHashWithHeaders(ctx context.Context, url string, headers map[string]string) (hash string, size int, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	for k, v := range headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := monitorClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("unexpected JavaScript response status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", 0, err
	}
	trimmed := strings.ToLower(strings.TrimSpace(string(body)))
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
		(strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html")) {
		return "", 0, fmt.Errorf("JavaScript URL returned an HTML document")
	}
	h := fmt.Sprintf("%x", sha256.Sum256(body))
	return h, len(body), nil
}

// monitorBodyCaptureCap bounds the per-file content stored beside the hash
// (see the "Body capture for diffing" migration comment). The HASH always
// covers the full download (up to the 5MB reader cap), so a real change deep
// inside a large bundle is still detected; only the stored diff material is
// truncated to the first N bytes.
const monitorBodyCaptureCap = 256 * 1024

// Stylesheet `<link rel="stylesheet" href>…` harvesting, attribute-order agnostic.
var (
	reLinkTag      = regexp.MustCompile(`(?i)<link\b[^>]*>`)
	reLinkAttrRel  = regexp.MustCompile(`(?i)\brel\s*=\s*["']?([^"'\s>]{2,20})`)
	reLinkAttrHref = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
)

// fetchFileWithBody fetches a static asset (JS/CSS) for content tracking:
// full-content SHA-256, size, and the capped body the diff drawer renders.
// The HTML-document rejection mirrors fetchHashWithHeaders — an SPA fallback
// must never be captured as an asset's content.
func (s *MonitorScanner) fetchFileWithBody(ctx context.Context, rawURL string, headers map[string]string) (hash string, size int, body string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	for k, v := range headers {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := monitorClient.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, "", fmt.Errorf("unexpected asset response status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", 0, "", err
	}
	trimmed := strings.ToLower(strings.TrimSpace(string(raw)))
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
		(strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html")) {
		return "", 0, "", fmt.Errorf("asset URL returned an HTML document")
	}
	captured := raw
	if len(captured) > monitorBodyCaptureCap {
		captured = captured[:monitorBodyCaptureCap]
	}
	h := fmt.Sprintf("%x", sha256.Sum256(raw))
	return h, len(raw), string(captured), nil
}

// harvestStylesheets pulls <link rel="stylesheet" href> URLs out of fresh page
// HTML and tracks them in css_files (same-origin AND cross-origin — that is
// what the browser actually loads), so the monitor can diff stylesheet
// CONTENT — the layer behind the Changes tab's css_change rows — rather than
// only the attribute-level "link appeared" check. Relative hrefs resolve
// against the page URL. Returns how many NEW URLs were registered.
func (s *MonitorScanner) harvestStylesheets(ctx context.Context, targetID, pageURL, body string, known map[string]bool) int {
	base, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || base.Host == "" {
		return 0
	}
	inserted := 0
	for _, tag := range reLinkTag.FindAllString(body, -1) {
		relMatch := reLinkAttrRel.FindStringSubmatch(tag)
		if relMatch == nil || !strings.Contains(strings.ToLower(relMatch[1]), "stylesheet") {
			continue
		}
		hrefMatch := reLinkAttrHref.FindStringSubmatch(tag)
		if hrefMatch == nil {
			continue
		}
		href := strings.TrimSpace(hrefMatch[1])
		if href == "" || strings.HasPrefix(href, "#") {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil {
			continue
		}
		if ref.Scheme != "" && ref.Scheme != "http" && ref.Scheme != "https" {
			continue // data:/javascript:/mailto:/tel: and friends
		}
		resolved := base.ResolveReference(ref)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		// Register the query-stripped URL: a `?ver=` churn maps to ONE tracked
		// row (content re-fetched from the stable path each pass) instead of a
		// new css_files row per cache-buster.
		trackedURL := stripResourceQuery(resolved.String())
		key := monitorURLKey(trackedURL)
		if key == "" || known[key] {
			continue
		}
		known[key] = true
		inserted++
		_, _ = s.db.ExecContext(ctx, `INSERT INTO css_files (id, target_id, url) VALUES (?, ?, ?)
			ON CONFLICT(target_id, url) DO NOTHING`, uuid.New().String(), targetID, trackedURL)
	}
	return inserted
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
