package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// OriginIPScanner discovers the real server IP hiding behind a CDN/WAF
// (Cloudflare, Akamai, etc.) by pulling the domain's HISTORICAL A records from
// SecurityTrails and checking which of those IPs still serve the site directly.
// A historical IP that returns the same page when addressed directly — with the
// CDN bypassed — is a candidate origin IP, which lets an attacker skip WAF rules
// and hit the backend. This is one of the highest-value recon findings and most
// scanners miss it.
//
// It is gated on a SecurityTrails API key (optional, per-deployment config). No
// key → the module is skipped cleanly.
type OriginIPScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewOriginIPScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *OriginIPScanner {
	return &OriginIPScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

func (s *OriginIPScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	key := strings.TrimSpace(s.cfg.SecurityTrailsAPIKey)
	if key == "" {
		logFn("info", "origin_ip", "Origin-IP discovery skipped — no SecurityTrails API key configured.")
		return nil
	}

	var domain string
	_ = s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id = ?`, targetID).Scan(&domain)
	if domain == "" {
		return nil
	}
	logFn("info", "origin_ip", "Pulling historical DNS to find origin IP behind CDN/WAF...")

	historicIPs, err := s.fetchHistoricalIPs(ctx, domain, key)
	if err != nil {
		logFn("warn", "origin_ip", "SecurityTrails query failed: "+err.Error())
		return nil
	}
	if len(historicIPs) == 0 {
		logFn("info", "origin_ip", "No historical IPs returned")
		return nil
	}

	// Current resolved IPs = almost certainly the CDN edge; exclude them.
	current := map[string]bool{}
	if ips, e := net.LookupIP(domain); e == nil {
		for _, ip := range ips {
			current[ip.String()] = true
		}
	}

	// Baseline: fetch the real site through the CDN to compare against.
	baseTitle, baseLen := s.fetchThroughCDN(ctx, domain)

	logFn("info", "origin_ip", fmt.Sprintf("Checking %d historical IP(s) for a live origin...", len(historicIPs)))
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found int64
	var mu sync.Mutex

	for _, ip := range historicIPs {
		if ctx.Err() != nil {
			break
		}
		if current[ip] {
			continue // that's the CDN edge, not the origin
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			ok, title, length, scheme := s.probeOrigin(ctx, ip, domain)
			if !ok {
				return
			}
			// Confirm it's really OUR site (not an unrelated host on that IP):
			// title match, or body size in the same band as the CDN baseline.
			confirmed := (baseTitle != "" && title != "" && strings.EqualFold(strings.TrimSpace(title), strings.TrimSpace(baseTitle))) ||
				(baseLen > 0 && length > 0 && float64(length) >= float64(baseLen)*0.6 && float64(length) <= float64(baseLen)*1.6)

			sev := "medium"
			note := "responds to the site's Host header directly (possible origin behind the CDN/WAF)"
			if confirmed {
				sev = "high"
				note = "serves the SAME site directly, bypassing the CDN/WAF — confirmed origin IP"
			}
			ev := fmt.Sprintf("Historical IP %s (%s://) %s. Test: curl -k -H 'Host: %s' %s://%s/", ip, scheme, note, domain, scheme, ip)
			s.store(targetID, domain, ip, sev, ev)
			mu.Lock()
			found++
			mu.Unlock()
			logFn("warn", "origin_ip", fmt.Sprintf("Origin IP candidate [%s]: %s (%s)", sev, ip, domain))
			if s.broadcast != nil {
				s.broadcast("new_vuln_finding", map[string]any{
					"target_id": targetID, "type": "origin_ip_disclosure", "url": domain, "parameter": "",
				})
			}
		}(ip)
	}
	wg.Wait()
	logFn("info", "origin_ip", fmt.Sprintf("Origin-IP discovery done. %d candidate(s).", found))
	return nil
}

// fetchHistoricalIPs pulls historical A records from SecurityTrails.
func (s *OriginIPScanner) fetchHistoricalIPs(ctx context.Context, domain, key string) ([]string, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", key)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited (HTTP 429)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data struct {
		Records []struct {
			Values []struct {
				IP string `json:"ip"`
			} `json:"values"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, rec := range data.Records {
		for _, v := range rec.Values {
			ip := strings.TrimSpace(v.IP)
			if ip != "" && !seen[ip] && net.ParseIP(ip) != nil {
				seen[ip] = true
				out = append(out, ip)
				if len(out) >= 60 {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

// probeOrigin connects directly to ip, sends the site's Host header, and reports
// whether it serves a page (title + length + scheme).
func (s *OriginIPScanner) probeOrigin(ctx context.Context, ip, domain string) (bool, string, int, string) {
	for _, scheme := range []string{"https", "http"} {
		var client *http.Client
		var urlStr string
		if scheme == "https" {
			client = &http.Client{
				Timeout: 8 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: domain},
					DisableKeepAlives: true,
					DialContext:       (&net.Dialer{Timeout: 6 * time.Second}).DialContext,
				},
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			urlStr = "https://" + net.JoinHostPort(ip, "443") + "/"
		} else {
			client = &http.Client{
				Timeout:       8 * time.Second,
				Transport:     &http.Transport{DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 6 * time.Second}).DialContext},
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			urlStr = "http://" + net.JoinHostPort(ip, "80") + "/"
		}

		reqCtx, cancel := context.WithTimeout(ctx, 9*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", urlStr, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Host = domain // the key: address the IP but ask for our vhost
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		cancel()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 && len(body) > 0 {
			return true, extractTitle(string(body)), len(body), scheme
		}
	}
	return false, "", 0, ""
}

func (s *OriginIPScanner) fetchThroughCDN(ctx context.Context, domain string) (string, int) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return "", 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := storedXSSClient.Do(req)
	if err != nil {
		return "", 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return extractTitle(string(body)), len(body)
}

func (s *OriginIPScanner) store(targetID, domain, ip, sev, evidence string) {
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority)
		VALUES (?, ?, 'origin_ip_disclosure', ?, ?, '', ?, ?, ?, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity, payload = excluded.payload,
			evidence = excluded.evidence, confidence = excluded.confidence, priority = excluded.priority
	`, uuid.New().String(), targetID, sev, domain, ip, evidence, pickConf(sev), pickPrio(sev))
}

func pickConf(sev string) int {
	if sev == "high" {
		return 90
	}
	return 55
}
func pickPrio(sev string) int {
	if sev == "high" {
		return 360
	}
	return 110
}
