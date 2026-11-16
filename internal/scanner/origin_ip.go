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
// Historical DNS comes from whichever source is available: SecurityTrails'
// purpose-built history endpoint when a key is configured (richer, higher
// rate limit), merged with AlienVault OTX's free, keyless passive DNS, which
// runs unconditionally. A missing or rate-limited SecurityTrails key no
// longer blocks the module outright — only a total failure of every source
// does.
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

	var domain string
	if err := s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id = ?`, targetID).Scan(&domain); err != nil {
		return fmt.Errorf("load origin-IP target: %w", err)
	}
	if domain == "" {
		return fmt.Errorf("origin-IP target domain is empty")
	}
	logFn("info", "origin_ip", "Pulling historical DNS to find origin IP behind CDN/WAF...")

	historicIPs, err := s.fetchHistoricalIPsWithFallback(ctx, domain, key, logFn)
	if err != nil {
		return BlockedPhase(err.Error())
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
	baseTitle, baseLen, baseHash := s.fetchThroughCDN(ctx, domain)
	if baseTitle == "" && baseLen == 0 {
		return BlockedPhase("target baseline could not be fetched for origin comparison")
	}

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

			ok, title, length, bodyHash, scheme := s.probeOrigin(ctx, ip, domain)
			if !ok {
				return
			}
			// Confirm it's really OUR site (not an unrelated host on that IP):
			// Require an exact normalized body fingerprint, or an exact title plus
			// a compatible body-size band. Length alone is never identity proof:
			// unrelated default vhosts commonly return similarly sized pages.
			confirmed := originResponseMatches(baseTitle, baseLen, baseHash, title, length, bodyHash)
			if !confirmed {
				logFn("info", "origin_ip", fmt.Sprintf("Rejected historical IP %s: response did not match the target baseline", ip))
				return
			}

			sev := "high"
			note := "serves the SAME site directly, bypassing the CDN/WAF — confirmed origin IP"
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

func originResponseMatches(baseTitle string, baseLen int, baseHash string, candidateTitle string, candidateLen int, candidateHash string) bool {
	if baseHash != "" && candidateHash != "" && baseHash == candidateHash {
		return true
	}
	if baseTitle == "" || candidateTitle == "" || !strings.EqualFold(strings.TrimSpace(candidateTitle), strings.TrimSpace(baseTitle)) {
		return false
	}
	return baseLen > 0 && candidateLen > 0 && float64(candidateLen) >= float64(baseLen)*0.6 && float64(candidateLen) <= float64(baseLen)*1.6
}

// fetchHistoricalIPsWithFallback tries every available historical-DNS source
// and merges their results, so one provider's rate limit or missing API key
// never fully blocks origin-IP discovery. SecurityTrails (when a key is
// configured) is the richer, purpose-built source; AlienVault OTX's passive
// DNS is free and keyless and always runs, so there is at least one source
// out of the box. Returns an error only when EVERY available source failed
// outright — a source that ran cleanly and simply found nothing is not a
// failure, matching the pre-fallback "no historical IPs returned" outcome.
func (s *OriginIPScanner) fetchHistoricalIPsWithFallback(ctx context.Context, domain, key string, logFn LogFunc) ([]string, error) {
	anySourceSucceeded := false
	var lastErr error
	var stIPs, otxIPs []string

	if key != "" {
		var err error
		stIPs, err = s.fetchHistoricalIPs(ctx, domain, key)
		if err != nil {
			lastErr = fmt.Errorf("SecurityTrails: %w", err)
			logFn("warn", "origin_ip", "SecurityTrails query failed: "+err.Error()+" — falling back to AlienVault OTX passive DNS.")
		} else {
			anySourceSucceeded = true
			logFn("info", "origin_ip", fmt.Sprintf("SecurityTrails: %d historical IP(s)", len(stIPs)))
		}
	} else {
		logFn("info", "origin_ip", "No SecurityTrails API key configured — using AlienVault OTX passive DNS (free, no key required) instead.")
	}

	var err error
	otxIPs, err = fetchHistoricalIPsFromOTX(ctx, domain)
	if err != nil {
		lastErr = fmt.Errorf("OTX: %w", err)
		logFn("info", "origin_ip", "AlienVault OTX passive DNS unavailable: "+err.Error())
	} else {
		anySourceSucceeded = true
		logFn("info", "origin_ip", fmt.Sprintf("AlienVault OTX: %d historical IP(s)", len(otxIPs)))
	}

	if !anySourceSucceeded {
		return nil, fmt.Errorf("every historical-DNS source failed: %w", lastErr)
	}
	return mergeHistoricalIPs(stIPs, otxIPs), nil
}

// mergeHistoricalIPs deduplicates and combines historical-IP lists from
// every source that returned data, preserving first-seen order, and caps
// the result so the origin probe step downstream has a bounded, predictable
// cost no matter how many sources contributed.
func mergeHistoricalIPs(sources ...[]string) []string {
	seen := map[string]bool{}
	var merged []string
	for _, ips := range sources {
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				merged = append(merged, ip)
			}
		}
	}
	const maxMerged = 80
	if len(merged) > maxMerged {
		merged = merged[:maxMerged]
	}
	return merged
}

// fetchHistoricalIPsFromOTX pulls historical A-record addresses for domain
// from AlienVault OTX's passive DNS — free, no API key, and the same
// endpoint this codebase's passive subdomain sources already query
// successfully (see queryOTX). Less deep than SecurityTrails' purpose-built
// history endpoint, but it is always available, which is exactly what
// origin-IP discovery needs when SecurityTrails is unconfigured or
// rate-limited.
func fetchHistoricalIPsFromOTX(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

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
	return parseOTXPassiveDNSAddresses(body)
}

// parseOTXPassiveDNSAddresses extracts up to 60 deduplicated, valid A-record
// addresses from an OTX passive_dns JSON response body. Split out of
// fetchHistoricalIPsFromOTX so the parsing/filtering logic is directly
// unit-testable from a fixed response fixture, with no network involved.
func parseOTXPassiveDNSAddresses(body []byte) ([]string, error) {
	if !looksJSON(body) {
		return nil, errSourceUnavailable
	}
	var data struct {
		PassiveDNS []struct {
			Address    string `json:"address"`
			RecordType string `json:"record_type"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string
	for _, rec := range data.PassiveDNS {
		if !strings.EqualFold(rec.RecordType, "A") {
			continue
		}
		ip := strings.TrimSpace(rec.Address)
		if ip != "" && !seen[ip] && net.ParseIP(ip) != nil {
			seen[ip] = true
			out = append(out, ip)
			if len(out) >= 60 {
				break
			}
		}
	}
	return out, nil
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
func (s *OriginIPScanner) probeOrigin(ctx context.Context, ip, domain string) (bool, string, int, string, string) {
	for _, scheme := range []string{"https", "http"} {
		var client *http.Client
		var urlStr string
		if scheme == "https" {
			client = &http.Client{
				Timeout: 8 * time.Second,
				Transport: identityRoundTripper{base: &http.Transport{
					TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: domain}, // #nosec G402 -- direct-IP origin verification intentionally bypasses certificate-chain validation
					DisableKeepAlives: true,
					DialContext:       (&net.Dialer{Timeout: 6 * time.Second}).DialContext,
				}},
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			urlStr = "https://" + net.JoinHostPort(ip, "443") + "/"
		} else {
			client = &http.Client{
				Timeout:       8 * time.Second,
				Transport:     identityRoundTripper{base: &http.Transport{DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 6 * time.Second}).DialContext}},
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
			return true, extractTitle(string(body)), len(body), BodyHash(string(body)), scheme
		}
	}
	return false, "", 0, "", ""
}

func (s *OriginIPScanner) fetchThroughCDN(ctx context.Context, domain string) (string, int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", "https://"+domain+"/", nil)
	if err != nil {
		return "", 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := storedXSSClient.Do(req)
	if err != nil {
		return "", 0, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return extractTitle(string(body)), len(body), BodyHash(string(body))
}

func (s *OriginIPScanner) store(targetID, domain, ip, sev, evidence string) {
	conf := pickConf(sev)
	verdict := CandDetected
	if conf >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "origin_ip_disclosure", Severity: sev, URL: domain,
		Method: "DNS/HTTP", Location: "host", Payload: ip, Evidence: evidence,
		Source: "origin-ip", DetectionMethod: "origin-differential", Confidence: conf,
		Priority: pickPrio(sev), Verdict: verdict,
	})
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
