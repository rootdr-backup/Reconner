package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// errSourceUnavailable is returned when a passive source responds with something
// other than the JSON we expect (an HTML rate-limit / Cloudflare / error page).
// It lets the caller log a clean "unavailable" note instead of a scary JSON
// parse error like `invalid character '<'`.
var errSourceUnavailable = errors.New("unavailable (rate-limited or blocked)")

// looksJSON reports whether a body plausibly starts a JSON document.
func looksJSON(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && (b[0] == '[' || b[0] == '{')
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// crtHTTPClient gives slow sources (crt.sh in particular) more headroom, since
// crt.sh regularly takes 20-40s to answer for busy domains.
var crtHTTPClient = &http.Client{Timeout: 60 * time.Second}

func queryCRTSH(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	// crt.sh flakes often (timeouts, 502s). Retry a couple of times before giving
	// up — it's one of the highest-signal sources so it's worth the patience.
	var body []byte
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := crtHTTPClient.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if looksJSON(b) {
			body = b
			lastErr = nil
			break
		}
		lastErr = errSourceUnavailable
	}
	if body == nil {
		if lastErr == nil {
			lastErr = errSourceUnavailable
		}
		return nil, lastErr
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []string

	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if !seen[name] && isValidSubdomain(name, domain) {
				seen[name] = true
				result = append(result, name)
			}
		}
	}

	return result, nil
}

func queryHackerTarget(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	content := string(body)
	if strings.Contains(content, "API count exceeded") || strings.Contains(content, "error") {
		return nil, fmt.Errorf("hackertarget rate limit or error")
	}

	var result []string
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			host := strings.TrimSpace(strings.ToLower(parts[0]))
			if isValidSubdomain(host, domain) {
				result = append(result, host)
			}
		}
	}

	return result, nil
}

func queryRapidDNS(domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	content := string(body)
	var result []string
	seen := make(map[string]bool)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "."+domain) || line == domain {
			host := strings.ToLower(line)
			if !seen[host] && isValidSubdomain(host, domain) {
				seen[host] = true
				result = append(result, host)
			}
		}
	}

	return result, nil
}

func queryOTX(domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	if !looksJSON(body) {
		return nil, errSourceUnavailable
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []string

	for _, entry := range data.PassiveDNS {
		host := strings.ToLower(strings.TrimSpace(entry.Hostname))
		if !seen[host] && isValidSubdomain(host, domain) {
			seen[host] = true
			result = append(result, host)
		}
	}

	return result, nil
}

// queryAnubis uses the free jldc.me Anubis DB — a real, independent passive
// source (replaces the old queryAlienVault which just duplicated queryOTX).
func queryAnubis(domain string) ([]string, error) {
	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	if !looksJSON(body) {
		return nil, errSourceUnavailable
	}
	var hosts []string
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []string
	for _, h := range hosts {
		host := strings.ToLower(strings.TrimSpace(h))
		if !seen[host] && isValidSubdomain(host, domain) {
			seen[host] = true
			result = append(result, host)
		}
	}
	return result, nil
}

func queryURLScan(domain string) ([]string, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	if !looksJSON(body) {
		return nil, errSourceUnavailable
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var result []string
	for _, r := range data.Results {
		host := strings.ToLower(strings.TrimSpace(r.Page.Domain))
		if !seen[host] && isValidSubdomain(host, domain) {
			seen[host] = true
			result = append(result, host)
		}
	}
	return result, nil
}

// queryCertSpotter pulls subdomains from SSLMate's Cert Spotter CT-log API. It's
// free (no key for basic use), reliable, and often surfaces names crt.sh misses.
func queryCertSpotter(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}
	if !looksJSON(body) {
		return nil, errSourceUnavailable
	}
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var result []string
	for _, e := range entries {
		for _, name := range e.DNSNames {
			name = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "*.")
			if !seen[name] && isValidSubdomain(name, domain) {
				seen[name] = true
				result = append(result, name)
			}
		}
	}
	return result, nil
}
