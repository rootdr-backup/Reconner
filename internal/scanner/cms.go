package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/recon-platform/internal/database"
)

// Native CMS detector. Given a live URL it does ONE benign GET and identifies the
// CMS (WordPress, Joomla, Drupal, …) from strong, CMS-specific markers in the
// HTML, headers and links. Accuracy over recall: it only reports a CMS when a
// signature that is essentially unique to that CMS is present, so a "wordpress"
// verdict is trustworthy enough to gate scanning decisions on.
//
// Why it matters: blindly firing per-parameter XSS/SQLi/DAST at a stock
// WordPress or Joomla install is mostly wasted effort and a false-positive
// magnet — the core is widely patched and the real, exploitable surface (known
// plugin/core CVEs) is already covered by nuclei's CMS templates. So the scanner
// SKIPS the active injection modules on a detected WP/Joomla host (see
// loadCMSSkipHosts) while keeping nuclei's CMS-aware checks.

var cmsFingerprintClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: sharedHTTPTransport,
	CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// detectCMS returns "wordpress", "joomla", "drupal", … or "" if none is
// confidently fingerprinted.
func detectCMS(ctx context.Context, rawURL string) string {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := cmsFingerprintClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	gen := strings.ToLower(resp.Header.Get("X-Generator"))
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))
	cookies := strings.ToLower(strings.Join(resp.Header.Values("Set-Cookie"), "; "))
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	body := strings.ToLower(string(bodyBytes))

	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(body, s) {
				return true
			}
		}
		return false
	}

	switch {
	// ── WordPress ──
	case strings.Contains(gen, "wordpress"),
		strings.Contains(cookies, "wordpress_"), strings.Contains(cookies, "wp-settings"),
		has("/wp-content/", "/wp-includes/", "wp-json", "/wp-login.php"),
		strings.Contains(body, `name="generator" content="wordpress`):
		return "wordpress"
	// ── Joomla ──
	case strings.Contains(gen, "joomla"),
		has("/media/jui/", "/media/system/js/", "com_content", "option=com_",
			`name="generator" content="joomla`, "/administrator/index.php"):
		return "joomla"
	// ── Drupal ──
	case strings.Contains(gen, "drupal"), strings.Contains(poweredBy, "drupal"),
		has("drupal.settings", "/sites/default/files/", "/sites/all/", "drupal-",
			`name="generator" content="drupal`):
		return "drupal"
	// ── A few more, reported but not skipped (no XSS/SQLi skip for these) ──
	case has("/typo3/", "typo3temp/"):
		return "typo3"
	case has("cdn.shopify.com", "shopify.") || strings.Contains(poweredBy, "shopify"):
		return "shopify"
	case has("/_next/static/") && has("__next_data__"):
		return "next.js"
	}
	return ""
}

// cmsSkipsInjection reports whether a detected CMS should have the active
// injection/DAST modules skipped on it. Only the mass-market PHP CMSes whose
// stock surface is a proven false-positive magnet qualify; app frameworks
// (Next.js/Shopify/…) are NOT skipped — they carry real custom logic.
func cmsSkipsInjection(cms string) bool {
	switch strings.ToLower(strings.TrimSpace(cms)) {
	case "wordpress", "joomla", "drupal":
		return true
	}
	return false
}

// loadCMSSkipHosts returns the set of hostnames for a target whose detected CMS
// means the active injection/DAST modules should skip them (stock WP/Joomla/
// Drupal). Empty when no such host exists — callers then scan everything.
func loadCMSSkipHosts(db *database.DB, targetID string) map[string]bool {
	set := map[string]bool{}
	rows, err := db.Query(`SELECT url, COALESCE(cms,'') FROM http_services WHERE target_id=? AND COALESCE(cms,'') <> ''`, targetID)
	if err != nil {
		return set
	}
	defer rows.Close()
	for rows.Next() {
		var u, cms string
		if rows.Scan(&u, &cms) == nil && cmsSkipsInjection(cms) {
			if h := hostOf(u); h != "" {
				set[h] = true
			}
		}
	}
	return set
}

// hostSkippedByCMS reports whether rawURL's host is a CMS the injection modules
// should skip. A nil/empty set means "skip nothing".
func hostSkippedByCMS(rawURL string, skip map[string]bool) bool {
	if len(skip) == 0 {
		return false
	}
	return skip[hostOf(rawURL)]
}
