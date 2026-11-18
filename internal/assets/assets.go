// Package assets holds small, dependency-free helpers for classifying scope
// assets. Both the bounty importer and the scheduler use these helpers so the
// same asset is treated the same way before and after it is stored.
package assets

import (
	"net/url"
	"strings"
)

// AppStoreHosts are hosts that only serve mobile or desktop app listings.
// Matching an exact host avoids excluding a legitimate apex scope such as
// apple.com or google.com.
var AppStoreHosts = map[string]bool{
	"play.google.com":           true,
	"apps.apple.com":            true,
	"itunes.apple.com":          true,
	"appstore.apple.com":        true,
	"apps.microsoft.com":        true,
	"appgallery.huawei.com":     true,
	"store.steampowered.com":    true,
	"chromewebstore.google.com": true,
}

var appStorePaths = []string{
	"/store/apps/details",
	"/store/apps/",
	"/us/app/",
	"/store/app/",
}

// IsAppStoreAsset reports whether an identifier points to a mobile or desktop
// app listing instead of a web origin that Reconner can enumerate.
func IsAppStoreAsset(identifier string) bool {
	raw := strings.ToLower(strings.TrimSpace(identifier))
	if raw == "" {
		return false
	}

	host := raw
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		host = parsed.Hostname()
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	host = strings.TrimPrefix(host, "*.")
	if AppStoreHosts[host] {
		return true
	}

	// Marketplace app pages are listings too. Match the store host together
	// with its app path so an unrelated /apps/ route on another host is safe.
	if strings.Contains(raw, "marketplace.atlassian.com/apps/") || strings.Contains(raw, "chrome.google.com/webstore/") {
		return true
	}

	for _, path := range appStorePaths {
		if strings.Contains(raw, path) {
			return true
		}
	}

	// Apple App Store IDs appear as /app/<name>/id<digits>. Require actual
	// digits after "id" so a normal path such as /app/identity is not excluded.
	if index := strings.Index(raw, "/app/"); index >= 0 {
		rest := raw[index+len("/app/"):]
		if strings.HasPrefix(rest, "id") && startsWithDigit(strings.TrimPrefix(rest, "id")) {
			return true
		}
		if pos := strings.Index(rest, "/id"); pos >= 0 && startsWithDigit(rest[pos+len("/id"):]) {
			return true
		}
	}
	return false
}

func startsWithDigit(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

// IsWebShapedIdentifier reports whether raw can work as a DNS root or an HTTP
// seed. Providers sometimes put a prose note in an asset whose declared type
// is "domain" or "url". Those notes are not hosts and must not become scan
// roots. A host may carry a path suffix, as in example.com/app/login.
func IsWebShapedIdentifier(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, " \t\r\n()[]<>\"'|") {
		return false
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		u, err := url.Parse(v)
		return err == nil && u.Host != "" && validHostname(u.Hostname())
	}
	host := v
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimPrefix(host, "*.")
	if h, port, ok := strings.Cut(host, ":"); ok && port != "" && allDigits(port) {
		host = h // host:port is a valid HTTP seed
	}
	return validHostname(host)
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validHostname(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if strings.ContainsAny(host, " /:@?#,;\\") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '*':
			case r == '-' || r == '_':
			default:
				return false
			}
		}
	}
	return true
}

// IsScannableWebAsset reports whether an asset may enter watch or deep
// enumeration and HTTP probing.
func IsScannableWebAsset(assetType, identifier string) bool {
	t := strings.ToLower(strings.TrimSpace(assetType))
	switch t {
	case "app_store", "android", "ios", "hardware", "source_code", "other", "reference",
		"cidr", "ip", "network", "ip_address":
		return false
	}
	if IsAppStoreAsset(identifier) {
		return false
	}
	if !IsWebShapedIdentifier(identifier) {
		return false
	}
	switch t {
	case "domain", "wildcard", "url", "page", "js", "api":
		return true
	default:
		return false
	}
}
