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
	"play.google.com":        true,
	"apps.apple.com":         true,
	"itunes.apple.com":       true,
	"appstore.apple.com":     true,
	"apps.microsoft.com":     true,
	"appgallery.huawei.com":  true,
	"store.steampowered.com": true,
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
	switch t {
	case "domain", "wildcard", "url", "page", "js", "api":
		return true
	default:
		return false
	}
}
