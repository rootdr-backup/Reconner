// Package browser turns a manually-authenticated browser session into a
// Reconner AuthContext. The researcher completes login (incl. CAPTCHA/OTP/MFA/
// SSO) in a real browser; Reconner only CAPTURES the resulting session. Two
// modes, one output:
//
//   - Import mode (works everywhere, incl. headless servers): the researcher
//     exports a standard Playwright/Chrome `storageState` JSON from their own
//     browser and imports it. ParseStorageState handles this — pure, testable.
//   - Desktop mode (needs a display): CaptureHeadful launches a headful Chromium
//     via chromedp, the researcher logs in, and we extract cookies + storage via
//     CDP. Only meaningful where Reconner runs on the researcher's machine.
//
// The browser is an AUTHENTICATION mechanism only. All subsequent testing runs
// through the shared HTTP client, never Playwright/Chromium.
package browser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// CapturedContext is the minimum session material needed to replay an
// authenticated session. Secrets here are encrypted by the caller before storage.
type CapturedContext struct {
	Origin         string            // scheme://host the session belongs to
	UserAgent      string            // captured UA, replayed for consistency
	CookieHeader   string            // ready-to-replay "Cookie: k=v; k2=v2"
	LocalStorage   map[string]string // captured only for the target origin
	SessionStorage map[string]string
}

// storageState mirrors the Playwright/Chrome `storageState()` JSON shape.
type storageState struct {
	Cookies []struct {
		Name   string `json:"name"`
		Value  string `json:"value"`
		Domain string `json:"domain"`
		Path   string `json:"path"`
	} `json:"cookies"`
	Origins []struct {
		Origin       string `json:"origin"`
		LocalStorage []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"localStorage"`
	} `json:"origins"`
}

// ParseStorageState converts a Playwright/Chrome storageState JSON into a
// CapturedContext scoped to targetOrigin (scheme://host). Only cookies whose
// domain matches the target host and localStorage for the target origin are
// kept — we do not indiscriminately hoover every value.
func ParseStorageState(raw []byte, targetOrigin string) (CapturedContext, error) {
	var st storageState
	if err := json.Unmarshal(raw, &st); err != nil {
		return CapturedContext{}, fmt.Errorf("invalid storageState JSON: %w", err)
	}
	host := hostOf(targetOrigin)
	if host == "" {
		return CapturedContext{}, fmt.Errorf("targetOrigin must be scheme://host")
	}

	var pairs []string
	for _, c := range st.Cookies {
		if c.Name == "" {
			continue
		}
		if domainMatches(c.Domain, host) {
			pairs = append(pairs, c.Name+"="+c.Value)
		}
	}
	sort.Strings(pairs) // deterministic for tests + stable evidence

	ls := map[string]string{}
	for _, o := range st.Origins {
		if hostOf(o.Origin) == host {
			for _, kv := range o.LocalStorage {
				ls[kv.Name] = kv.Value
			}
		}
	}

	if len(pairs) == 0 && len(ls) == 0 {
		return CapturedContext{}, fmt.Errorf("no session material found for %s", host)
	}
	return CapturedContext{
		Origin:       targetOrigin,
		CookieHeader: strings.Join(pairs, "; "),
		LocalStorage: ls,
	}, nil
}

// Headers renders the replay headers (Cookie + optional UA) for the identity model.
func (c CapturedContext) Headers() map[string]string {
	h := map[string]string{}
	if c.CookieHeader != "" {
		h["Cookie"] = c.CookieHeader
	}
	return h
}

// unmarshalStringMap decodes a JSON object of string→string into dst.
func unmarshalStringMap(raw []byte, dst map[string]string) error {
	tmp := map[string]string{}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return err
	}
	for k, v := range tmp {
		dst[k] = v
	}
	return nil
}

func hostOf(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	if !strings.Contains(origin, "://") {
		origin = "https://" + origin
	}
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// domainMatches implements cookie-domain matching: a leading-dot domain matches
// the host and its subdomains; otherwise exact host match.
func domainMatches(cookieDomain, host string) bool {
	cd := strings.ToLower(strings.TrimSpace(cookieDomain))
	cd = strings.TrimPrefix(cd, ".")
	if cd == "" {
		return true // host-only cookie captured for this origin
	}
	return host == cd || strings.HasSuffix(host, "."+cd)
}
