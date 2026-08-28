package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
)

// ── P0-1: first-class identity + cross-identity authorization primitive ───────
//
// This is the reusable foundation the audit calls out as the #1 gap: authz bugs
// (BOLA/IDOR/BFLA/priv-esc) are defined by the DIFFERENCE BETWEEN USERS, so they
// cannot be found — let alone proven — with a single auth blob. Every authz
// scanner should build on THIS, not re-implement per-user logic.

// Identity is a structured authentication context for one labelled test user.
type Identity struct {
	ID         string
	Label      string
	Role       string
	Headers    map[string]string // request headers to replay (Cookie/Authorization/CSRF)
	IsBaseline bool

	// Structured auth-context (Phase 1)
	AuthMethod       string            // headers | browser-capture | bearer
	Origin           string            // scheme://host the session belongs to
	UserAgent        string            // captured UA (replayed for consistency)
	Storage          map[string]string // browser local/session storage (when required)
	ValidationURL    string            // endpoint used to check the session
	ValidationSignal string            // substring that means "authenticated" (empty = heuristic)
	Status           string            // authenticated | expired | unauthenticated | unknown
	CapturedAt       *time.Time
	LastVerifiedAt   *time.Time
	ExpiresAt        *time.Time
}

// IdentityResponse is one identity's view of a replayed request.
type IdentityResponse struct {
	Identity Identity
	Status   int
	CT       string
	NoSniff  bool // response carried X-Content-Type-Options: nosniff
	Body     string
	Len      int
	Err      error
}

// identityHTTPClient is the ONE client that replays captured credentials
// (Cookie/Authorization). It uses the guarded, destination-validating, IP-pinning
// transport (see destination.go) so an in-scope hostname that resolves — or is
// rebound — to loopback/private/metadata can never receive those credentials, and
// CheckRedirect refuses to follow ANY redirect: a 302 is returned as-is (it IS the
// signal), which also guarantees credentials are never re-sent to a redirect
// target (in- or out-of-scope). Both halves of the boundary — hostname scope
// (URLInScope, enforced by callers) and DNS/IP (this transport) — are explicit.
var identityHTTPClient = &http.Client{
	Transport: guardedCredentialTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // never follow — no creds to any redirect target
	},
}

// LoadIdentities returns every test identity for a target. For backward
// compatibility, when no `identities` rows exist but the legacy single
// `targets.auth_headers` blob is set, it is surfaced as one baseline identity —
// so existing single-user setups keep working and new multi-user setups unlock
// true cross-identity testing.
func LoadIdentities(ctx context.Context, db *database.DB, targetID string, box *secret.Box) []Identity {
	rows, err := db.QueryContext(ctx,
		`SELECT id, label, role, COALESCE(headers_json,'{}'), COALESCE(is_baseline,0),
		        COALESCE(auth_method,'headers'), COALESCE(origin,''), COALESCE(user_agent,''),
		        COALESCE(storage_json,''), COALESCE(validation_url,''), COALESCE(validation_signal,''),
		        COALESCE(status,'unknown')
		 FROM identities WHERE target_id = ? ORDER BY is_baseline DESC, created_at ASC`, targetID)
	var out []Identity
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id Identity
			var hjson, sjson string
			var base int
			if rows.Scan(&id.ID, &id.Label, &id.Role, &hjson, &base,
				&id.AuthMethod, &id.Origin, &id.UserAgent, &sjson,
				&id.ValidationURL, &id.ValidationSignal, &id.Status) != nil {
				continue
			}
			// Secrets are encrypted at rest — decrypt for replay.
			if box != nil {
				hjson = box.Decrypt(hjson)
				if sjson != "" {
					sjson = box.Decrypt(sjson)
				}
			}
			id.Headers = map[string]string{}
			_ = json.Unmarshal([]byte(hjson), &id.Headers)
			if sjson != "" {
				id.Storage = map[string]string{}
				_ = json.Unmarshal([]byte(sjson), &id.Storage)
			}
			id.IsBaseline = base != 0
			if len(id.Headers) > 0 {
				out = append(out, id)
			}
		}
	}
	if len(out) > 0 {
		// Guarantee exactly one baseline.
		hasBase := false
		for _, i := range out {
			if i.IsBaseline {
				hasBase = true
				break
			}
		}
		if !hasBase {
			out[0].IsBaseline = true
		}
		return out
	}

	// Legacy fallback: single auth_headers blob → one baseline identity.
	if legacy := loadAuthHeaders(ctx, db, targetID); len(legacy) > 0 {
		return []Identity{{ID: "legacy", Label: "user", Role: "user", Headers: legacy, IsBaseline: true}}
	}
	return nil
}

// baselineIdentity returns the identity flagged baseline (or the first).
func baselineIdentity(ids []Identity) (Identity, bool) {
	for _, i := range ids {
		if i.IsBaseline {
			return i, true
		}
	}
	if len(ids) > 0 {
		return ids[0], true
	}
	return Identity{}, false
}

// fetchAs performs a GET of url as a specific identity (nil identity = no auth,
// used to prove a resource is actually protected). Bodies are capped.
func fetchAs(ctx context.Context, url string, id *Identity) IdentityResponse {
	var who Identity
	if id != nil {
		who = *id
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return IdentityResponse{Identity: who, Err: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	if id != nil {
		if id.UserAgent != "" {
			req.Header.Set("User-Agent", id.UserAgent)
		}
		for k, v := range id.Headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := identityHTTPClient.Do(req)
	if err != nil {
		return IdentityResponse{Identity: who, Err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return IdentityResponse{
		Identity: who,
		Status:   resp.StatusCode,
		CT:       resp.Header.Get("Content-Type"),
		Body:     string(b),
		Len:      len(b),
	}
}

// ReplayAcross fetches the same URL as every identity plus once unauthenticated,
// returning all views so a caller can build an authorization matrix.
func ReplayAcross(ctx context.Context, url string, ids []Identity) (unauth IdentityResponse, perIdentity []IdentityResponse) {
	unauth = fetchAs(ctx, url, nil)
	for i := range ids {
		perIdentity = append(perIdentity, fetchAs(ctx, url, &ids[i]))
	}
	return
}

// ── Session validation (Phase 4) ─────────────────────────────────────────────

// ValidateSession decides whether an identity's session is still authenticated.
// It does NOT assume 200 = authenticated. It fetches the validation endpoint (or
// the identity's origin as a fallback) and compares the authenticated vs
// unauthenticated response: a session is authenticated when it can reach content
// that the unauthenticated request cannot (and, if configured, the
// ValidationSignal substring is present). Returns one of
// authenticated|unauthenticated|expired|unknown.
func ValidateSession(ctx context.Context, id Identity) string {
	url := id.ValidationURL
	if url == "" {
		url = id.Origin
	}
	if url == "" {
		return "unknown"
	}
	authed := fetchAs(ctx, url, &id)
	if authed.Err != nil {
		return "unknown"
	}
	// Explicit signal wins when configured.
	if id.ValidationSignal != "" {
		if strings.Contains(authed.Body, id.ValidationSignal) {
			return "authenticated"
		}
		return "expired"
	}
	// Heuristic: authenticated must NOT look denied, AND must differ from the
	// unauthenticated view (proving the session actually grants access).
	if deniesAccess(authed) {
		return "expired"
	}
	unauth := fetchAs(ctx, url, nil)
	if deniesAccess(unauth) || (unauth.Status == 200 && !bodiesSameObject(unauth.Body, authed.Body)) {
		return "authenticated"
	}
	// Same content with and without the session → the endpoint is public, can't
	// prove authentication from it.
	return "unknown"
}

// ── Authorization matrix (Phase 6) ───────────────────────────────────────────

// MatrixCell is one identity's result against one resource URL.
type MatrixCell struct {
	IdentityLabel string
	URL           string
	Resp          IdentityResponse
	Verdict       string // authorized | denied | ambiguous
}

// AuthzMatrix replays two identities against two resources (A owns URLA, B owns
// URLB) and classifies every cell. It records the full A→A, B→B, A→B, B→A grid
// so a caller can decide vulnerability with strong, non-status-only signal.
func AuthzMatrix(ctx context.Context, a, b Identity, urlA, urlB string) []MatrixCell {
	grid := []struct {
		id  Identity
		url string
	}{
		{a, urlA}, {b, urlB}, {a, urlB}, {b, urlA},
	}
	var out []MatrixCell
	for _, g := range grid {
		id := g.id
		r := fetchAs(ctx, g.url, &id)
		verdict := "ambiguous"
		if looksLikeAuthObject(r) {
			verdict = "authorized"
		} else if deniesAccess(r) {
			verdict = "denied"
		}
		out = append(out, MatrixCell{IdentityLabel: id.Label, URL: g.url, Resp: r, Verdict: verdict})
	}
	return out
}

// looksLikeAuthObject reports whether a response is a real, substantial,
// authenticated object body (not an error page, redirect, or static asset).
func looksLikeAuthObject(r IdentityResponse) bool {
	if r.Err != nil || r.Status != 200 || r.Len < 120 {
		return false
	}
	if isStaticCT(r.CT) {
		return false
	}
	return matchAny(strings.ToLower(r.Body), idorErrorSignatures) == ""
}

// deniesAccess reports whether a response represents access being denied /
// resource-not-visible (401/403/redirect-to-login/empty/error page).
func deniesAccess(r IdentityResponse) bool {
	if r.Err != nil {
		return true
	}
	if r.Status == 401 || r.Status == 403 || r.Status == 404 {
		return true
	}
	if r.Status >= 300 && r.Status < 400 {
		return true // redirect (typically to login)
	}
	if r.Status == 200 && (r.Len < 80 || matchAny(strings.ToLower(r.Body), idorErrorSignatures) != "") {
		return true
	}
	return false
}
