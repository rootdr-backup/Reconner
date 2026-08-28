package scanner

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Request Intelligence layer (P0-3 / Phase 8). A canonical, normalized model for
// HTTP interactions plus fingerprinting and semantic comparison utilities that
// scanners can migrate onto over time (adapters, not a big-bang rewrite).

// CanonRequest is the normalized request.
type CanonRequest struct {
	Method        string
	URL           string
	NormURL       string
	IdentityLabel string
	Scanner       string
}

// CanonResponse is the normalized response.
type CanonResponse struct {
	Status int
	CT     string
	Len    int
	Hash   string
	Body   string
	TimeMs int64
}

var reNumSegments = regexp.MustCompile(`/\d+`)

// NormalizeURL produces a stable template for a URL: sorted query keys (values
// dropped) and numeric path segments collapsed to {id}. This lets us recognize
// that /api/orders/1 and /api/orders/2 are the SAME endpoint.
func NormalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	path := reNumSegments.ReplaceAllString(u.Path, "/{id}")
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	norm := u.Scheme + "://" + u.Host + path
	if len(keys) > 0 {
		norm += "?" + strings.Join(keys, "&")
	}
	return norm
}

// BodyHash returns a stable fingerprint of a response body with volatile tokens
// (CSRF/nonce/timestamps) blurred, so two structurally-identical responses hash
// the same even if a nonce differs.
var reVolatileKV = regexp.MustCompile(`(?i)"(csrf|xsrf|_?csrf_?token|nonce|token|ts|timestamp|time|updated_at|created_at|expires?|iat|exp)"\s*:\s*"?[^",}\s]+"?`)

// reEpochish is hoisted to package scope (it was recompiled on every BodyHash
// call — a needless cost in a hot comparison path).
var reEpochish = regexp.MustCompile(`\d{10,}`)

// blurVolatile masks fields that legitimately change between two responses to the
// SAME object — csrf/nonce/token/timestamps, api keys, JWTs, epoch-ish numbers —
// so a rotating value is never counted as a real content difference.
func blurVolatile(body string) string {
	b := reVolatileKV.ReplaceAllString(body, `"$1":X`)
	b = reAPIKeyKV.ReplaceAllString(b, "$1=X")
	b = reJWT.ReplaceAllString(b, "X")
	return reEpochish.ReplaceAllString(b, "N")
}

func BodyHash(body string) string {
	sum := sha1.Sum([]byte(blurVolatile(body)))
	return hex.EncodeToString(sum[:])
}

// SemanticCompare classifies the relationship between two responses beyond
// status codes: same-object | different-object | one-denied | both-denied |
// ambiguous.
func SemanticCompare(a, b IdentityResponse) string {
	da, db := deniesAccess(a), deniesAccess(b)
	switch {
	case da && db:
		return "both-denied"
	case da != db:
		return "one-denied"
	case bodiesSameObject(a.Body, b.Body):
		return "same-object"
	case a.Status == b.Status && a.CT == b.CT:
		return "different-object"
	default:
		return "ambiguous"
	}
}

// RecordInteraction persists a normalized interaction to http_interactions
// (best-effort; never blocks a scan on failure).
func RecordInteraction(ctx context.Context, db *database.DB, targetID string, req CanonRequest, resp CanonResponse) {
	if req.NormURL == "" {
		req.NormURL = NormalizeURL(req.URL)
	}
	if resp.Hash == "" && resp.Body != "" {
		resp.Hash = BodyHash(resp.Body)
	}
	_, _ = db.ExecContext(ctx, `
		INSERT INTO http_interactions
		 (id, target_id, identity_label, method, url, norm_url, status, content_type, resp_len, resp_hash, timing_ms, scanner)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, req.IdentityLabel, req.Method, req.URL, req.NormURL,
		resp.Status, resp.CT, resp.Len, resp.Hash, resp.TimeMs, req.Scanner)
}
