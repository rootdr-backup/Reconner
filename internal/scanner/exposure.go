package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// ExposureScanner bundles cheap, high-signal active checks that surface real
// bounty-class exposures: GraphQL introspection, API-spec leaks, and open
// cloud storage buckets.
type ExposureScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewExposureScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *ExposureScanner {
	return &ExposureScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var exposureHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   12 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func (s *ExposureScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	if err := s.runGraphQL(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.runGraphQLDeep(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.runAPISpec(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.runOpenBuckets(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.runGitExposure(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.runConfigLeaks(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.runJWTChecks(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// ── Exposed .env / config file + .DS_Store (keyless) ─────────────────────────

// envSecretRe matches an env-style assignment of a SENSITIVE key to a non-trivial
// value (DB_PASSWORD=…, AWS_SECRET_ACCESS_KEY=…, STRIPE_SECRET=…). Anchored to a
// line start so it fires on a real dotenv/properties file, not prose.
var envSecretRe = regexp.MustCompile(`(?im)^\s*[A-Z0-9_]*(?:PASSWORD|SECRET|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTH[_-]?TOKEN|DB_PASS|STRIPE|TWILIO|SENDGRID|MAILGUN)[A-Z0-9_]*\s*[:=]\s*\S{6,}`)

// bodyLeaksSecret reports the kind of credential a config/env body exposes, or ""
// when the body is an HTML page or holds only framework defaults (no secret). It
// reuses the shared JS/secret pattern set (skipping the low-signal endpoint/URL
// types that would match any config) plus an env-style sensitive-assignment probe.
// This is what keeps the direct .env/config check near-zero-FP: a 200 alone is
// never a finding — only a 200 whose body carries a real secret is.
func bodyLeaksSecret(body string) string {
	if body == "" || strings.Contains(strings.ToLower(body), "<html") ||
		strings.Contains(strings.ToLower(body), "<!doctype html") {
		return ""
	}
	lowSignal := map[string]bool{
		"endpoint": true, "api_url": true, "config": true, "auth_endpoint": true,
		"debug_endpoint": true, "sourcemap": true, "internal_url": true,
		"websocket": true, "graphql": true, "s3_bucket": true, "firebase": true,
	}
	for _, p := range jsPatterns {
		if lowSignal[p.Type] {
			continue
		}
		if p.Pattern.MatchString(body) {
			return p.Type
		}
	}
	for _, p := range extraSecretPatterns {
		if !lowSignal[p.Type] && p.Pattern.MatchString(body) {
			return p.Type
		}
	}
	if envSecretRe.MatchString(body) {
		return "env credential"
	}
	return ""
}

// runConfigLeaks fetches the highest-signal directly-servable config/secret files
// (dotenv, framework config, cloud creds) and the macOS .DS_Store directory index.
// A config file is reported ONLY when its body actually contains a secret (see
// bodyLeaksSecret); .DS_Store is reported on its binary magic (a real directory
// listing leak, not an HTML 200). Both are keyless, high-signal recon wins drawn
// straight from the web2-recon Source-Disclosure playbook.
func (s *ExposureScanner) runConfigLeaks(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "exposure", "Checking for exposed .env / config files + .DS_Store...")
	bases := s.loadServiceBases(ctx, targetID, 200)

	configPaths := []string{
		"/.env", "/.env.local", "/.env.production", "/.env.dev", "/.env.staging",
		"/appsettings.json", "/appsettings.Production.json",
		"/application.properties", "/application.yml", "/application.yaml",
		"/config.php.bak", "/config.json", "/config.yml", "/secrets.json",
		"/.aws/credentials", "/.npmrc", "/.dockercfg", "/database.yml",
	}

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var found atomic.Int64

	fetch := func(u string) (int, string) {
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
		if err != nil {
			return 0, ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
		resp, err := exposureHTTPClient.Do(req)
		if err != nil {
			return 0, ""
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		return resp.StatusCode, string(body)
	}

	// One goroutine per base: establish the host's soft-404 baseline ONCE, then run
	// all its probes against it. The baseline is the FP killer here — a SPA/catch-all
	// host that answers 200 for every path (its JS bundle can itself contain an API
	// key that bodyLeaksSecret would match) must not have "/.env" reported as a leak.
	for _, base := range bases {
		b := strings.TrimRight(base, "/")
		wg.Add(1)
		sem <- struct{}{}
		go func(b string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			bl := soft404Baseline(ctx, b)

			// .DS_Store — binary magic (bytes 4..8 == "Bud1"). Its magic check
			// already excludes any HTML/JS catch-all, so no baseline gate needed.
			if code, body := fetch(b + "/.DS_Store"); code == 200 &&
				len(body) >= 8 && body[4:8] == "Bud1" {
				s.store(targetID, "exposed_ds_store", "low", b+"/.DS_Store", "",
					"Exposed .DS_Store — leaks the directory's file/folder names (map hidden backups, source, admin paths; recurse with ds_store_exp)")
				found.Add(1)
				logFn("warn", "exposure", "Exposed .DS_Store: "+b+"/.DS_Store")
				s.notify(targetID, "exposed_ds_store", b+"/.DS_Store")
			}

			for _, path := range configPaths {
				if ctx.Err() != nil {
					return
				}
				code, body := fetch(b + path)
				if code != 200 {
					continue
				}
				// Catch-all guard: if this 200 looks like the host's bogus-path
				// baseline, it's the SPA/error page served for everything, not a real
				// distinct config file — skip it even if the baseline body happens to
				// contain a secret-looking string.
				if bl.matches(code, []byte(body), "") {
					continue
				}
				kind := bodyLeaksSecret(body)
				if kind == "" {
					continue
				}
				s.store(targetID, "exposed_config", "high", b+path, "",
					fmt.Sprintf("Exposed config file %s served directly and leaking a %s — verify the secret works, then chain to the account/service it unlocks", path, kind))
				found.Add(1)
				logFn("warn", "exposure", fmt.Sprintf("Exposed config file leaking %s: %s%s", kind, b, path))
				s.notify(targetID, "exposed_config", b+path)
			}
		}(b)
	}
	wg.Wait()
	logFn("info", "exposure", fmt.Sprintf("Config/DS_Store exposure check done. Found %d.", found.Load()))
	return nil
}

// ── Exposed .git / VCS directory (keyless) ───────────────────────────────────

// runGitExposure detects a publicly reachable .git directory, which allows the
// entire source repo to be reconstructed with git-dumper. Requires no API key.
func (s *ExposureScanner) runGitExposure(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "exposure", "Checking for exposed .git / .svn / .hg directories...")

	bases := s.loadServiceBases(ctx, targetID, 300)
	checks := []struct{ path, marker, vcs string }{
		{"/.git/HEAD", "ref:", "git"},
		{"/.git/config", "[core]", "git"},
		{"/.svn/entries", "", "svn"},
		{"/.hg/requires", "", "hg"},
		{"/.bzr/branch-format", "Bazaar", "bzr"},
	}

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var found atomic.Int64
	seen := &sync.Map{} // avoid duplicate report per base

	for _, base := range bases {
		for _, c := range checks {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(b, path, marker, vcs string) {
				defer wg.Done()
				defer func() { <-sem }()

				u := strings.TrimRight(b, "/") + path
				reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
				if err != nil {
					cancel()
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
				resp, err := exposureHTTPClient.Do(req)
				if err != nil {
					cancel()
					return
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				resp.Body.Close()
				cancel()

				if resp.StatusCode != 200 {
					return
				}
				bs := string(body)
				// Must look like real VCS metadata (not an HTML catch-all page).
				valid := (vcs == "git" && (strings.HasPrefix(bs, "ref:") || strings.Contains(bs, "[core]"))) ||
					(vcs == "svn" && (strings.Contains(bs, "dir") || len(bs) < 400)) ||
					(vcs == "hg" && len(bs) < 200) ||
					(vcs == "bzr" && strings.Contains(bs, "Bazaar"))
				if marker != "" && !strings.Contains(bs, marker) {
					valid = false
				}
				if strings.Contains(strings.ToLower(bs), "<html") {
					valid = false
				}
				if !valid {
					return
				}
				if _, dup := seen.LoadOrStore(b+vcs, true); dup {
					return
				}
				s.store(targetID, "exposed_"+vcs, "high", strings.TrimRight(b, "/")+"/."+vcs+"/", "",
					fmt.Sprintf("Exposed %s directory — full source recoverable (e.g. git-dumper)", vcs))
				found.Add(1)
				logFn("warn", "exposure", fmt.Sprintf("Exposed .%s directory: %s", vcs, u))
				s.notify(targetID, "exposed_"+vcs, u)
			}(base, c.path, c.marker, c.vcs)
		}
	}
	wg.Wait()
	logFn("info", "exposure", fmt.Sprintf("VCS exposure check done. Found %d.", found.Load()))
	return nil
}

// ── JWT weakness checks (alg:none, weak HMAC secret) ─────────────────────────

var jwtWeakSecrets = []string{
	"secret", "password", "123456", "key", "jwt", "token", "changeme",
	"admin", "test", "your-256-bit-secret", "your_jwt_secret", "supersecret",
	"secretkey", "private", "s3cr3t", "qwerty", "12345678", "0000",
	// expanded common/default HMAC secrets seen in the wild and in frameworks
	"secret123", "jwtsecret", "jwt_secret", "mysecret", "mysecretkey", "secretpassword",
	"password123", "root", "toor", "default", "example", "demo", "dev", "development",
	"production", "staging", "shhhh", "letmein", "welcome", "iloveyou", "sunshine",
	"secretKey", "SecretKey", "JWT_SECRET", "auth", "authsecret", "hmac", "hmackey",
	"application-secret", "app-secret", "appsecret", "signingkey", "signing_key",
	"1234567890", "abc123", "passw0rd", "P@ssw0rd", "keyboardcat", "youshallnotpass",
	"MIGfMA0GCSqGSIb3DQEB", "verysecret", "topsecret", "nosecret", "randomsecret",
}

// sensitiveClaimKeys are JWT payload fields that shouldn't be exposed — a JWT is
// only base64, so anyone holding it can read these.
var sensitiveClaimKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "secret": true, "api_key": true,
	"apikey": true, "access_token": true, "refresh_token": true, "private_key": true,
	"ssn": true, "credit_card": true, "card": true, "cvv": true, "pin": true,
	"is_admin": true, "isadmin": true, "role": true, "roles": true, "admin": true,
	"permissions": true, "scope": true, "email": true, "phone": true, "address": true,
	"salary": true, "dob": true, "national_id": true, "passport": true,
}

// sensitiveClaims returns the names of sensitive claims present in the payload.
func sensitiveClaims(claims map[string]any) []string {
	var out []string
	for k := range claims {
		if sensitiveClaimKeys[strings.ToLower(k)] {
			out = append(out, k)
		}
	}
	return out
}

// isDemoJWT reports whether a token is a well-known example/demo JWT (not a live
// credential) by its payload signature. Catches the jwt.io default token and its
// common variants — the dominant source of JWT false positives, since these are
// bundled verbatim into countless JS libraries, docs, and test fixtures.
func isDemoJWT(parts []string) bool {
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims map[string]any
	if json.Unmarshal(payloadJSON, &claims) != nil {
		return false
	}
	if name, _ := claims["name"].(string); strings.EqualFold(name, "John Doe") {
		return true // jwt.io default subject name
	}
	if sub, _ := claims["sub"].(string); sub == "1234567890" {
		return true // jwt.io default subject id
	}
	// jwt.io's fixed sample issued-at (2018-01-18T01:30:22Z).
	if iat, ok := claims["iat"].(float64); ok && iat == 1516239022 {
		return true
	}
	return false
}

func (s *ExposureScanner) runJWTChecks(ctx context.Context, targetID string, logFn LogFunc) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT value FROM js_findings
		WHERE target_id = ? AND type = 'jwt' LIMIT 200
	`, targetID)
	if err != nil {
		return nil
	}
	var tokens []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err == nil {
			tokens = append(tokens, v)
		}
	}
	rows.Close()
	if len(tokens) == 0 {
		return nil
	}

	logFn("info", "exposure", fmt.Sprintf("Analyzing %d JWTs for weaknesses...", len(tokens)))
	found := 0
	for _, tok := range tokens {
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			continue
		}
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}
		var hdr map[string]any
		if json.Unmarshal(headerJSON, &hdr) != nil {
			continue
		}
		alg, _ := hdr["alg"].(string)
		alg = strings.ToLower(alg)
		id := "jwt:" + parts[0]

		// Skip well-known DEMO/example JWTs shipped inside JS libraries, docs, and
		// test fixtures (jwt.io's default token is the canonical one). They are not
		// live credentials, yet analyzing them yields critical-looking noise — e.g.
		// the jwt.io sample is HS256-signed with "your-256-bit-secret", which is in
		// jwtWeakSecrets, so it would be "cracked" and reported as a critical weak-
		// secret finding on a token that unlocks nothing.
		if isDemoJWT(parts) {
			continue
		}

		// alg:none — signature strippable.
		if alg == "none" {
			s.store(targetID, "jwt_alg_none", "high", id, "",
				"JWT accepts alg:none — the signature can be stripped and the token forged.")
			found++
		}

		// Weak HMAC secret (crackable → full forgery).
		if alg == "hs256" || alg == "hs384" || alg == "hs512" {
			if secret := crackJWT(tok, parts, alg); secret != "" {
				s.store(targetID, "jwt_weak_secret", "critical", id, "",
					fmt.Sprintf("JWT signed with weak/guessable HMAC secret %q — tokens can be forged for any user.", secret))
				found++
				s.notify(targetID, "jwt_weak_secret", "jwt")
			}
		}

		// RS256 → HS256 algorithm-confusion HINT. An RS256 JWT is normal and secure
		// BY DEFAULT — it's only exploitable if the server ALSO accepts an HS256
		// token signed with the public key. We can't confirm that without the public
		// key + a forged-token replay, so this is an INFO advisory (a manual-test
		// pointer), never a medium finding — otherwise every RS256 token on the
		// internet would be flagged (the exact JWT-confusion false-positive noise).
		if alg == "rs256" || alg == "rs384" || alg == "rs512" {
			s.store(targetID, "jwt_alg_confusion_candidate", "info", id, "",
				"Advisory (not a confirmed issue): JWT uses "+strings.ToUpper(alg)+". IF the server also accepts HS256, an RS→HS algorithm-confusion forgery may be possible (sign with the public key as the HMAC secret). Manual verification required.")
			found++
		}

		// Risky header parameters that enable key injection / SSRF.
		for _, k := range []string{"jku", "x5u"} {
			if v, ok := hdr[k].(string); ok && v != "" {
				s.store(targetID, "jwt_"+k+"_header", "high", id, "",
					fmt.Sprintf("JWT %q header points to %q — if not strictly allow-listed, an attacker can host their own JWKS and forge tokens (also an SSRF vector).", k, v))
				found++
			}
		}
		// A `kid` header is present on virtually every JWKS-based JWT and is benign by
		// default — only a hint that the kid VALUE is worth manually fuzzing for
		// path-traversal / SQLi in the key lookup. INFO advisory, not a medium
		// finding, so a normal kid doesn't generate noise on every token.
		if v, ok := hdr["kid"].(string); ok && v != "" {
			s.store(targetID, "jwt_kid_injectable", "info", id, "",
				fmt.Sprintf("Advisory (not a confirmed issue): JWT carries kid=%q. Manually fuzz the kid for path-traversal / SQL injection (kid is often used to look up the signing key).", v))
			found++
		}

		// Payload analysis: sensitive-claim disclosure + missing expiry.
		if payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims map[string]any
			if json.Unmarshal(payloadJSON, &claims) == nil {
				if leaked := sensitiveClaims(claims); len(leaked) > 0 {
					s.store(targetID, "jwt_sensitive_claims", "medium", id, "",
						"JWT payload (readable by anyone — it is only base64) exposes sensitive claims: "+strings.Join(leaked, ", "))
					found++
				}
				if _, hasExp := claims["exp"]; !hasExp {
					s.store(targetID, "jwt_no_expiry", "low", id, "",
						"JWT has no exp claim — a stolen token never expires.")
					found++
				}
			}
		}
	}
	logFn("info", "exposure", fmt.Sprintf("JWT analysis done. Found %d weaknesses.", found))
	return nil
}

// crackJWT tries a small dictionary of weak HMAC secrets against the token,
// using the hash that matches the token's alg (HS256/384/512).
func crackJWT(token string, parts []string, alg string) string {
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ""
	}
	var h func() hash.Hash
	switch alg {
	case "hs384":
		h = sha512.New384
	case "hs512":
		h = sha512.New
	default: // hs256
		h = sha256.New
	}
	for _, secret := range jwtWeakSecrets {
		mac := hmac.New(h, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sig) {
			return secret
		}
	}
	return ""
}

// ── GraphQL introspection ────────────────────────────────────────────────────

const introspectionQuery = `{"query":"query{__schema{queryType{name} types{name kind}}}"}`

func (s *ExposureScanner) runGraphQL(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "exposure", "Probing for exposed GraphQL introspection...")

	bases := s.loadServiceBases(ctx, targetID, 200)
	paths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/query", "/gql", "/graphiql"}

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, base := range bases {
		for _, p := range paths {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-sem }()

				reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				req, err := http.NewRequestWithContext(reqCtx, "POST", u, strings.NewReader(introspectionQuery))
				if err != nil {
					cancel()
					return
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
				resp, err := exposureHTTPClient.Do(req)
				if err != nil {
					cancel()
					return
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				resp.Body.Close()
				cancel()

				b := string(body)
				// A working introspection response contains the schema root.
				if resp.StatusCode == 200 && strings.Contains(b, "__schema") && strings.Contains(b, "queryType") {
					s.store(targetID, "graphql_introspection", "medium", u, "",
						"GraphQL introspection enabled — full schema exposed")
					found.Add(1)
					logFn("warn", "exposure", "GraphQL introspection exposed: "+u)
					s.notify(targetID, "graphql_introspection", u)
				}
			}(strings.TrimRight(base, "/") + p)
		}
	}
	wg.Wait()
	logFn("info", "exposure", fmt.Sprintf("GraphQL check done. Found %d exposed endpoints.", found.Load()))
	return nil
}

// ── API spec discovery (Swagger / OpenAPI) ───────────────────────────────────

func (s *ExposureScanner) runAPISpec(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "exposure", "Looking for exposed API specs (Swagger/OpenAPI)...")

	bases := s.loadServiceBases(ctx, targetID, 200)
	paths := []string{
		"/swagger.json", "/openapi.json", "/v1/swagger.json", "/api/swagger.json",
		"/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json", "/openapi.yaml",
		"/swagger-ui.html", "/api/openapi.json", "/.well-known/openapi.json",
	}

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, base := range bases {
		for _, p := range paths {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-sem }()

				reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
				if err != nil {
					cancel()
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
				resp, err := exposureHTTPClient.Do(req)
				if err != nil {
					cancel()
					return
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				resp.Body.Close()
				cancel()

				b := string(body)
				if resp.StatusCode == 200 && (strings.Contains(b, "\"swagger\"") ||
					strings.Contains(b, "\"openapi\"") || strings.Contains(b, "\"paths\"") && strings.Contains(b, "\"definitions\"")) {
					s.store(targetID, "api_spec_exposed", "low", u, "",
						"API specification publicly accessible — reveals endpoints/params")
					found.Add(1)
					logFn("warn", "exposure", "API spec exposed: "+u)
					s.notify(targetID, "api_spec_exposed", u)
				}
			}(strings.TrimRight(base, "/") + p)
		}
	}
	wg.Wait()
	logFn("info", "exposure", fmt.Sprintf("API spec check done. Found %d specs.", found.Load()))
	return nil
}

// ── Open S3 / GCS bucket permission check ─────────────────────────────────────

func (s *ExposureScanner) runOpenBuckets(ctx context.Context, targetID string, logFn LogFunc) error {
	// Pull candidate bucket hosts previously found in JS (type s3_bucket/firebase).
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT value FROM js_findings
		WHERE target_id = ? AND type IN ('s3_bucket','firebase')
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var buckets []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err == nil {
			buckets = append(buckets, v)
		}
	}
	rows.Close()

	if len(buckets) == 0 {
		return nil
	}
	logFn("info", "exposure", fmt.Sprintf("Checking %d cloud buckets for public access...", len(buckets)))

	var found atomic.Int64
	for _, bkt := range buckets {
		if ctx.Err() != nil {
			break
		}
		u := bkt
		if !strings.HasPrefix(u, "http") {
			u = "https://" + u
		}
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
		resp, err := exposureHTTPClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		cancel()

		b := string(body)
		// Public, listable S3/GCS buckets return an XML listing with these tags.
		if resp.StatusCode == 200 && (strings.Contains(b, "<ListBucketResult") ||
			strings.Contains(b, "<Contents>") || strings.Contains(b, "<Key>")) {
			s.store(targetID, "open_bucket", "high", u, "",
				"Cloud storage bucket is publicly listable")
			found.Add(1)
			logFn("warn", "exposure", "Open/listable bucket: "+u)
			s.notify(targetID, "open_bucket", u)
		}
	}
	logFn("info", "exposure", fmt.Sprintf("Bucket check done. Found %d public buckets.", found.Load()))
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (s *ExposureScanner) loadServiceBases(ctx context.Context, targetID string, limit int) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT ?
	`, targetID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var bases []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			bases = append(bases, u)
		}
	}
	return filterURLsByHostScope(ctx, bases)
}

func (s *ExposureScanner) store(targetID, vulnType, severity, rawURL, param, evidence string) {
	id := uuid.New().String()
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence)
		VALUES (?, ?, ?, ?, ?, ?, '', ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity,
			evidence = excluded.evidence
	`, id, targetID, vulnType, severity, rawURL, param, evidence)
}

func (s *ExposureScanner) notify(targetID, vulnType, u string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID,
			"type":      vulnType,
			"url":       u,
		})
	}
}
