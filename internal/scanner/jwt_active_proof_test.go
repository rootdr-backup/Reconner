package scanner

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// withPlainIdentityClient swaps identityHTTPClient for a plain, unguarded
// client for the duration of the test, so fetchAs can reach a local
// httptest.Server (127.0.0.1) — the production client's destination guard
// (destination.go) deliberately refuses to send credentials to loopback,
// which is correct for a real scan but would block this local fixture too.
func withPlainIdentityClient(t *testing.T) {
	t.Helper()
	original := identityHTTPClient
	identityHTTPClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() { identityHTTPClient = original })
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaSign(t *testing.T, priv *rsa.PrivateKey, signingInput string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestProveAlgConfusionBypass builds a deliberately vulnerable local fixture
// server that verifies BOTH a real RS256 token (against its own public key)
// AND, by mistake, an HS256 token HMAC-signed with that same public key's PEM
// bytes — the exact RS256->HS256 confusion bug. proveAlgConfusionBypass must
// discover the public key via the fixture's JWKS endpoint and confirm the
// bypass; a patched (non-confused) verifier must NOT be confirmed.
func TestProveAlgConfusionBypass(t *testing.T) {
	withPlainIdentityClient(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey

	verify := func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(authz, "Bearer ")
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		hdr, _ := b64urlJSON(parts[0])
		alg := strings.ToUpper(jwtAlg(hdr))
		signingInput := parts[0] + "." + parts[1]
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		ok := false
		switch alg {
		case "RS256":
			digest := sha256.Sum256([]byte(signingInput))
			ok = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
		case "HS256":
			// THE BUG: resolves "the verification key" the same way for every
			// algorithm and hands its PEM bytes to HMAC when alg says HS256.
			pem, _ := rsaPublicKeyPEM(pub)
			mac := hmac.New(sha256.New, []byte(pem))
			mac.Write([]byte(signingInput))
			ok = hmac.Equal(mac.Sum(nil), sig)
		}
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"profile":"this is the protected profile object, padded to be a real page and not a tiny error body, over one hundred and twenty bytes long"}`)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", verify)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"k1","n":%q,"e":%q}]}`,
			b64u(pub.N.Bytes()), b64u(big.NewInt(int64(pub.E)).Bytes()))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}
	payload := map[string]any{"sub": "user1", "role": "user", "exp": float64(time.Now().Add(time.Hour).Unix())}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64, p64 := b64u(hb), b64u(pb)
	sig := rsaSign(t, priv, h64+"."+p64)
	realToken := h64 + "." + p64 + "." + b64u(sig)

	db, tid := testDB(t)
	seedBearerIdentity(t, db, tid, realToken)
	seedHTTPService(t, db, tid, srv.URL+"/api/profile")
	seedHTTPService(t, db, tid, srv.URL+"/.well-known/jwks.json")

	cfg := &config.Config{}
	s := NewJWTScanner(db, nil, cfg, logger.New("error"), nil)
	logFn := func(string, string, string) {}

	if n := s.proveAlgConfusionBypass(context.Background(), tid, logFn); n == 0 {
		t.Fatal("expected the RS256->HS256 confusion bypass to be CONFIRMED against the vulnerable fixture")
	}
}

// TestProveAlgConfusionBypassRejectsPatchedServer proves the same attack does
// NOT confirm against a server that pins the expected algorithm (rejects
// HS256 outright) — the negative control every proof-gated detector needs.
func TestProveAlgConfusionBypassRejectsPatchedServer(t *testing.T) {
	withPlainIdentityClient(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey

	verify := func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(authz, "Bearer ")
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		hdr, _ := b64urlJSON(parts[0])
		if strings.ToUpper(jwtAlg(hdr)) != "RS256" {
			http.Error(w, "unauthorized: algorithm not permitted", http.StatusUnauthorized)
			return
		}
		signingInput := parts[0] + "." + parts[1]
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		digest := sha256.Sum256([]byte(signingInput))
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"profile":"this is the protected profile object, padded to be a real page and not a tiny error body, over one hundred and twenty bytes long"}`)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", verify)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"k1","n":%q,"e":%q}]}`,
			b64u(pub.N.Bytes()), b64u(big.NewInt(int64(pub.E)).Bytes()))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}
	payload := map[string]any{"sub": "user1", "role": "user", "exp": float64(time.Now().Add(time.Hour).Unix())}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64, p64 := b64u(hb), b64u(pb)
	sig := rsaSign(t, priv, h64+"."+p64)
	realToken := h64 + "." + p64 + "." + b64u(sig)

	db, tid := testDB(t)
	seedBearerIdentity(t, db, tid, realToken)
	seedHTTPService(t, db, tid, srv.URL+"/api/profile")
	seedHTTPService(t, db, tid, srv.URL+"/.well-known/jwks.json")

	cfg := &config.Config{}
	s := NewJWTScanner(db, nil, cfg, logger.New("error"), nil)
	logFn := func(string, string, string) {}

	if n := s.proveAlgConfusionBypass(context.Background(), tid, logFn); n != 0 {
		t.Fatal("must NOT confirm a bypass against a server that pins the expected algorithm")
	}
}

// TestProveKidInjectionBypass exercises both the path-traversal and the SQLi
// kid-injection attempts against a fixture that resolves the HMAC secret from
// an unsanitized "kid" claim.
func TestProveKidInjectionBypass(t *testing.T) {
	withPlainIdentityClient(t)
	const realKid = "real-key-1"
	const realSecret = "s3cr3t-hs-key-1"

	resolveSecret := func(kid string) (string, bool) {
		switch {
		case kid == realKid:
			return realSecret, true
		case strings.Contains(kid, "/dev/null"):
			return "", true // path traversed to an empty file
		case strings.Contains(kid, "UNION SELECT '"):
			return strings.SplitN(kid, "UNION SELECT '", 2)[1], true
		default:
			return "", false
		}
	}

	verify := func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(authz, "Bearer ")
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		hdr, _ := b64urlJSON(parts[0])
		kid, _ := hdr["kid"].(string)
		secret, ok := resolveSecret(kid)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		signingInput := parts[0] + "." + parts[1]
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		if !hmac.Equal(mac.Sum(nil), sig) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"profile":"this is the protected profile object, padded to be a real page and not a tiny error body, over one hundred and twenty bytes long"}`)
	}

	srv := httptest.NewServer(http.HandlerFunc(verify))
	defer srv.Close()

	hdr := map[string]any{"alg": "HS256", "typ": "JWT", "kid": realKid}
	payload := map[string]any{"sub": "user1", "role": "user", "exp": float64(time.Now().Add(time.Hour).Unix())}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64, p64 := b64u(hb), b64u(pb)
	mac := hmac.New(sha256.New, []byte(realSecret))
	mac.Write([]byte(h64 + "." + p64))
	realToken := h64 + "." + p64 + "." + b64u(mac.Sum(nil))

	db, tid := testDB(t)
	seedBearerIdentity(t, db, tid, realToken)
	seedHTTPService(t, db, tid, srv.URL+"/")

	cfg := &config.Config{}
	s := NewJWTScanner(db, nil, cfg, logger.New("error"), nil)
	logFn := func(string, string, string) {}

	if n := s.proveKidInjectionBypass(context.Background(), tid, logFn); n == 0 {
		t.Fatal("expected a kid-injection bypass to be CONFIRMED against the vulnerable fixture")
	}
}

// TestProveJWKInjectionBypass exercises the embedded-jwk header attack against
// a fixture that trusts a jwk header carried by the token itself.
func TestProveJWKInjectionBypass(t *testing.T) {
	withPlainIdentityClient(t)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey

	verify := func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(authz, "Bearer ")
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		hdr, _ := b64urlJSON(parts[0])
		signingInput := parts[0] + "." + parts[1]
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			http.Error(w, "bad sig", http.StatusUnauthorized)
			return
		}
		digest := sha256.Sum256([]byte(signingInput))

		verifyKey := pub // default: the server's own trusted key
		// THE BUG: trust a public key embedded in the token's own header.
		if jwk, ok := hdr["jwk"].(map[string]any); ok {
			n, _ := jwk["n"].(string)
			e, _ := jwk["e"].(string)
			if k, ok := jwkToRSAPublicKey(jwkKey{Kty: "RSA", N: n, E: e}); ok {
				verifyKey = k
			}
		}
		if rsa.VerifyPKCS1v15(verifyKey, crypto.SHA256, digest[:], sig) != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"profile":"this is the protected profile object, padded to be a real page and not a tiny error body, over one hundred and twenty bytes long"}`)
	}

	srv := httptest.NewServer(http.HandlerFunc(verify))
	defer srv.Close()

	hdr := map[string]any{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{"sub": "user1", "role": "user", "exp": float64(time.Now().Add(time.Hour).Unix())}
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	h64, p64 := b64u(hb), b64u(pb)
	sig := rsaSign(t, priv, h64+"."+p64)
	realToken := h64 + "." + p64 + "." + b64u(sig)

	db, tid := testDB(t)
	seedBearerIdentity(t, db, tid, realToken)
	seedHTTPService(t, db, tid, srv.URL+"/")

	cfg := &config.Config{}
	s := NewJWTScanner(db, nil, cfg, logger.New("error"), nil)
	logFn := func(string, string, string) {}

	if n := s.proveJWKInjectionBypass(context.Background(), tid, logFn); n == 0 {
		t.Fatal("expected a jwk-header-injection bypass to be CONFIRMED against the vulnerable fixture")
	}
}

func seedBearerIdentity(t *testing.T, db *database.DB, targetID, token string) {
	t.Helper()
	headers, _ := json.Marshal(map[string]string{"Authorization": "Bearer " + token})
	_, err := db.Exec(`INSERT INTO identities (id, target_id, label, role, headers_json, is_baseline)
		VALUES (?, ?, 'user1', 'user', ?, 1)`, uuid.New().String(), targetID, string(headers))
	if err != nil {
		t.Fatal(err)
	}
}

func seedHTTPService(t *testing.T, db *database.DB, targetID, url string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES (?, ?, ?, 200)`,
		uuid.New().String(), targetID, url)
	if err != nil {
		t.Fatal(err)
	}
}
