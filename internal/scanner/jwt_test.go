package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mkJWT builds an HS256 token signed with secret.
func mkJWT(t *testing.T, payload map[string]any, secret string) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	pb, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestLooksLikeJWT(t *testing.T) {
	good := mkJWT(t, map[string]any{"sub": "1"}, "secret")
	if !looksLikeJWT(good) {
		t.Fatal("valid JWT not recognised")
	}
	for _, bad := range []string{"", "a.b", "not.a.jwt", "aGVsbG8.d29ybGQ.sig"} {
		if looksLikeJWT(bad) {
			t.Errorf("%q must not look like a JWT", bad)
		}
	}
}

func TestHMACSecretMatchesAndBrute(t *testing.T) {
	tok := mkJWT(t, map[string]any{"sub": "42"}, "secret")
	if !hmacSecretMatches(tok, "secret") {
		t.Fatal("correct secret must verify")
	}
	if hmacSecretMatches(tok, "wrong") {
		t.Fatal("wrong secret must not verify")
	}
	sec, ok := bruteHS256(tok, jwtWeakSecrets)
	if !ok || sec != "secret" {
		t.Fatalf("weak secret must be cracked, got %q ok=%v", sec, ok)
	}
}

func TestForgeAlgNone(t *testing.T) {
	tok := mkJWT(t, map[string]any{"sub": "1", "role": "user"}, "secret")
	forged := forgeAlgNone(tok)
	parts := strings.Split(forged, ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("alg=none token must have an empty signature: %q", forged)
	}
	h, _ := b64urlJSON(parts[0])
	if strings.ToLower(jwtAlg(h)) != "none" {
		t.Fatalf("forged header must be alg=none, got %v", h)
	}
	// payload preserved
	if parts[1] != strings.Split(tok, ".")[1] {
		t.Fatal("alg=none forgery must preserve the original payload")
	}
}

func TestForgeHSProducesValidToken(t *testing.T) {
	tok := mkJWT(t, map[string]any{"sub": "1", "role": "user"}, "secret")
	forged := forgeHS(tok, "secret", map[string]any{"role": "admin"})
	if !hmacSecretMatches(forged, "secret") {
		t.Fatal("re-signed token must verify with the same secret")
	}
	_, payload, _ := decodeJWT(forged)
	if payload["role"] != "admin" {
		t.Fatalf("claim mutation not applied: %v", payload["role"])
	}
}

func TestAnalyzeJWT(t *testing.T) {
	kinds := func(tok string) map[string]bool {
		m := map[string]bool{}
		for _, i := range analyzeJWT(tok) {
			m[i.kind] = true
		}
		return m
	}

	// Weak secret + no exp.
	weak := kinds(mkJWT(t, map[string]any{"sub": "1"}, "secret"))
	if !weak["weak_secret"] {
		t.Error("weak-secret token must be flagged")
	}
	if !weak["no_expiry"] {
		t.Error("missing exp must be flagged")
	}

	// alg=none token.
	none := kinds(forgeAlgNone(mkJWT(t, map[string]any{"sub": "1", "exp": float64(time.Now().Add(time.Hour).Unix())}, "secret")))
	if !none["alg_none"] {
		t.Error("alg=none token must be flagged")
	}

	// Sensitive claim.
	sens := kinds(mkJWT(t, map[string]any{"sub": "1", "password": "hunter2", "exp": float64(time.Now().Add(time.Hour).Unix())}, "strong-unguessable-key-9f8a7b6c5d4e"))
	if !sens["sensitive_claims"] {
		t.Error("sensitive claim must be flagged")
	}
	if sens["weak_secret"] {
		t.Error("a strong secret must NOT be cracked")
	}
}
