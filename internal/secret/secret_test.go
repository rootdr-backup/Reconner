package secret

import "testing"

func TestRoundTrip(t *testing.T) {
	b := New("test-passphrase")
	plain := "session=abc123; Authorization: Bearer eyJhbGciOi.jwt.tok"
	enc := b.Encrypt(plain)
	if enc == plain {
		t.Fatal("ciphertext must differ from plaintext")
	}
	if !isEncrypted(enc) {
		t.Fatal("must be marked encrypted")
	}
	if got := b.Decrypt(enc); got != plain {
		t.Fatalf("decrypt mismatch: %q", got)
	}
}

func TestIdempotentAndEmpty(t *testing.T) {
	b := New("k")
	if b.Encrypt("") != "" {
		t.Error("empty stays empty")
	}
	enc := b.Encrypt("x")
	if b.Encrypt(enc) != enc {
		t.Error("encrypting ciphertext must be a no-op")
	}
	if b.Decrypt("plain-legacy") != "plain-legacy" {
		t.Error("legacy plaintext must pass through decrypt unchanged")
	}
}

func TestWrongKeyFails(t *testing.T) {
	enc := New("right").Encrypt("secret")
	if New("wrong").Decrypt(enc) == "secret" {
		t.Fatal("wrong key must not decrypt")
	}
}
