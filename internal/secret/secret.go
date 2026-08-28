// Package secret provides a small, dependency-free secret abstraction: it
// encrypts sensitive strings (session cookies, bearer tokens, captured storage)
// at rest with AES-256-GCM, keyed by a secret derived from the app's session
// secret. Reconner stores authentication contexts for authorized testing, so
// those credentials must never sit in the database as plaintext.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

const prefix = "enc:v1:" // marks an encrypted value so decrypt is idempotent-safe

// Box holds a derived AES key.
type Box struct{ key [32]byte }

// New derives a 256-bit key from the given passphrase (the app SessionSecret).
func New(passphrase string) *Box {
	return &Box{key: sha256.Sum256([]byte("reconner-secret-v1|" + passphrase))}
}

// Encrypt returns an encoded, self-describing ciphertext. Empty input stays
// empty. Already-encrypted input is returned unchanged (idempotent).
func (b *Box) Encrypt(plain string) string {
	if plain == "" || isEncrypted(plain) {
		return plain
	}
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return plain
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plain
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plain
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.StdEncoding.EncodeToString(ct)
}

// Decrypt reverses Encrypt. Non-encrypted (legacy plaintext) input is returned
// as-is so old rows keep working.
func (b *Box) Decrypt(enc string) string {
	if !isEncrypted(enc) {
		return enc
	}
	raw, err := base64.StdEncoding.DecodeString(enc[len(prefix):])
	if err != nil {
		return ""
	}
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	if len(raw) < gcm.NonceSize() {
		return ""
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

func isEncrypted(s string) bool {
	return len(s) > len(prefix) && s[:len(prefix)] == prefix
}

// ErrEmptyKey is returned by callers that require a configured key.
var ErrEmptyKey = errors.New("empty secret key")
