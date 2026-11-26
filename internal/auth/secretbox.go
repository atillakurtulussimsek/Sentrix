package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// SecretBox encrypts secrets at rest with AES-256-GCM using the server key.
type SecretBox struct{ aead cipher.AEAD }

const sealedPrefix = "enc:v1:"

// LoadOrCreateKey reads a 32-byte key from path (base64), creating it with 0600 if missing.
// SENTRIX_SECRET_KEY (base64) overrides the file.
func LoadOrCreateKey(path string) ([]byte, error) {
	if env := os.Getenv("SENTRIX_SECRET_KEY"); env != "" {
		k, err := base64.StdEncoding.DecodeString(env)
		if err != nil || len(k) != 32 {
			return nil, errors.New("SENTRIX_SECRET_KEY must be 32 bytes, base64 encoded")
		}
		return k, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("invalid secret key in %s", path)
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write secret key: %w", err)
	}
	return k, nil
}

// NewSecretBox creates a box from a 32-byte key.
func NewSecretBox(key []byte) (*SecretBox, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

// Seal encrypts plaintext; empty input stays empty.
func (b *SecretBox) Seal(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return sealedPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Open decrypts a sealed value.
func (b *SecretBox) Open(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	raw, ok := strings.CutPrefix(sealed, sealedPrefix)
	if !ok {
		return "", errors.New("value is not sealed")
	}
	ct, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	n := b.aead.NonceSize()
	if len(ct) < n {
		return "", errors.New("ciphertext too short")
	}
	pt, err := b.aead.Open(nil, ct[:n], ct[n:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(pt), nil
}
