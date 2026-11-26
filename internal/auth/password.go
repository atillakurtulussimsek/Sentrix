// Package auth provides password hashing (argon2id), TOTP, secret encryption and
// login rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP 2023 recommendation: m=19 MiB, t=2, p=1; we use a bit more memory).
const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// MinPasswordLength is enforced on every password set.
const MinPasswordLength = 10

// HashPassword returns an encoded argon2id hash ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// ErrMismatch is returned for a wrong password.
var ErrMismatch = errors.New("password mismatch")

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(encoded, pw string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("unsupported hash format")
	}
	var mem uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return fmt.Errorf("parse hash params: %w", err)
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(pw), salt, t, mem, p, uint32(len(want))) //nolint:gosec // len is 32
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// ValidatePassword enforces basic password policy (ASVS L1: length ≥ 8; we require 10).
func ValidatePassword(pw string) error {
	if len([]rune(pw)) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(pw) > 256 {
		return errors.New("password too long")
	}
	return nil
}

// dummyHash is used to equalise timing for unknown usernames.
var dummyHash, _ = HashPassword("sentrix-timing-equaliser")

// VerifyDummy burns the same time as a real verification.
func VerifyDummy(pw string) { _ = VerifyPassword(dummyHash, pw) }
