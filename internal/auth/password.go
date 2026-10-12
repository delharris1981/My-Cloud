// Package auth handles accounts, password verification, sessions, CSRF, rate
// limiting, TOTP, and app passwords.
//
// Two properties shape the design:
//
//   - Passwords are stored as argon2id PHC strings. Legacy bcrypt hashes are
//     still accepted and upgraded lazily at login, so migrating the Node
//     installation never forces a reset.
//   - Sessions are opaque random tokens stored server-side as a SHA-256 hash.
//     A database leak yields no usable cookies.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCredentials is returned for every failed verification, whether or
// not the username exists. A distinct "no such user" error would let an
// attacker enumerate accounts.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Argon2id parameters. 64MB / 3 passes is the OWASP-recommended baseline;
// it costs roughly 50-100ms per verification on the small hardware this
// targets, which is the point.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// bcryptCost is the legacy Node cost, accepted for verification only.
const bcryptCost = 10

// dummyHash is a real bcrypt hash of an unguessable value, compared against
// when a username does not exist so a missing account costs the same time as
// a wrong password. Without it, login timing enumerates usernames.
var dummyHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

// HashPassword returns an argon2id PHC string.
func HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	// PHC string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against either an argon2id PHC hash or a
// legacy bcrypt hash, and reports which format was used so the caller can
// upgrade it lazily.
//
// Returns ErrInvalidCredentials for both a wrong password and an unsupported
// hash format, so a malformed row is not distinguishable from a wrong guess.
func VerifyPassword(password, encoded string) (needsUpgrade bool, err error) {
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		return false, verifyArgon2(password, encoded)
	case strings.HasPrefix(encoded, "$argon2"), strings.HasPrefix(encoded, "$2a$"), strings.HasPrefix(encoded, "$2b$"), strings.HasPrefix(encoded, "$2y$"):
		return true, bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
	default:
		// Unknown format: still burn comparable time so a corrupt row is not
		// faster than a real check.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false, ErrInvalidCredentials
	}
}

func verifyArgon2(password, encoded string) error {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 {
		return ErrInvalidCredentials
	}
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return ErrInvalidCredentials
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrInvalidCredentials
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrInvalidCredentials
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// DummyCompare burns a bcrypt comparison. Called when no user matched, so the
// response time does not reveal whether the account exists.
func DummyCompare() { _ = bcrypt.CompareHashAndPassword(dummyHash, []byte("x")) }

// NewToken returns a fresh opaque token and the SHA-256 of it, hex-encoded.
//
// Only the hash is persisted. The raw token goes to the client in a cookie and
// is never recoverable from the database.
func NewToken() (token, id string, err error) {
	raw := make([]byte, 32) // 256 bits, per the plan
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("auth: read token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken returns the hex SHA-256 of a session token, used as the row id.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking length-independent
// timing. Used for CSRF and share-token checks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// randomHex returns n random bytes hex-encoded, for CSRF secrets and ids.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if err := randomRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomRead fills b with cryptographically secure random bytes.
func randomRead(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("auth: read random: %w", err)
	}
	return nil
}
