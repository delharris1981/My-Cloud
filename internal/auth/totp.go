package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP is RFC 6238 over RFC 4648 base32, hand-rolled to avoid a dependency.
// It is byte-compatible with the Node implementation in totp.js, so an
// authenticator enrolled before cutover keeps working.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// skewSteps allows +/- one 30-second step for clock drift, matching the
	// Node verifier.
	skewSteps = 1
)

// b32Alphabet is RFC 4648 base32 without padding.
const b32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

var b32Encode = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a fresh 160-bit secret in base32.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if err := randomRead(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(b32Encode.EncodeToString(raw), "="), nil
}

// VerifyTOTP checks a 6-digit code against a base32 secret, allowing +/- one
// step of clock skew. Non-numeric and wrong-length input is rejected without
// touching the HMAC.
func VerifyTOTP(secret, code string, now time.Time) bool {
	clean := stripNonDigits(code)
	if len(clean) != totpDigits {
		return false
	}
	step := now.Unix() / int64(totpPeriod.Seconds())
	for w := -skewSteps; w <= skewSteps; w++ {
		expected := hotp(secret, uint64(step+int64(w)))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(clean)) == 1 {
			return true
		}
	}
	return false
}

// hotp derives the one-time password for a counter, per RFC 4226.
func hotp(secret string, counter uint64) string {
	key, err := b32Decode(secret)
	if err != nil {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3).
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, value%1_000_000)
}

// b32Decode decodes a base32 secret, tolerating the padding and stray
// characters an authenticator app may hand back.
func b32Decode(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.TrimSpace(s))
	clean = strings.TrimRight(clean, "=")
	var out strings.Builder
	for _, r := range clean {
		if strings.ContainsRune(b32Alphabet, r) {
			out.WriteRune(r)
		}
	}
	decoded, err := b32Encode.DecodeString(out.String())
	if err != nil {
		return nil, fmt.Errorf("auth: base32 decode: %w", err)
	}
	return decoded, nil
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TOTPURI builds the otpauth:// enrolment URI for a QR code.
func TOTPURI(secret, account, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		urlEscape(issuer), urlEscape(account), secret, urlEscape(issuer), totpDigits, int(totpPeriod.Seconds()))
}

func urlEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return b.String()
}
