package crypt

import (
	"bytes"
	"strings"
	"testing"
)

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	// 48 bytes of hex, the shape secret.key has on disk.
	s, err := New(strings.Repeat("ab", 48))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := testSealer(t)
	const aad = "totp:alice"

	sealed, err := s.SealString(PurposeSecrets, aad, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := s.OpenString(PurposeSecrets, aad, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestNonceIsFreshPerRecord(t *testing.T) {
	s := testSealer(t)
	const aad = "totp:alice"
	a, _ := s.SealString(PurposeSecrets, aad, "same-secret")
	b, _ := s.SealString(PurposeSecrets, aad, "same-secret")
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same plaintext twice produced identical bytes; nonce is not fresh")
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	s := testSealer(t)
	sealed, _ := s.SealString(PurposeSecrets, "totp:alice", "seed")
	// The whole point of the AAD: a sealed blob moved to another user's row
	// must not decrypt.
	if _, err := s.OpenString(PurposeSecrets, "totp:bob", sealed); err == nil {
		t.Fatal("opened under the wrong AAD; rows can be transplanted between users")
	}
}

func TestOpenRejectsWrongPurpose(t *testing.T) {
	s := testSealer(t)
	sealed, _ := s.SealString(PurposeSecrets, "x:1", "seed")
	if _, err := s.OpenString(PurposePasskeys, "x:1", sealed); err == nil {
		t.Fatal("opened under a different purpose; subkeys are not independent")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	s := testSealer(t)
	sealed, _ := s.SealString(PurposeSecrets, "x:1", "seed-value")
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := s.OpenString(PurposeSecrets, "x:1", tampered); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

func TestNewRejectsShortAndInvalidSecrets(t *testing.T) {
	if _, err := New("abcd"); err == nil {
		t.Fatal("accepted a 2-byte secret")
	}
	if _, err := New("zz" + strings.Repeat("ab", 47)); err == nil {
		t.Fatal("accepted non-hex secret")
	}
}

func TestDifferentRootsCannotDecrypt(t *testing.T) {
	a, _ := New(strings.Repeat("ab", 48))
	b, _ := New(strings.Repeat("cd", 48))
	sealed, _ := a.SealString(PurposeSecrets, "x:1", "seed")
	if _, err := b.OpenString(PurposeSecrets, "x:1", sealed); err == nil {
		t.Fatal("a different secret.key decrypted the value")
	}
}
