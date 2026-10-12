// Package crypt provides the encryption-at-rest envelope for short values:
// TOTP seeds, passkey material, and recovery codes.
//
// The root key is /config/secret.key — a file the Node version already creates
// and already relies on for durability. Nothing signs with it any more (the Go
// rewrite moved sessions to opaque server-side tokens), so it is repurposed as
// the root from which purpose-specific subkeys are derived.
//
// One leaked subkey cannot decrypt another table's rows.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// keyLen is AES-256.
	keyLen = 32
	// nonceLen is the GCM standard nonce. A fresh one is drawn per record.
	nonceLen = 12
)

// Purposes. Each derives an independent subkey from the root.
const (
	PurposeSecrets  = "secrets"  // TOTP seeds and staged pending seeds
	PurposePasskeys = "passkeys" // WebAuthn credential IDs and COSE keys
	PurposeSharePw  = "sharepw"  // share-link passwords
)

// Sealer seals and opens credential-sized values. It is safe for concurrent use.
type Sealer struct {
	root []byte
}

// New builds a Sealer from the hex-encoded contents of secret.key.
func New(rootHex string) (*Sealer, error) {
	root, err := hex.DecodeString(rootHex)
	if err != nil {
		return nil, fmt.Errorf("secret.key is not valid hex: %w", err)
	}
	if len(root) < 32 {
		return nil, fmt.Errorf("secret.key is too short: %d bytes, need at least 32", len(root))
	}
	return &Sealer{root: root}, nil
}

// subkey derives a purpose-specific 256-bit key via HKDF-SHA256. The info
// string is the only thing separating purposes, so it must never be reused.
func (s *Sealer) subkey(purpose string) ([]byte, error) {
	key := make([]byte, keyLen)
	r := hkdf.New(sha256.New, s.root, nil, []byte("mycloud:v1:"+purpose))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf(%s): %w", purpose, err)
	}
	return key, nil
}

func (s *Sealer) gcm(purpose string) (cipher.AEAD, error) {
	key, err := s.subkey(purpose)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext under the given purpose and returns nonce||ciphertext||tag.
//
// aad is authenticated but not encrypted. Pass a value that identifies the
// row — table name plus primary key — so a sealed blob cannot be moved from
// one row to another and still decrypt.
func (s *Sealer) Seal(purpose, aad string, plaintext []byte) ([]byte, error) {
	gcm, err := s.gcm(purpose)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	// Seal appends the tag to the ciphertext; prefixing the nonce keeps the
	// blob self-contained, which matters because these live in a single BLOB
	// column with no companion nonce column.
	return gcm.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// Open reverses Seal. It fails if the purpose, aad, or key do not match.
func (s *Sealer) Open(purpose, aad string, blob []byte) ([]byte, error) {
	gcm, err := s.gcm(purpose)
	if err != nil {
		return nil, err
	}
	if len(blob) < nonceLen+gcm.Overhead() {
		return nil, fmt.Errorf("sealed value is truncated (%d bytes)", len(blob))
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
	pt, err := gcm.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return pt, nil
}

// SealString is a convenience wrapper for the common case of sealing a string.
func (s *Sealer) SealString(purpose, aad, plaintext string) ([]byte, error) {
	return s.Seal(purpose, aad, []byte(plaintext))
}

// OpenString reverses SealString. The plaintext is assumed to be a string;
// a successful decrypt of non-UTF-8 bytes is returned as-is.
func (s *Sealer) OpenString(purpose, aad string, blob []byte) (string, error) {
	pt, err := s.Open(purpose, aad, blob)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
