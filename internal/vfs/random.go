package vfs

import (
	"crypto/rand"
	"encoding/hex"
)

func randomRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}

func hexEncode(b []byte) string { return hex.EncodeToString(b) }
