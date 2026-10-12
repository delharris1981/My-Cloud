package upload

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// randomID returns a 16-byte hex id used for chunk sessions.
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("upload: read id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// copyPath copies src to dst, creating dst. Used for the cross-device fallback
// when a completed .part cannot simply be renamed into place.
func copyPath(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// joinRel joins relative path components with forward slashes, which is the
// form vfs.Resolve expects.
func joinRel(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out == "" {
			out = p
			continue
		}
		out = filepath.ToSlash(filepath.Join(out, p))
	}
	return out
}
