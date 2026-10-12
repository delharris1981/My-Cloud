package dav

import (
	"errors"
	"mime"
	"net/url"
	"path"
	"strings"

	"github.com/derek/my-cloud/internal/vfs"
)

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func isNotFound(err error) bool    { return errors.Is(err, vfs.ErrNotFound) }
func isInvalidPath(err error) bool { return errors.Is(err, vfs.ErrInvalidPath) }

// urlUnescape decodes a percent-encoded path.
func urlUnescape(s string) (string, error) { return url.PathUnescape(s) }

// urlEscape percent-encodes one path segment.
func urlEscape(s string) string { return url.PathEscape(s) }

// contentTypeFor maps a filename to a MIME type, defaulting to
// application/octet-stream so a client downloads rather than guesses.
func contentTypeFor(name string) string {
	ext := strings.ToLower(path.Ext(name))
	// An explicit table keeps the answer identical between the alpine runtime
	// image and a developer machine, whose mime.types files differ.
	switch ext {
	case ".txt", ".md", ".csv", ".log":
		return "text/plain; charset=utf-8"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".mp4", ".m4v":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mov":
		return "video/quicktime"
	case ".mp3":
		return "audio/mpeg"
	case ".m4a":
		return "audio/mp4"
	case ".flac":
		return "audio/flac"
	case ".zip":
		return "application/zip"
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}
