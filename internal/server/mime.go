package server

import (
	"mime"
	"path"
	"strconv"
	"strings"
)

// parseInt64 parses a decimal int64.
func parseInt64(s string) (int64, error) { return strconv.ParseInt(strings.TrimSpace(s), 10, 64) }

// itoa renders an int for messages.
func itoa(v int) string { return strconv.Itoa(v) }

// contentTypeFor guesses a Content-Type from a filename extension.
//
// mime.TypeByExtension consults the system mime.types database, which can vary
// between the alpine runtime image and a developer machine. The explicit table
// comes first so a given extension always produces the same type regardless of
// host configuration — that consistency matters for range requests and for
// browsers deciding whether to render or download.
var explicitTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".json":  "application/json",
	".txt":   "text/plain; charset=utf-8",
	".md":    "text/markdown; charset=utf-8",
	".csv":   "text/csv; charset=utf-8",
	".xml":   "application/xml",
	".pdf":   "application/pdf",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".avif":  "image/avif",
	".svg":   "image/svg+xml",
	".ico":   "image/x-icon",
	".bmp":   "image/bmp",
	".webm":  "video/webm",
	".mp4":   "video/mp4",
	".m4v":   "video/mp4",
	".mov":   "video/quicktime",
	".mkv":   "video/x-matroska",
	".mp3":   "audio/mpeg",
	".m4a":   "audio/mp4",
	".ogg":   "audio/ogg",
	".opus":  "audio/opus",
	".wav":   "audio/wav",
	".flac":  "audio/flac",
	".zip":   "application/zip",
	".gz":    "application/gzip",
	".tar":   "application/x-tar",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".wasm":  "application/wasm",
}

func contentTypeFor(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := explicitTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	// application/octet-stream makes the browser download rather than guess,
	// which is the safe default for an unknown type from a user's disk.
	return "application/octet-stream"
}
