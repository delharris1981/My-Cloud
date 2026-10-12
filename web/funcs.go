package web

import (
	"fmt"
	"html/template"
	"strings"
	"time"
	"unicode"
)

// funcs are the template helpers available to every template.
var funcs = template.FuncMap{
	// humanSize renders a byte count the way a file manager does. Binary units
	// throughout: a "1 GB" disk shown as 1.07 GB is technically right and
	// practically confusing.
	"humanSize": humanSize,
	// humanTime renders a unix-millis timestamp in the viewer's local zone.
	"humanTime": humanTime,
	// relPath splits a slash path into its segments for breadcrumbs.
	"pathSegments": pathSegments,
	// lower lowercases for case-insensitive sorting already done in Go.
	"lower": strings.ToLower,
	// add/sub for simple index arithmetic in templates.
	"add": func(a, b int) int { return a + b },
	// isImage/isVideo/isAudio/isPDF/isText drive the icon shown per file type.
	"isImage": isExt(".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".bmp", ".ico"),
	"isVideo": isExt(".mp4", ".webm", ".mkv", ".mov", ".m4v"),
	"isAudio": isExt(".mp3", ".m4a", ".ogg", "opus", ".wav", ".flac"),
	"isPDF":   isExt(".pdf"),
	// hasExt reports whether name ends in any of the given extensions.
	"hasExt": func(name string, exts ...string) bool {
		for _, e := range exts {
			if strings.HasSuffix(strings.ToLower(name), e) {
				return true
			}
		}
		return false
	},
	// dirLink builds the browse URL for a folder path.
	"dirLink": func(p string) string { return "/files?path=" + template.URLQueryEscaper(p) },
	// pathLink builds the download URL for a file path.
	"pathLink": func(p string) string { return "/api/files/download?path=" + template.URLQueryEscaper(p) },
	// quote renders a value safely inside a JS string literal.
	"jsStr": func(s string) template.JS {
		b, _ := jsonMarshal(s)
		return template.JS(b)
	},
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	val := float64(n) / float64(div)
	// One decimal below 10, none above: 9.4 GB reads better than 9.43 GB.
	if val < 10 {
		return fmt.Sprintf("%.1f %s", val, units[exp])
	}
	return fmt.Sprintf("%.0f %s", val, units[exp])
}

func humanTime(ms int64) string {
	if ms == 0 {
		return ""
	}
	t := time.UnixMilli(ms)
	now := time.Now()
	switch {
	case t.Year() == now.Year() && t.YearDay() == now.YearDay():
		return t.Format("15:04")
	case t.Year() == now.Year():
		return t.Format("2 Jan 15:04")
	default:
		return t.Format("2 Jan 2006")
	}
}

// segment is one breadcrumb component.
type segment struct {
	Name string
	Path string
	Last bool
}

func pathSegments(p string) []segment {
	clean := strings.Trim(strings.ReplaceAll(p, "\\", "/"), "/")
	if clean == "" {
		return []segment{{Name: "Home", Path: "", Last: true}}
	}
	parts := strings.Split(clean, "/")
	segs := []segment{{Name: "Home", Path: ""}}
	acc := ""
	for i, part := range parts {
		if acc == "" {
			acc = part
		} else {
			acc += "/" + part
		}
		segs = append(segs, segment{Name: part, Path: acc, Last: i == len(parts)-1})
	}
	return segs
}

func isExt(exts ...string) func(string) bool {
	return func(name string) bool {
		l := strings.ToLower(name)
		for _, e := range exts {
			if strings.HasSuffix(l, e) {
				return true
			}
		}
		return false
	}
}

// jsonMarshal quotes a string as a JSON literal, used for embedding values in
// inline script attributes.
func jsonMarshal(s string) (string, error) {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '<':
			// Escaped so a value can never close a <script> tag.
			b.WriteString(`<`)
		case '>':
			b.WriteString(`>`)
		case '&':
			b.WriteString(`&`)
		default:
			if unicode.IsControl(r) {
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}
