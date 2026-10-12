// Package web embeds the templates and static assets into the binary, so the
// container ships a single file with no asset directory to keep in sync.
package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed all:templates all:static
var files embed.FS

// Embedded returns the raw embedded filesystem.
//
// Used for the root-level PWA icons the manifest references, which sit
// outside the /static/ prefix that Static() serves under.
func Embedded() *embed.FS { return &files }

// FS returns the embedded filesystem rooted at the package directory.
func FS() fs.FS { return files }

// Templates parses and returns the embedded templates.
//
// Parsing happens once at startup rather than per request: a template error
// should crash the boot, not surface as a 500 to whoever happens to browse
// that page first.
func Templates() (*template.Template, error) {
	return template.New("").Funcs(funcs).ParseFS(files, "templates/*.html")
}

// Static returns the static asset subdirectory.
func Static() (fs.FS, error) {
	return fs.Sub(files, "static")
}
