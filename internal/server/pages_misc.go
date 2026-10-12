package server

import (
	"net/http"
)

// rootRedirect sends "/" to the files browser or the login page, so the root
// is never a dead end.
func (a *App) rootRedirect(w http.ResponseWriter, r *http.Request) {
	if sess, _, err := a.authenticate(r); err == nil && sess != nil {
		redirect(w, r, "/files")
		return
	}
	redirect(w, r, "/login")
}

// handleManifest serves the PWA manifest with the site name filled in.
//
// The PWA survives the rewrite: an installed app that 404s its manifest would
// break offline behaviour and the home-screen icon for every existing user.
func (a *App) handleManifest(w http.ResponseWriter, r *http.Request) {
	name := a.Cfg.Settings.SiteName
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	// Built as a literal rather than templated JSON so a site name containing
	// a quote cannot produce invalid JSON.
	w.Write([]byte(`{
  "name": "` + jsonEscape(name) + `",
  "short_name": "` + jsonEscape(name) + `",
  "start_url": "/files",
  "scope": "/",
  "display": "standalone",
  "background_color": "#12151c",
  "theme_color": "#12151c",
  "icons": [
    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}
  ]
}`))
}

// jsonEscape makes a string safe to embed in a JSON string literal.
func jsonEscape(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '<':
			out = append(out, '<')
		case '&':
			out = append(out, '&')
		case '\n':
			out = append(out, ' ')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// handleIcon serves a PWA icon from the embedded assets.
//
// The manifest references these at the site root, so they are mounted
// separately from /static/. They are served from the raw embedded FS rather
// than the stripped static handler, whose /static/ prefix would not match.
func (a *App) handleIcon(size int) http.HandlerFunc {
	name := "/icon.png"
	if size == 192 {
		name = "/icon-192.png"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := a.icons.ReadFile("static" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(b)
	}
}
