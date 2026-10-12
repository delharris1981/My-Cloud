package server

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
)

// pageData is the view model shared by every page template.
type pageData struct {
	Title      string
	SiteName   string
	Theme      string
	BodyClass  string
	Username   string
	IsAdmin    bool
	View       string
	Query      string
	CSRFToken  string
	Path       string
	Segments   []crumb
	Error      string
	Notice     string
	NeedsSetup bool
	TwoFA      bool
	Script     bool
	// ShowHeadbar renders the top navigation. Off for the login page, which
	// has no session to navigate with.
	ShowHeadbar bool

	// Browser-side view state kept in the query string so a reload or a
	// shared link reproduces exactly what the sender saw.
	ViewMode string
	SortBy   string
	SortDir  string
	Selected map[string]bool

	// Content is pre-rendered HTML for the layout to emit.
	Content template.HTML
}

// crumb is one breadcrumb component.
type crumb struct {
	Name string
	Path string
	Last bool
}

// render executes a template by name with data and writes it.
func (a *App) render(w http.ResponseWriter, status int, name string, data pageData) {
	buf := &bytes.Buffer{}
	tmpl, err := a.Template(name)
	if err != nil {
		a.Log.Printf("render %s: %v", name, err)
		http.Error(w, "Server error.", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(buf, data); err != nil {
		a.Log.Printf("render %s: %v", name, err)
		http.Error(w, "Server error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// basePage fills the fields every page needs. sess may be nil for the login
// page.
func (a *App) basePage(r *http.Request, sess *authSession) pageData {
	d := pageData{
		SiteName:  a.Cfg.Settings.SiteName,
		Theme:     "dark",
		Query:     r.URL.Query().Get("q"),
		Path:      cleanRelPath(r.URL.Query().Get("path")),
		ViewMode:  r.URL.Query().Get("view"),
		SortBy:    r.URL.Query().Get("sort"),
		SortDir:   r.URL.Query().Get("dir"),
		Selected:  map[string]bool{},
		TwoFA:     r.URL.Query().Get("code") != "",
		CSRFToken: "",
	}
	if d.ViewMode != "list" {
		d.ViewMode = "grid"
	}
	if d.SortBy == "" {
		d.SortBy = "name"
	}
	if d.SortDir != "" {
		d.SortDir = "asc"
	}
	// Selection lives in the query string so it survives a reload and a
	// shared link, per the plan.
	for _, sel := range r.URL.Query()["selected"] {
		d.Selected[sel] = true
	}
	if sess != nil {
		d.CSRFToken = sess.CSRFSecret
		d.Username = sess.Username
	}
	if a.Auth != nil {
		if n, err := a.Auth.CountUsers(r.Context()); err == nil {
			d.NeedsSetup = n == 0
		}
	}
	return d
}

// authSession aliases the session type so page code does not need the auth
// import in every signature.
type authSession = authSessionType

// redirect sends the browser onward. Used after a successful form POST so a
// reload does not resubmit.
func redirect(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// htmlEscape is used when injecting a value into an attribute built in Go.
func htmlEscape(s string) string { return template.HTMLEscapeString(s) }

// trimQuery rebuilds a query string with one parameter replaced. Used by the
// sort and view-mode toggles, which change state without a new page load.
func trimQuery(base string, key, value string) string {
	parts := strings.Split(base, "&")
	out := parts[:0]
	replaced := false
	for _, p := range parts {
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, key+"=") {
			out = append(out, key+"="+template.URLQueryEscaper(value))
			replaced = true
			continue
		}
		out = append(out, p)
	}
	if !replaced {
		out = append(out, key+"="+template.URLQueryEscaper(value))
	}
	return strings.Join(out, "&")
}
