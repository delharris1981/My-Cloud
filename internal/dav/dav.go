package dav

import (
	"crypto/sha1"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/derek/my-cloud/internal/vfs"
)

// Handler serves the WebDAV methods over a user's files root.
type Handler struct {
	// UserRoot returns the confined FS for an authenticated username. It is a
	// function because the root is derived per request from the verified user.
	UserRoot func(username string) (*vfs.FS, error)
	Auth     BasicAuthenticator
	Cache    *authCache
	// MaxPutBytes caps a single PUT body.
	MaxPutBytes int64
}

// ServeHTTP dispatches the DAV methods.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, ok := authenticate(r, h.Cache, h.Auth)
	if !ok {
		challenge(w)
		return
	}
	root, err := h.UserRoot(username)
	if err != nil {
		http.Error(w, "Server error.", http.StatusInternalServerError)
		return
	}
	// Strip the mount prefix so the DAV handler deals in relative paths only.
	rel := strings.TrimPrefix(r.URL.Path, Mount)

	switch r.Method {
	case http.MethodOptions:
		h.options(w)
	case "PROPFIND":
		h.propfind(w, r, root, rel)
	case "PROPPATCH":
		h.proppatch(w, r, root, rel)
	case "GET", http.MethodHead:
		h.get(w, r, root, rel, r.Method == http.MethodHead)
	case http.MethodPut:
		h.put(w, r, root, rel)
	case http.MethodDelete:
		h.delete(w, r, root, rel)
	case "MKCOL":
		h.mkcol(w, r, root, rel)
	case "COPY", "MOVE":
		h.copyMove(w, r, root, rel, r.Method == "MOVE")
	case "LOCK":
		h.lock(w, r, root, rel)
	case "UNLOCK":
		h.unlock(w, r, root, rel)
	default:
		w.Header().Set("Allow", Allow)
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) options(w http.ResponseWriter) {
	w.Header().Set("Allow", Allow)
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("MS-Author-Via", "DAV")
	w.WriteHeader(http.StatusOK)
}

// --- GET / HEAD ---

func (h *Handler) get(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string, headOnly bool) {
	f, err := root.Open(rel)
	if err != nil {
		davError(w, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		davError(w, err)
		return
	}
	if st.IsDir() {
		// A GET on a collection is not part of the contract; clients use
		// PROPFIND. Return the listing rather than a confusing error.
		h.propfindBody(w, root, rel, 1)
		return
	}
	w.Header().Set("ETag", etagFor(rel, st))
	w.Header().Set("Last-Modified", st.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", contentTypeFor(f.Name()))
	// http.ServeContent handles conditional and range requests, which video
	// and large-file transfers depend on.
	http.ServeContent(w, r, path.Base(f.Name()), st.ModTime(), f)
}

// --- PUT ---

func (h *Handler) put(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	abs, err := root.Resolve(rel)
	if err != nil {
		davError(w, err)
		return
	}
	if st, err := os.Stat(abs); err == nil {
		if st.IsDir() {
			http.Error(w, "Conflict: a collection exists here.", http.StatusConflict)
			return
		}
	} else {
		// The parent must exist: WebDAV clients are expected to MKCOL first,
		// and auto-creating parents would mask a genuinely wrong path.
		if _, perr := os.Stat(path.Dir(abs)); perr != nil {
			http.Error(w, "Conflict: parent collection does not exist.", http.StatusConflict)
			return
		}
	}
	if h.MaxPutBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.MaxPutBytes)
	}
	// Streamed to a temp file and renamed into place, so a dropped connection
	// cannot leave a truncated file at the destination: the caller gets the
	// whole file or nothing. Routed through vfs so every user-data write goes
	// through the one package that owns confinement.
	if err := vfs.WriteStream(abs, r.Body, 0o644); err != nil {
		http.Error(w, "Server error.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// --- DELETE ---

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	if err := root.Remove(rel); err != nil {
		davError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- MKCOL ---

func (h *Handler) mkcol(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	// RFC 4918: MKCOL on an existing resource is 405, and a body is 415.
	if r.ContentLength > 0 {
		http.Error(w, "MKCOL must not carry a body.", http.StatusUnsupportedMediaType)
		return
	}
	parent, name := path.Split(strings.TrimSuffix(rel, "/"))
	if name == "" {
		http.Error(w, "Conflict: cannot create a collection here.", http.StatusConflict)
		return
	}
	if _, err := root.Resolve(path.Clean("/" + parent)); err != nil {
		davError(w, err)
		return
	}
	if _, err := root.MkdirSingle(parent, name); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, "Method not allowed: already exists.", http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, "Conflict: parent collection does not exist.", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// --- COPY / MOVE ---

func (h *Handler) copyMove(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string, move bool) {
	srcAbs, err := root.Resolve(rel)
	if err != nil {
		davError(w, err)
		return
	}
	if srcAbs == root.Root() {
		http.Error(w, "Forbidden: cannot operate on the collection root.", http.StatusForbidden)
		return
	}

	destRel, ok := h.destination(r)
	if !ok {
		http.Error(w, "Bad Request: missing or invalid Destination header.", http.StatusBadRequest)
		return
	}
	// The destination is client-supplied too, so it goes through Resolve.
	destAbs, err := root.Resolve(destRel)
	if err != nil {
		davError(w, err)
		return
	}
	// Overwrite is opt-in, per RFC 4918.
	overwrite := r.Header.Get("Overwrite") != "F"
	if _, err := os.Stat(destAbs); err == nil {
		if !overwrite {
			w.Header().Set("Allow", Allow)
			http.Error(w, "Precondition Failed: destination exists.", http.StatusPreconditionFailed)
			return
		}
	}
	// Copying a collection into itself or a descendant would recurse forever.
	if st, err := os.Stat(srcAbs); err == nil && st.IsDir() {
		if strings.HasPrefix(destAbs, srcAbs+"/") {
			http.Error(w, "Forbidden: cannot copy a collection into itself.", http.StatusForbidden)
			return
		}
	}
	destParent := path.Dir(destAbs)
	if _, err := os.Stat(destParent); err != nil {
		http.Error(w, "Conflict: destination parent does not exist.", http.StatusConflict)
		return
	}

	status := http.StatusCreated
	if _, err := os.Stat(destAbs); err == nil {
		status = http.StatusNoContent // overwritten
	}
	// Remove the old destination first so a rename onto an existing name works.
	if status == http.StatusNoContent {
		if err := vfs.RemovePath(destAbs, root.Root()); err != nil {
			davError(w, err)
			return
		}
	}
	// WebDAV's Destination names the full target path including a possibly
	// different filename, so this is a rename/copy-to, not a move-into.
	destRel, rerr := root.RelPath(destAbs)
	if rerr != nil {
		davError(w, rerr)
		return
	}
	var opErr error
	if move {
		opErr = root.MoveTo(rel, destRel)
	} else {
		opErr = root.CopyTo(rel, destRel)
	}
	if opErr != nil {
		davError(w, opErr)
		return
	}
	w.WriteHeader(status)
}

// destination extracts the relative path from a Destination header, rejecting
// anything that does not point inside this DAV mount.
func (h *Handler) destination(r *http.Request) (string, bool) {
	dest := r.Header.Get("Destination")
	if dest == "" {
		return "", false
	}
	// The header is a full URL. Parse just its path; a hostile header must not
	// be able to name another mount or host.
	p := dest
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			p = rest[j:]
		} else {
			return "", false
		}
	}
	if !strings.HasPrefix(p, Mount) {
		return "", false
	}
	rel := strings.TrimPrefix(p, Mount)
	unescaped, err := urlUnescape(rel)
	if err != nil {
		return "", false
	}
	return unescaped, true
}

// --- LOCK / UNLOCK ---

// h.lock answers with a synthetic lock.
//
// A real byte-range lock table would let one client block another indefinitely
// after a crash. Since this server is a single-user view of files the same
// user already controls through the web UI and WebDAV, an advisory-only lock
// is the honest trade: clients see a token and behave, and a stale lock can
// never wedge the mount.
func (h *Handler) lock(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	if _, err := root.Resolve(rel); err != nil {
		davError(w, err)
		return
	}
	// A refresh carries If: (<token>) rather than a body.
	token := lockToken(rel)
	w.Header().Set("Lock-Token", "<opaquelocktoken:"+token+">")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	if r.ContentLength == 0 && r.Header.Get("If") == "" {
		// A refresh, not a new lock.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>`+
		`<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>`+
		`<D:locktype><D:write/></D:locktype>`+
		`<D:lockscope><D:exclusive/></D:lockscope>`+
		`<D:depth>infinity</D:depth>`+
		`<D:timeout>Second-3600</D:timeout>`+
		`<D:locktoken><D:href>opaquelocktoken:%s</D:href></D:locktoken>`+
		`</D:activelock></D:lockdiscovery></D:prop>`, token)
}

// lockToken derives a stable token for a path so a refresh returns the same
// value the client already holds.
func lockToken(rel string) string {
	sum := sha1.Sum([]byte("mycloud-lock:" + rel))
	return hexEncode(sum[:8])
}

func (h *Handler) unlock(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	// Nothing is retained, so unlocking always succeeds.
	w.WriteHeader(http.StatusNoContent)
}

// --- PROPFIND ---

func (h *Handler) propfind(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}
	if _, err := root.Resolve(rel); err != nil {
		davError(w, err)
		return
	}
	h.propfindBody(w, root, rel, depthInt(depth))
}

func depthInt(d string) int {
	switch strings.TrimSpace(d) {
	case "0":
		return 0
	case "infinity":
		return -1
	default:
		return 1
	}
}

// propfindBody renders the multistatus response.
func (h *Handler) propfindBody(w http.ResponseWriter, root *vfs.FS, rel string, depth int) {
	entries, err := collectProps(root, rel, depth)
	if err != nil {
		davError(w, err)
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<D:multistatus xmlns:D="DAV:">`)
	for _, e := range entries {
		b.WriteString(propResponse(e.rel, e.st))
	}
	b.WriteString(`</D:multistatus>`)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	w.Write([]byte(b.String()))
}

type propEntry struct {
	rel string
	st  os.FileInfo
}

// collectProps gathers the resource and, for depth 1, its children.
func collectProps(root *vfs.FS, rel string, depth int) ([]propEntry, error) {
	abs, err := root.Resolve(rel)
	if err != nil {
		return nil, err
	}
	st, err := statOrNotFound(os.Stat(abs))
	if err != nil {
		return nil, err
	}
	relPath, err := root.RelPath(abs)
	if err != nil {
		relPath = strings.Trim(rel, "/")
	}
	out := []propEntry{{rel: relPath, st: st}}
	if !st.IsDir() || depth == 0 {
		return out, nil
	}
	dirents, err := os.ReadDir(abs)
	if err != nil {
		return out, nil
	}
	for _, de := range dirents {
		info, err := de.Info()
		if err != nil {
			continue // vanished mid-listing
		}
		child := relPath + "/" + de.Name()
		if relPath == "" {
			child = de.Name()
		}
		out = append(out, propEntry{rel: child, st: info})
	}
	return out, nil
}

// propResponse renders one <D:response>.
func propResponse(rel string, st os.FileInfo) string {
	isDir := st.IsDir()
	name := path.Base(rel)
	if rel == "" || rel == "/" {
		name = "/"
	}
	var b strings.Builder
	b.WriteString(`<D:response>`)
	b.WriteString(`<D:href>` + xmlEscape(hrefFor(rel, isDir)) + `</D:href>`)
	b.WriteString(`<D:propstat><D:prop>`)
	b.WriteString(`<D:displayname>` + xmlEscape(name) + `</D:displayname>`)
	if isDir {
		b.WriteString(`<D:resourcetype><D:collection/></D:resourcetype>`)
	} else {
		b.WriteString(`<D:resourcetype/>`)
		b.WriteString(fmt.Sprintf(`<D:getcontentlength>%d</D:getcontentlength>`, st.Size()))
		b.WriteString(`<D:getcontenttype>` + xmlEscape(contentTypeFor(name)) + `</D:getcontenttype>`)
		b.WriteString(`<D:quota-used-bytes>0</D:quota-used-bytes>`)
		b.WriteString(`<D:quota-available-bytes>-1</D:quota-available-bytes>`)
	}
	b.WriteString(`<D:getlastmodified>` + st.ModTime().UTC().Format(http.TimeFormat) + `</D:getlastmodified>`)
	b.WriteString(`<D:creationdate>` + st.ModTime().UTC().Format("2006-01-02T15:04:05Z") + `</D:creationdate>`)
	b.WriteString(`<D:getetag>` + etagFor(rel, st) + `</D:getetag>`)
	b.WriteString(`<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>` +
		`<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>`)
	b.WriteString(`</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>`)
	b.WriteString(`</D:response>`)
	return b.String()
}

// proppatch answers every requested property change with 403 Forbidden.
//
// Storing arbitrary properties would mean a metadata store, which the project
// deliberately does not have: user data must stay inspectable with plain tools.
// Reporting them rather than silently ignoring keeps clients honest.
func (h *Handler) proppatch(w http.ResponseWriter, r *http.Request, root *vfs.FS, rel string) {
	if _, err := root.Resolve(rel); err != nil {
		davError(w, err)
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	b.WriteString(`<D:multistatus xmlns:D="DAV:"><D:response>`)
	b.WriteString(`<D:href>` + xmlEscape(hrefFor(strings.Trim(rel, "/"), false)) + `</D:href>`)
	b.WriteString(`<D:propstat><D:prop/>`)
	b.WriteString(`<D:status>HTTP/1.1 403 Forbidden</D:status>`)
	b.WriteString(`</D:propstat></D:response></D:multistatus>`)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	w.Write([]byte(b.String()))
}

// --- helpers ---

// hrefFor builds the URL a client should use for a resource. Collections get a
// trailing slash: without it Finder treats them as files and refuses to
// descend.
func hrefFor(rel string, isDir bool) string {
	rel = strings.Trim(rel, "/")
	var b strings.Builder
	b.WriteString(Mount)
	if rel != "" {
		for _, seg := range strings.Split(rel, "/") {
			b.WriteString("/")
			b.WriteString(urlEscape(seg))
		}
	}
	if isDir && !strings.HasSuffix(b.String(), "/") {
		b.WriteString("/")
	}
	if b.String() == Mount {
		return Mount + "/"
	}
	return b.String()
}

// etagFor derives a stable entity tag from path, size, and mtime.
func etagFor(rel string, st os.FileInfo) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%d|%d", rel, st.Size(), st.ModTime().UnixNano())))
	return `"` + hexEncode(sum[:8]) + `"`
}

// davError maps a vfs error to a WebDAV status.
func davError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case isNotFound(err):
		http.Error(w, "Not Found.", http.StatusNotFound)
	case isInvalidPath(err):
		http.Error(w, "Forbidden.", http.StatusForbidden)
	default:
		http.Error(w, "Server error.", http.StatusInternalServerError)
	}
}

// statOrNotFound translates a raw os.Stat error into the vfs sentinel so a
// missing path becomes 404 rather than an opaque 500. WebDAV clients probe
// paths constantly, and answering 500 makes rclone treat a simple "no such
// file" as a server fault and retry.
func statOrNotFound(st os.FileInfo, err error) (os.FileInfo, error) {
	if err == nil {
		return st, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, vfs.ErrNotFound
	}
	return nil, err
}

func xmlEscape(s string) string {
	var b strings.Builder
	//nolint:errcheck // strings.Builder.Write never returns an error
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
