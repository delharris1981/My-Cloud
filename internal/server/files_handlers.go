package server

import (
	"errors"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/upload"
	"github.com/derek/my-cloud/internal/vfs"
)

// maxEditSize caps the built-in text editor, matching the Node limit.
const maxEditSize = 5 << 20 // 5 MB

// userFS builds the files and trash roots for a user. Every request resolves
// through these, so no handler ever constructs a path itself.
func (a *App) userFS(username string) (*vfs.Trash, error) {
	_, files, trash, _ := a.Cfg.UserDirs(username)
	return vfs.NewTrash(files, trash)
}

// vfsError maps a vfs error to an HTTP status. The message is the vfs one,
// which is already user-safe: it describes the rule, not the filesystem.
func vfsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vfs.ErrInvalidPath):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid path."})
	case errors.Is(err, vfs.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found."})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
	}
}

// handleFileList lists a directory. The `partial` parameter is honoured by the
// htmx layer in phase 6; here the JSON form is the contract.
func (a *App) handleFileList(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dir := r.URL.Query().Get("path")
	entries, err := tr.Files().List(dir)
	if err != nil {
		vfsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":  cleanRelPath(dir),
		"items": entries,
		"usage": a.usagePayload(tr, u),
	})
}

// cleanRelPath normalises a client path for display in JSON.
func cleanRelPath(p string) string {
	if p == "" {
		return ""
	}
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}

// usagePayload returns the user's storage usage, preferring the TTL cache so a
// listing does not walk the whole tree every time.
func (a *App) usagePayload(tr *vfs.Trash, u *auth.User) map[string]any {
	used := a.usageCache.Get(u.Username, func() int64 {
		return tr.Files().Usage("")
	})
	quota := int64(u.QuotaMB) * 1024 * 1024
	out := map[string]any{"used": used, "quotaBytes": quota, "quotaMB": u.QuotaMB}
	if quota > 0 {
		remaining := quota - used
		if remaining < 0 {
			remaining = 0
		}
		out["remaining"] = remaining
	}
	return out
}

// handleFileDownload streams a file.
func (a *App) handleFileDownload(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	f, err := tr.Files().Open(r.URL.Query().Get("path"))
	if err != nil {
		vfsError(w, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		vfsError(w, err)
		return
	}
	if st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Not a file."})
		return
	}
	w.Header().Set("Content-Type", contentTypeFor(f.Name()))
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	if r.URL.Query().Get("dl") != "0" {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+path.Base(f.Name())+"\"")
	}
	//nolint:errcheck // the client disconnecting mid-stream is normal
	http.ServeContent(w, r, f.Name(), st.ModTime(), f)
}

// handleMkdir creates a directory.
func (a *App) handleMkdir(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dir := r.FormValue("path")
	name, err := tr.Files().MkdirSingle(dir, r.FormValue("name"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": normaliseError(err)})
		return
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// handleRename renames an entry.
func (a *App) handleRename(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	name, err := tr.Files().Rename(r.FormValue("path"), r.FormValue("name"))
	if err != nil {
		if errors.Is(err, vfs.ErrInvalidPath) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid name."})
			return
		}
		if errors.Is(err, vfs.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Not found."})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": normaliseError(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// formPaths extracts the repeated path/id parameters from a form body.
//
// r.ParseForm must have run first; these helpers call it so a handler cannot
// forget. Accepts both "paths[]" (what the HTML form emits) and "paths" (a
// hand-written request), since the field name differs by client.
func formPaths(r *http.Request, field string) []string {
	r.ParseForm() //nolint:errcheck // a parse failure shows up as empty fields
	if v := r.Form[field+"[]"]; len(v) > 0 {
		return v
	}
	return r.Form[field]
}

// handleMove moves entries into a directory.
func (a *App) handleMove(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	a.bulkTransfer(w, r, u, "move")
}

// handleCopy copies entries into a directory.
func (a *App) handleCopy(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	a.bulkTransfer(w, r, u, "copy")
}

// bulkTransfer moves or copies a selection. Partial success is reported per
// item rather than failing the whole request, matching the Node behaviour: one
// bad path in a multi-select should not strand the rest.
func (a *App) bulkTransfer(w http.ResponseWriter, r *http.Request, u *auth.User, op string) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	paths := formPaths(r, "paths")
	if len(paths) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Nothing selected."})
		return
	}
	dest := r.FormValue("dest")
	type itemErr struct {
		Path  string `json:"path"`
		Error string `json:"error"`
	}
	var errs []itemErr
	for _, p := range paths {
		var opErr error
		if op == "move" {
			_, opErr = tr.Files().Move(p, dest)
		} else {
			_, opErr = tr.Files().Copy(p, dest)
		}
		if opErr != nil {
			errs = append(errs, itemErr{Path: p, Error: normaliseError(opErr)})
		}
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(errs) == 0, "errors": errs})
}

// handleDelete moves the selection to the trash.
func (a *App) handleDelete(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	paths := formPaths(r, "paths")
	if len(paths) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Nothing selected."})
		return
	}
	type itemErr struct {
		Path  string `json:"path"`
		Error string `json:"error"`
	}
	var errs []itemErr
	for _, p := range paths {
		if _, derr := tr.Delete(p); derr != nil {
			errs = append(errs, itemErr{Path: p, Error: normaliseError(derr)})
		}
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(errs) == 0, "errors": errs})
}

// handleTrashList lists trashed items.
func (a *App) handleTrashList(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	items, err := tr.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	if items == nil {
		items = []vfs.TrashItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleTrashRestore restores selected items.
func (a *App) handleTrashRestore(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	ids := formPaths(r, "ids")
	if len(ids) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Nothing selected."})
		return
	}
	type itemErr struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	var errs []itemErr
	for _, id := range ids {
		if _, rerr := tr.Restore(id); rerr != nil {
			errs = append(errs, itemErr{ID: id, Error: normaliseError(rerr)})
		}
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": len(errs) == 0, "errors": errs})
}

// handleTrashDelete permanently removes selected trashed items.
func (a *App) handleTrashDelete(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	ids := formPaths(r, "ids")
	if len(ids) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Nothing selected."})
		return
	}
	for _, id := range ids {
		tr.Purge(id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTrashEmpty empties the trash.
func (a *App) handleTrashEmpty(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	n, err := tr.Empty()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
}

// handleSearch finds files by name.
func (a *App) handleSearch(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"results": []vfs.SearchResult{}})
		return
	}
	results, err := tr.Files().Search(q, 200)
	if err != nil {
		vfsError(w, err)
		return
	}
	if results == nil {
		results = []vfs.SearchResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// handleUsage reports storage usage.
func (a *App) handleUsage(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, a.usagePayload(tr, u))
}

// handleContentRead returns a text file's contents for the editor.
func (a *App) handleContentRead(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	f, err := tr.Files().Open(r.URL.Query().Get("path"))
	if err != nil {
		vfsError(w, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		vfsError(w, err)
		return
	}
	if st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Not a file."})
		return
	}
	if st.Size() > maxEditSize {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": "File too large to edit (5 MB max).",
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	//nolint:errcheck
	http.ServeContent(w, r, f.Name(), st.ModTime(), f)
}

// handleContentWrite replaces a text file's contents.
//
// The write goes to a temp file and is renamed into place, so a crash mid-save
// cannot truncate the user's file.
func (a *App) handleContentWrite(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	body, err := readLimited(r, maxEditSize)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": "File too large to save (5 MB max).",
		})
		return
	}
	target, err := tr.Files().Resolve(r.URL.Query().Get("path"))
	if err != nil {
		vfsError(w, err)
		return
	}
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Not a file."})
		return
	}

	// Enforce quota on the delta rather than the total, so an edit that shrinks
	// a file is not blocked.
	quotaBytes := int64(u.QuotaMB) * 1024 * 1024
	if quotaBytes > 0 {
		var existing int64
		if st, err := os.Stat(target); err == nil {
			existing = st.Size()
		}
		used := a.usageCache.Get(u.Username, func() int64 { return tr.Files().Usage("") })
		if used-existing+int64(len(body)) > quotaBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error": "Storage quota exceeded.",
			})
			return
		}
	}

	// Atomic replace: a crash mid-save must not truncate the user's file.
	if err := vfs.WriteFileAtomic(target, body, 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sinkFor builds an upload sink for a user, applying the quota and the caps.
func (a *App) sinkFor(u *auth.User, fs *vfs.FS, allowSubdirs bool, maxBytes int64, outOfSpaceMsg string) *upload.Sink {
	return &upload.Sink{
		FS:            fs,
		QuotaBytes:    int64(u.QuotaMB) * 1024 * 1024,
		MaxBytes:      maxBytes,
		AllowSubdirs:  allowSubdirs,
		OutOfSpaceMsg: outOfSpaceMsg,
	}
}
