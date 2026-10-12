package server

import (
	"io"
	"net/http"
	"strings"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/upload"
)

// maxUploadBytes caps a single authenticated upload. Chosen well above any
// realistic file but finite, so an unbounded request cannot fill the disk.
const maxUploadBytes = 10 << 30 // 10 GB

// handleUpload accepts a multipart upload.
//
// This is the no-JS path: a plain <form method="post" enctype="multipart/form-data">
// lands here with no JavaScript involved. The htmx path posts to the same
// endpoint, so there is one write path to keep safe.
func (a *App) handleUpload(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dest := r.URL.Query().Get("path")
	sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")

	written, err := sink.Stream(r, dest)
	if err != nil {
		a.usageCache.Invalidate(u.Username)
		status := http.StatusInternalServerError
		msg := "Server error."
		if err == upload.ErrTooLarge || strings.Contains(err.Error(), "quota") {
			status, msg = http.StatusRequestEntityTooLarge, normaliseError(err)
		}
		writeJSON(w, status, map[string]any{"error": msg, "written": written})
		return
	}
	a.usageCache.Invalidate(u.Username)
	if written == nil {
		written = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "written": written})
}

// handleUploadSessionCreate starts a resumable upload.
func (a *App) handleUploadSessionCreate(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dest := r.URL.Query().Get("path")
	sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")
	total := int64(-1)
	if v := r.FormValue("total"); v != "" {
		if n, err := parseInt64(v); err == nil {
			total = n
		}
	}
	sess2, err := sink.CreateSession(dest, r.FormValue("filename"), total)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": normaliseError(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": sess2.ID, "offset": 0})
}

// handleUploadSessionStatus reports how much of a session has been received,
// so a client that lost its connection resumes from the right offset.
func (a *App) handleUploadSessionStatus(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dest := r.URL.Query().Get("path")
	sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")
	offset, err := sink.SessionStatus(dest, r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Unknown upload session."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"offset": offset})
}

// handleUploadSessionChunk appends a byte range.
//
// The body is PUT with Content-Range; the offset must match what has already
// been stored or the assembled file would be corrupt.
func (a *App) handleUploadSessionChunk(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	offset, _, ok := upload.ParseContentRange(r.Header.Get("Content-Range"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid Content-Range header."})
		return
	}
	dest := r.URL.Query().Get("path")
	sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")
	n, err := sink.WriteChunk(dest, r.PathValue("id"), offset, r.Body)
	if err != nil {
		if err == upload.ErrTooLarge {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "File too large."})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": normaliseError(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "offset": offset + n})
}

// handleUploadSessionComplete finalises a resumable upload.
func (a *App) handleUploadSessionComplete(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dest := r.URL.Query().Get("path")
	sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")
	name, err := sink.CompleteSession(dest, r.PathValue("id"), r.FormValue("filename"))
	if err != nil {
		a.usageCache.Invalidate(u.Username)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": normaliseError(err)})
		return
	}
	a.usageCache.Invalidate(u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// handleUploadSessionCancel abandons a resumable upload and removes its .part.
func (a *App) handleUploadSessionCancel(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	dest := r.URL.Query().Get("path")
	sink := a.sinkFor(u, tr.Files(), true, maxUploadBytes, "Storage quota exceeded.")
	if err := sink.CancelSession(dest, r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid session."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// readLimited reads at most max bytes, reporting whether the limit was hit.
// Callers distinguish "too large" from a transport error by the error alone,
// so the body is truncated rather than partially consumed.
func readLimited(r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, max+1))
}
