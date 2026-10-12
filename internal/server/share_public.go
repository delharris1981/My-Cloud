package server

import (
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/share"
	"github.com/derek/my-cloud/internal/upload"
	"golang.org/x/crypto/bcrypt"
)

// publicRateLimit wraps the public share surface in the shared per-IP limiter.
func (a *App) publicRateLimit(max int, window time.Duration, next http.HandlerFunc) http.HandlerFunc {
	limiter := a.Public
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "Too many requests. Slow down.",
			})
			return
		}
		next(w, r)
	}
}

// handleSharePage renders the public share page, or the unlock form when the
// share is password protected.
func (a *App) handleSharePage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	sh := a.loadShare(w, r, token)
	if sh == nil {
		return
	}
	a.Audit.Log(r.Context(), auditShare(sh, "share.view", clientIP(r), true))

	if sh.HasPassword && !shareIsUnlocked(r, sh) {
		a.renderShareUnlock(w, r, sh)
		return
	}
	a.renderShareListing(w, r, sh)
}

// renderShareUnlock shows the password form.
func (a *App) renderShareUnlock(w http.ResponseWriter, r *http.Request, sh *share.Share) {
	d := a.basePage(r, nil)
	d.Title = "Protected link"
	d.BodyClass = "auth-body"
	d.Content = a.mustRender("share-unlock", map[string]any{
		"Token": sh.Token,
		"Error": r.URL.Query().Get("e"),
	})
	a.render(w, http.StatusOK, "layout", d)
}

// handleShareUnlock checks the password and sets the unlock cookie.
func (a *App) handleShareUnlock(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	sh := a.loadShare(w, r, token)
	if sh == nil {
		return
	}
	r.ParseForm() //nolint:errcheck
	pw := r.FormValue("password")

	// The comparison always runs, whether or not a verifier exists, so a
	// request against an unprotected share costs the same as a wrong guess.
	verifier := sh.UnlockSecret()
	if verifier == "" {
		bcrypt.CompareHashAndPassword([]byte("$2a$10$"+dummydigest), []byte(pw))
	} else if err := bcrypt.CompareHashAndPassword([]byte(verifier), []byte(pw)); err != nil {
		// Same response as every other failure: an attacker learns nothing
		// about whether the token exists or the password was merely wrong.
		a.Audit.Log(r.Context(), auditShare(sh, "share.unlock.fail", clientIP(r), false))
		if wantsHTML(r) {
			redirect(w, r, "/s/"+pathEscape(token)+"?e=1")
			return
		}
		shareGone(w, http.StatusForbidden)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     shareCookieName(token),
		Value:    shareUnlockValue(token, verifier),
		Path:     "/s/" + token,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
		Secure:   r.TLS != nil || a.Cfg.ForceSecureCookie,
	})
	if wantsHTML(r) {
		redirect(w, r, "/s/"+pathEscape(token))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// renderShareListing shows the shared items.
func (a *App) renderShareListing(w http.ResponseWriter, r *http.Request, sh *share.Share) {
	d := a.basePage(r, nil)
	d.Title = "Shared with you"
	d.BodyClass = "auth-body"
	d.Content = a.mustRender("share-listing", map[string]any{
		"Share":  sh,
		"Items":  sh.Items,
		"Upload": sh.AllowUpload,
	})
	a.render(w, http.StatusOK, "layout", d)
}

// handleShareInfo is the JSON equivalent of the listing, for the PWA.
func (a *App) handleShareInfo(w http.ResponseWriter, r *http.Request) {
	sh := a.loadShare(w, r, r.PathValue("token"))
	if sh == nil {
		return
	}
	if sh.HasPassword && !shareIsUnlocked(r, sh) {
		writeJSON(w, http.StatusOK, map[string]any{"locked": true})
		return
	}
	a.Audit.Log(r.Context(), auditShare(sh, "share.view", clientIP(r), true))
	writeJSON(w, http.StatusOK, map[string]any{
		"locked":      false,
		"name":        sh.FirstName,
		"isMulti":     len(sh.Items) > 1,
		"allowUpload": sh.AllowUpload,
		"items":       len(sh.Items),
	})
}

// handleShareDownload streams a shared item, or the whole share as a zip.
//
// The path is resolved inside the *owner's* vfs, so a share can only ever
// expose what its owner actually has.
func (a *App) handleShareDownload(w http.ResponseWriter, r *http.Request) {
	sh := a.loadShare(w, r, r.PathValue("token"))
	if sh == nil {
		return
	}
	if sh.HasPassword && !shareIsUnlocked(r, sh) {
		shareGone(w, http.StatusForbidden)
		return
	}
	tr, err := a.userFS(sh.Owner)
	if err != nil {
		shareGone(w, http.StatusNotFound)
		return
	}

	// A multi-item share serves whichever item was asked for.
	idx := -1
	if v := r.URL.Query().Get("i"); v != "" {
		n, err := parseInt64(v)
		if err != nil || n < 0 || int(n) >= len(sh.Items) {
			shareGone(w, http.StatusNotFound)
			return
		}
		idx = int(n)
	}

	target := ""
	if idx >= 0 {
		target = sh.Items[idx].Path
	} else if len(sh.Items) == 1 {
		target = sh.Items[0].Path
	}

	if target != "" {
		st, err := tr.Files().Stat(target)
		if err != nil {
			shareGone(w, http.StatusNotFound)
			return
		}
		if !st.IsDir {
			a.countShareDownload(r, sh)
			f, err := tr.Files().Open(target)
			if err != nil {
				shareGone(w, http.StatusNotFound)
				return
			}
			defer f.Close()
			info, _ := f.Stat()
			if info != nil {
				w.Header().Set("Content-Type", contentTypeFor(f.Name()))
				w.Header().Set("Content-Disposition", "attachment; filename=\""+
					path.Base(f.Name())+"\"")
				http.ServeContent(w, r, f.Name(), info.ModTime(), f)
			}
			return
		}
		// A folder share without an explicit item index serves a zip.
		a.serveZip(w, r, tr, sh, []string{target})
		return
	}

	// The whole selection as one archive.
	paths := make([]string, 0, len(sh.Items))
	for _, it := range sh.Items {
		paths = append(paths, it.Path)
	}
	a.serveZip(w, r, tr, sh, paths)
}

// countShareDownload records one download, but only for the initial request of
// a file — not per HTTP range. Video scrubbing fires dozens of ranges, and
// counting each would make the number meaningless.
func (a *App) countShareDownload(r *http.Request, sh *share.Share) {
	rangeHdr := r.Header.Get("Range")
	if rangeHdr == "" || strings.HasPrefix(rangeHdr, "bytes=0-") {
		_ = a.Shares.CountDownload(r.Context(), sh.Token)
	}
}

// handleShareUpload accepts an anonymous drop-box upload into a folder share.
func (a *App) handleShareUpload(w http.ResponseWriter, r *http.Request) {
	sh := a.loadShare(w, r, r.PathValue("token"))
	if sh == nil {
		return
	}
	if sh.HasPassword && !shareIsUnlocked(r, sh) {
		shareGone(w, http.StatusForbidden)
		return
	}
	if !sh.AllowUpload {
		shareGone(w, http.StatusForbidden)
		return
	}
	tr, err := a.userFS(sh.Owner)
	if err != nil {
		shareGone(w, http.StatusNotFound)
		return
	}
	owner, err := a.Auth.FindUser(r.Context(), sh.Owner)
	if err != nil {
		shareGone(w, http.StatusNotFound)
		return
	}

	// Uploads land at the share root: no client subpaths, so a visitor cannot
	// scatter files across the owner's tree.
	dest := ""
	if p := r.URL.Query().Get("path"); p != "" {
		if abs, err := tr.Files().Resolve(p); err == nil {
			dest, _ = tr.Files().RelPath(abs)
		}
	}
	if dest == "" && len(sh.Items) > 0 {
		dest = sh.Items[0].Path
	}

	sink := &upload.Sink{
		FS: tr.Files(),
		// The owner's quota AND an absolute cap: an anonymous visitor must
		// not be able to fill the disk of an unlimited-quota owner.
		QuotaBytes:    int64(owner.QuotaMB) * 1024 * 1024,
		MaxBytes:      maxPublicUploadBytes,
		AllowSubdirs:  false,
		OutOfSpaceMsg: "The owner is out of storage space.",
	}
	written, err := sink.Stream(r, dest)
	if err != nil {
		a.Audit.Log(r.Context(), auditShare(sh, "share.upload.fail", clientIP(r), false))
		if errors.Is(err, upload.ErrTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Upload too large."})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Upload failed."})
		return
	}
	a.usageCache.Invalidate(sh.Owner)
	a.Audit.Log(r.Context(), auditShare(sh, "share.upload", clientIP(r), true))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "written": written})
}

// auditShare builds an audit event for a public share action.
func auditShare(sh *share.Share, action, ip string, ok bool) auth.AuditEvent {
	return auth.AuditEvent{Username: sh.Owner, Action: action, IP: ip, OK: ok}
}

// pathEscape escapes a token for use in a redirect URL.
func pathEscape(s string) string {
	return strings.NewReplacer("/", "%2F", "?", "%3F", "#", "%23").Replace(s)
}
