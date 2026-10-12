package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/share"
	"golang.org/x/crypto/bcrypt"
)

// maxPublicUploadBytes caps a single anonymous drop-box upload, independent of
// the owner's quota. Without it an owner with unlimited quota would let a
// stranger fill the disk.
const maxPublicUploadBytes = 2 << 30 // 2 GB

// handleShareList returns the caller's shares as JSON.
func (a *App) handleShareList(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	list, err := a.Shares.List(r.Context(), u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	if list == nil {
		list = []share.Share{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": list})
}

// handleShareCreate mints a share link for a selection.
func (a *App) handleShareCreate(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	if !a.Cfg.Settings.AllowPublicShares {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "Public share links are disabled by the administrator.",
		})
		return
	}
	tr, err := a.userFS(u.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	r.ParseForm() //nolint:errcheck

	// A multi-selection share carries several paths; a single share one.
	paths := formPaths(r, "paths")
	if p := r.FormValue("path"); p != "" && len(paths) == 0 {
		paths = []string{p}
	}
	if len(paths) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Nothing selected."})
		return
	}

	// Every path is resolved through vfs, so a share cannot point outside the
	// owner's area even if the client sends a traversal.
	items := make([]share.Item, 0, len(paths))
	for _, p := range paths {
		st, err := tr.Files().Stat(p)
		if err != nil {
			continue // a vanished path is skipped, not fatal
		}
		abs, err := tr.Files().Resolve(p)
		if err != nil {
			continue
		}
		rel, err := tr.Files().RelPath(abs)
		if err != nil {
			continue
		}
		items = append(items, share.Item{Path: rel, IsDir: st.IsDir})
	}
	if len(items) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "None of the selected items were found.",
		})
		return
	}

	var expires *int64
	if d := r.FormValue("expiresDays"); d != "" {
		days, err := parseInt64(d)
		if err == nil && days > 0 {
			t := time.Now().Add(time.Duration(days) * 24 * time.Hour).UnixMilli()
			expires = &t
		}
	}

	pwHash := ""
	if pw := r.FormValue("password"); pw != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
			return
		}
		pwHash = string(h)
	}

	sh := &share.Share{
		Owner:     u.Username,
		ExpiresAt: expires,
		Items:     items,
		// Upload is only meaningful for a single folder share.
		AllowUpload: r.FormValue("allowUpload") != "" && len(items) == 1 && items[0].IsDir,
	}
	if err := a.Shares.Create(r.Context(), sh, pwHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"share": sh})
}

// handleShareDelete revokes a share the caller owns.
func (a *App) handleShareDelete(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *auth.User) {
	token := r.FormValue("token")
	if token == "" {
		token = r.PathValue("token")
	}
	if err := a.Shares.Delete(r.Context(), u.Username, token); err != nil {
		if errors.Is(err, share.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Share not found."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Server error."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Public, unauthenticated surface ---

// shareGone is the single response for every failure mode on a public share:
// unknown token, expired, revoked, or wrong password.
//
// Returning the same status and body for all of them is what prevents the
// endpoint becoming an oracle for guessing tokens or for probing whether a
// given file exists. The timing is equalised too: the password comparison
// always runs, against the stored hash or a dummy.
func shareGone(w http.ResponseWriter, status int) {
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		w.Write([]byte(shareGoneHTML))
		return
	}
	writeJSON(w, status, map[string]any{
		"error": "This share does not exist or is no longer available.",
	})
}

const shareGoneHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unavailable</title><link rel="stylesheet" href="/static/style.css"></head>
<body class="auth-body"><div class="auth-screen"><div class="auth-card">
<div class="auth-logo">🔒</div><h1>Link unavailable</h1>
<p class="muted">This share does not exist, has expired, or the password is wrong.</p>
</div></div></body></html>`

// shareCookieName is per-share so unlocking one link does not unlock another.
func shareCookieName(token string) string {
	sum := sha256.Sum256([]byte("mycloud-share-unlock:" + token))
	return "mycloud_share_" + hex.EncodeToString(sum[:])[:16]
}

// loadShare resolves a token and applies the uniform failure rule.
func (a *App) loadShare(w http.ResponseWriter, r *http.Request, token string) *share.Share {
	sh, err := a.Shares.Get(r.Context(), token)
	if err != nil {
		shareGone(w, http.StatusNotFound)
		return nil
	}
	if sh.IsExpired(time.Now()) {
		shareGone(w, http.StatusNotFound)
		return nil
	}
	return sh
}

// shareUnlocked reports whether the visitor has already unlocked a protected
// share. The cookie is an HMAC over the token keyed by the stored verifier, so
// it cannot be forged without the password.
func shareIsUnlocked(r *http.Request, sh *share.Share) bool {
	if !sh.HasPassword {
		return true
	}
	c, err := r.Cookie(shareCookieName(sh.Token))
	if err != nil {
		// No cookie: still spend the time a comparison would take, so the
		// locked and unlocked paths cost about the same.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$"+dummydigest), []byte("x"))
		return false
	}
	expected := shareUnlockValue(sh.Token, sh.UnlockSecret())
	return hmac.Equal([]byte(c.Value), []byte(expected))
}

// dummydigest is a fixed 53-character bcrypt digest body used only to burn a
// comparison when no cookie is present.
const dummydigest = "N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// shareUnlockValue derives the unlock cookie value.
func shareUnlockValue(token, verifier string) string {
	mac := hmac.New(sha256.New, []byte(verifier))
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}
