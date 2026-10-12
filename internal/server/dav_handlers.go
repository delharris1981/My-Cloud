package server

import (
	"net/http"
	"time"

	"github.com/derek/my-cloud/internal/auth"
	"github.com/derek/my-cloud/internal/dav"
	"github.com/derek/my-cloud/internal/vfs"
)

// davHandler builds the WebDAV handler.
//
// Basic auth resolves through the app-password store: an app password always
// works, and the account password only when 2FA is off. Routing that decision
// through one store keeps the "2FA must not be bypassable" rule in a single
// place rather than duplicated per handler.
func (a *App) davHandler() http.Handler {
	return &dav.Handler{
		UserRoot: func(username string) (*vfs.FS, error) {
			_, files, _, _ := a.Cfg.UserDirs(username)
			return vfs.New(files)
		},
		Auth: func(r *http.Request, username, password string) (string, bool) {
			u, ok := a.AppPw.VerifyAppPassword(r.Context(), username, password)
			if !ok {
				a.Audit.Log(r.Context(), auth.AuditEvent{
					Username: username, Action: "dav.auth.fail",
					IP: clientIP(r), OK: false,
				})
				return "", false
			}
			a.Audit.Log(r.Context(), auth.AuditEvent{
				Username: u.Username, Action: "dav.auth", IP: clientIP(r), OK: true,
			})
			return u.Username, true
		},
		// Five minutes, bounded: a directory listing is dozens of requests and
		// each miss costs a hash verification. The bound stops an
		// unauthenticated client from growing the map with bogus headers.
		Cache:       dav.NewAuthCache(5*time.Minute, 1024),
		MaxPutBytes: maxUploadBytes,
	}
}
