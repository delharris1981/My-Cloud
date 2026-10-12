package server

import (
	"context"
	"time"

	"github.com/derek/my-cloud/internal/upload"
	"github.com/derek/my-cloud/internal/vfs"
)

// StartHousekeeping launches the periodic maintenance loop and returns a stop
// function.
//
// The Node version ran this too: without it, trash accumulates forever and
// expired sessions pile up. It runs on its own goroutine rather than on the
// request path so a large trash purge never blocks a user's file listing.
func (a *App) StartHousekeeping() (stop func()) {
	// The first sweep is delayed: at boot, migrating and validating the
	// database matters more than reclaiming disk.
	ticker := time.NewTicker(time.Hour)
	done := make(chan struct{})

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				a.runSweep(context.Background())
			}
		}
	}()
	return func() { close(done) }
}

// runSweep does one pass of trash purging and session cleanup.
func (a *App) runSweep(ctx context.Context) {
	retention := time.Duration(a.Cfg.Settings.TrashRetentionDays) * 24 * time.Hour
	users, err := a.Auth.ListUsers(ctx)
	if err != nil {
		a.Log.Printf("housekeeping: list users: %v", err)
		return
	}
	for _, u := range users {
		tr, err := a.userFS(u.Username)
		if err != nil {
			continue
		}
		// A retention of 0 means "keep forever" rather than "delete
		// everything", which is what a literal zero-day cutoff would do.
		if retention > 0 {
			n, err := tr.PurgeOlderThan(time.Now().Add(-retention))
			if err != nil {
				a.Log.Printf("housekeeping: purge trash for %q: %v", u.Username, err)
			} else if n > 0 {
				a.Log.Printf("housekeeping: purged %d trashed item(s) for %q", n, u.Username)
				a.usageCache.Invalidate(u.Username)
			}
		}
		// Abandoned resumable uploads: a .part file untouched for a day is
		// an upload that will never finish, and would otherwise hold disk.
		if n, err := sweepStaleUploads(tr.Files(), 24*time.Hour); err != nil {
			a.Log.Printf("housekeeping: sweep uploads for %q: %v", u.Username, err)
		} else if n > 0 {
			a.Log.Printf("housekeeping: removed %d stale upload part file(s) for %q", n, u.Username)
		}
	}
	if n, err := a.Auth.PurgeExpiredSessions(ctx); err != nil {
		a.Log.Printf("housekeeping: purge sessions: %v", err)
	} else if n > 0 {
		a.Log.Printf("housekeeping: purged %d expired session(s)", n)
	}
	a.LoginLimit.Sweep()
	a.Public.Sweep()
}

// sweepStaleUploads removes .part files older than ttl from the user's files
// root. Recursed because an upload can target any folder.
func sweepStaleUploads(fs *vfs.FS, ttl time.Duration) (int, error) {
	entries, err := fs.List("")
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if !e.IsDir {
			continue
		}
		sink := &upload.Sink{FS: fs}
		n, err := sink.SweepStaleSessions(e.Name, ttl)
		if err != nil {
			continue
		}
		removed += n
	}
	return removed, nil
}
