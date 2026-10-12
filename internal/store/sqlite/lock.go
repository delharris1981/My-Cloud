package sqlite

import (
	"fmt"
	"os"
	"syscall"

	"database/sql"
)

// txRunner is the subset of *sql.Tx the migration helpers use. Naming it
// keeps the import signatures honest about what they need.
type txRunner = sql.Tx

// acquireMigrateLock takes an exclusive flock on path, creating it if needed,
// and returns the release function.
//
// This is what makes the migration safe during the strangler rollout, where
// the Go and Node servers intentionally share the same /config volume: one
// container migrates while the other serves. Blocking (not LOCK_NB) is
// deliberate — the winner finishes in well under a second, and a failed
// migration should wait and retry rather than skip.
func acquireMigrateLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("migrate: open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("migrate: flock %s: %w", path, err)
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
