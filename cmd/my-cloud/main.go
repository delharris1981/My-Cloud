// Command my-cloud is the Go rewrite of the My Cloud server.
//
// Phase 1 scope: boot, migrate, serve the operational endpoints. The full
// feature surface arrives in phases 3-6.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/derek/my-cloud/internal/config"
	"github.com/derek/my-cloud/internal/crypt"
	"github.com/derek/my-cloud/internal/server"
	"github.com/derek/my-cloud/internal/store/sqlite"
	"github.com/derek/my-cloud/internal/version"
)

func main() {
	// --version prints the build stamp and exits. This is how the release
	// pipeline confirms the image it just pushed actually contains the version
	// it thinks it does.
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Println(version.Current())
			return
		}
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	logger.Printf("my-cloud %s starting", version.Version)
	if err := run(logger); err != nil {
		logger.Fatalf("fatal: %v", err)
	}
}

func run(logger *log.Logger) error {
	// Load config first: it creates /config, /data/users, and secret.key.
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger.Printf("config dir=%s data dir=%s port=%d", cfg.ConfigDir, cfg.DataDir, cfg.Port)

	sealer, err := crypt.New(cfg.Secret)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}

	db, err := sqlite.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()

	// First-boot migration, before anything can serve a request. On an
	// existing Node volume this imports users and shares; on a fresh install
	// it is a no-op.
	res, err := sqlite.Migrate(context.Background(), db, cfg.ConfigDir, sealer)
	if err != nil {
		return err
	}
	if res.Ran {
		logger.Printf("migrated from Node: %d users, %d shares, %d app passwords, "+
			"%d TOTP enrolments, %d recovery codes",
			res.Users, res.Shares, res.AppPasswords, res.TOTPUsers, res.RecoveryCodes)
		for _, b := range res.OriginalsKept {
			logger.Printf("migrate: original kept at %s (rollback is a mv away)", b)
		}
		logger.Printf("migrate: sessions are not migrated — one forced re-login per user")
	}

	// Drop privileges before binding the listener, so the socket is never
	// held as root. No-op outside a container.
	if uid, gid, ok := puidPgid(); ok {
		if err := dropPrivileges(logger, uid, gid); err != nil {
			return err
		}
	}

	srv, err := server.New(cfg, db, sealer, logger)
	if err != nil {
		return err
	}
	stopHousekeeping := srv.StartHousekeeping()
	defer stopHousekeeping()
	httpServer := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: zip streaming and large uploads are legitimately
		// long-lived. ReadTimeout is likewise absent so a slow upload is not
		// severed mid-stream; the per-IP limiter and quota are the real caps.
		IdleTimeout: 120 * time.Second,
	}

	// Listen before announcing, so a bind failure is reported synchronously.
	ln, err := listen(cfg.Port)
	if err != nil {
		return err
	}

	needsSetup, err := db.IsEmpty(context.Background())
	if err != nil {
		return err
	}
	logger.Printf("listening on port %d", cfg.Port)
	if needsSetup {
		logger.Printf("no users yet — the setup wizard is open")
	}

	// Signal-driven shutdown: stop accepting, let in-flight requests finish
	// within a deadline, then exit.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		err := httpServer.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		logger.Printf("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutCtx); err != nil {
			// A timeout means requests outlived the grace period; close hard.
			httpServer.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return <-serveErr
	}
}

// puidPgid reads the Unraid-style PUID/PGID pair. Absent in dev, where the
// process already runs as the invoking user.
func puidPgid() (uid, gid int, ok bool) {
	u, uok := os.LookupEnv("PUID")
	g, gok := os.LookupEnv("PGID")
	if !uok || !gok {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u)
	gid, err2 := strconv.Atoi(g)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// dropPrivileges sets the group first, then the user: the reverse order fails
// once the uid changes and the process no longer has the privilege needed to
// call setgid.
func dropPrivileges(logger *log.Logger, uid, gid int) error {
	if os.Geteuid() != 0 {
		// Already unprivileged (dev, or a distroless image that drops via
		// USER). Nothing to do.
		return nil
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}
	logger.Printf("dropped privileges to %d:%d", uid, gid)
	return nil
}
